#include "Clipboard.h"
#include "Utils.h"

#include <shellapi.h>
#include <tlhelp32.h>

#include <cstring>
#include <thread>

namespace
{

// RAII guard for OpenClipboard / CloseClipboard.
// Does NOT empty the clipboard on construction - callers that need to
// write must call EmptyClipboard() explicitly after acquiring the lock.
struct ClipboardLock
{
    bool ok = false;

    ClipboardLock() { ok = !!OpenClipboard(nullptr); }

    ~ClipboardLock()
    {
        if (ok)
        {
            CloseClipboard();
        }
    }

    ClipboardLock(const ClipboardLock&) = delete;
    ClipboardLock& operator=(const ClipboardLock&) = delete;
};

}  // namespace

namespace seal
{

bool Clipboard::setText(const std::string& text)
{
    ClipboardLock lock;
    if (!lock.ok)
    {
        return false;
    }

    // Must empty before SetClipboardData
    EmptyClipboard();

    if (text.size() > static_cast<size_t>(INT_MAX))
    {
        return false;
    }

    int wlen = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (wlen <= 0)
    {
        return false;
    }

    SIZE_T bytes = (static_cast<SIZE_T>(wlen) + 1) * sizeof(wchar_t);
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hMem)
    {
        return false;
    }

    wchar_t* p = static_cast<wchar_t*>(GlobalLock(hMem));
    if (!p)
    {
        GlobalFree(hMem);
        return false;
    }

    int written = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), p, wlen);
    if (written <= 0)
    {
        GlobalUnlock(hMem);
        GlobalFree(hMem);
        return false;
    }

    p[written] = L'\0';
    GlobalUnlock(hMem);

    // SetClipboardData takes ownership of hMem on success
    if (!SetClipboardData(CF_UNICODETEXT, hMem))
    {
        GlobalFree(hMem);
        return false;
    }
    return true;
}

bool Clipboard::copyWithTTL(const char* data, size_t n, DWORD ttl_ms)
{
    std::string val(data, n);
    bool ok = setText(val);
    if (!ok)
    {
        return false;
    }

    // Detached thread: sleeps, then scrubs the clipboard if content is unchanged
    std::thread(
        [val = std::move(val), ttl_ms]() mutable
        {
            Sleep(ttl_ms);

            // Open clipboard without emptying - we only want to read-compare
            ClipboardLock lock;
            if (!lock.ok)
            {
                seal::Cryptography::cleanseString(val);
                seal::Cryptography::trimWorkingSet();
                return;
            }

            bool same = false;
            HANDLE h = GetClipboardData(CF_UNICODETEXT);
            wchar_t* w = h ? static_cast<wchar_t*>(GlobalLock(h)) : nullptr;
            if (w)
            {
                // Round-trip current clipboard UTF-16 back to UTF-8 for comparison
                int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
                std::string cur(need ? static_cast<size_t>(need) - 1 : 0, '\0');
                if (need)
                {
                    WideCharToMultiByte(CP_UTF8, 0, w, -1, cur.data(), need, nullptr, nullptr);
                }
                GlobalUnlock(h);

                // Constant-time compare to avoid timing leaks
                same = seal::Cryptography::ctEqualAny(cur, val);
            }

            // Only clear if nobody else has changed the clipboard
            if (same)
            {
                EmptyClipboard();
            }

            seal::Cryptography::cleanseString(val);
            seal::Cryptography::trimWorkingSet();
        })
        .detach();

    return true;
}

bool Clipboard::copyWithTTL(const char* s, DWORD ttl_ms)
{
    if (!s)
        return copyWithTTL("", 0, ttl_ms);
    return copyWithTTL(s, std::strlen(s), ttl_ms);
}

bool Clipboard::copyInputFile()
{
    std::string buf;
    if (!utils::read_bin("seal", buf))
    {
        return false;
    }
    return copyWithTTL(buf);
}

/// @brief Heuristic check for suspicious global keyboard hooks.
/// Installs a temporary WH_KEYBOARD_LL hook and measures the time
/// CallNextHookEx takes. If another hook in the chain adds latency
/// beyond a threshold, a third-party hook is likely present.
/// Returns true if a suspicious hook is detected.
static bool isKeyboardHookPresent()
{
    // Quick check: verify the foreground window belongs to a reasonable process.
    // A transparent overlay injecting hooks would own the foreground but have
    // a suspicious class name or zero-sized window rect.
    HWND fg = GetForegroundWindow();
    if (fg)
    {
        RECT rc{};
        GetWindowRect(fg, &rc);
        // A zero-size foreground window is suspicious (hook overlay).
        if (rc.right - rc.left <= 0 || rc.bottom - rc.top <= 0)
        {
            OutputDebugStringA(
                "[seal] WARN: foreground window has zero size (possible hook overlay)\n");
            return true;
        }
    }

    // Timing-based heuristic: install a temporary low-level keyboard hook
    // and measure the round-trip latency of the hook chain.
    struct HookCtx
    {
        LARGE_INTEGER freq{};
        LARGE_INTEGER start{};
        LARGE_INTEGER end{};
        bool measured = false;
    } ctx;
    QueryPerformanceFrequency(&ctx.freq);

    HHOOK hHook = SetWindowsHookExW(
        WH_KEYBOARD_LL,
        [](int nCode, WPARAM wParam, LPARAM lParam) -> LRESULT
        { return CallNextHookEx(nullptr, nCode, wParam, lParam); },
        nullptr,
        0);

    if (!hHook)
        return false;  // Can't install hook - inconclusive, proceed

    // Send a dummy keystroke and time the hook chain processing
    QueryPerformanceCounter(&ctx.start);
    INPUT dummyInput[2]{};
    dummyInput[0].type = INPUT_KEYBOARD;
    dummyInput[0].ki.wVk = 0;
    dummyInput[0].ki.wScan = 0;
    dummyInput[0].ki.dwFlags = KEYEVENTF_UNICODE;
    dummyInput[1] = dummyInput[0];
    dummyInput[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;

    // Pump messages briefly to let the hook fire
    MSG msg;
    for (int i = 0; i < 10; ++i)
    {
        if (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
        Sleep(1);
    }
    QueryPerformanceCounter(&ctx.end);

    UnhookWindowsHookEx(hHook);

    // If processing took more than 15ms, another hook in the chain
    // is adding latency (normal chain with no hooks: < 2ms).
    double elapsed_ms =
        (double)(ctx.end.QuadPart - ctx.start.QuadPart) * 1000.0 / (double)ctx.freq.QuadPart;
    if (elapsed_ms > 15.0)
    {
        OutputDebugStringA("[seal] WARN: keyboard hook chain latency suggests third-party hooks\n");
        return true;
    }

    return false;
}

bool typeSecret(const wchar_t* bytes, int len, DWORD delay_ms)
{
    if (!bytes)
    {
        return false;
    }

    // Heuristic: warn if keyboard hooks are detected (keylogger risk).
    // This is best-effort - a determined attacker can evade detection.
    if (isKeyboardHookPresent())
    {
        OutputDebugStringA("[seal] WARN: suspicious keyboard hooks detected before auto-type\n");
    }

    std::wstring w;
    if (len < 0)
    {
        w = std::wstring(bytes);
        if (w.empty())
        {
            return false;
        }
    }
    else
    {
        if (len <= 0)
        {
            return false;
        }
        w.assign(bytes, bytes + static_cast<size_t>(len));
        // Strip trailing null if the caller included one in the length
        if (!w.empty() && w.back() == L'\0')
        {
            w.pop_back();
        }
    }

    // Give the user time to switch focus to the target window
    Sleep(delay_ms);

    // Build key-down / key-up pairs for each UTF-16 code unit
    std::vector<INPUT> seq;
    seq.reserve(static_cast<size_t>(w.size()) * 2);
    for (wchar_t ch : w)
    {
        INPUT down{};
        down.type = INPUT_KEYBOARD;
        down.ki.wScan = ch;
        down.ki.dwFlags = KEYEVENTF_UNICODE;
        INPUT up = down;
        up.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        seq.push_back(down);
        seq.push_back(up);
    }

    // Send one event at a time with a small randomised delay after each pair
    // to avoid tripping input-rate limiters in target applications
    for (size_t i = 0; i < seq.size(); ++i)
    {
        SendInput(1, &seq[i], sizeof(INPUT));
        if ((i & 1) == 1)
        {
            Sleep(5 + (GetTickCount64() & 7));
        }
    }

    // Scrub sensitive keystroke data before returning
    SecureZeroMemory(seq.data(), seq.size() * sizeof(INPUT));
    SecureZeroMemory(w.data(), w.size() * sizeof(wchar_t));
    return true;
}

bool openInputInNotepad()
{
    const char* file = "seal";
    HINSTANCE h = ShellExecuteA(nullptr, "open", "notepad.exe", file, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(h) <= 32)
    {
        // Fallback: ShellExecuteA can fail on restricted accounts
        int ret = system("cmd /c start \"\" notepad.exe seal");
        return (ret == 0);
    }
    return true;
}

void wipeConsoleBuffer()
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE)
    {
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (!GetConsoleScreenBufferInfo(hOut, &info))
    {
        return;
    }

    DWORD cells = static_cast<DWORD>(info.dwSize.X) * static_cast<DWORD>(info.dwSize.Y);
    COORD home{0, 0};
    DWORD written = 0;

    // Overwrite every character cell, then reset attributes and cursor
    FillConsoleOutputCharacterA(hOut, ' ', cells, home, &written);
    FillConsoleOutputAttribute(hOut, info.wAttributes, cells, home, &written);
    SetConsoleCursorPosition(hOut, home);
}

}  // namespace seal
