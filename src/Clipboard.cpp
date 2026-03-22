#include "Clipboard.h"
#include "Utils.h"

#include <shellapi.h>
#include <tlhelp32.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>

namespace
{

// RAII guard for OpenClipboard / CloseClipboard.
// Write callers must explicitly call EmptyClipboard() after locking.
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

// Joinable TTL thread wrapped in unique_ptr. Clipboard::shutdown() explicitly
// resets the pointer (which joins the thread) before main() returns.  This
// avoids relying on static-destruction ordering where DLL unloading may have
// already invalidated clipboard API entry points, causing a deadlock on join.
std::unique_ptr<std::jthread> s_TtlThread;

// Serializes access to s_TtlThread. Without this, concurrent copyWithTTL
// calls race on the jthread assignment (one thread may be mid-join while
// another writes a new jthread value, causing undefined behavior).
std::mutex s_TtlMutex;

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
    // GMEM_MOVEABLE is required by the The Windows clipboard API
    // the system needs to relocate the block when other processes request data.
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

    // SetClipboardData takes ownership of hMem on success - the system
    // manages its lifetime from here, so we must NOT call GlobalFree.
    // Only free on failure (when ownership was never transferred).
    if (!SetClipboardData(CF_UNICODETEXT, hMem))
    {
        GlobalFree(hMem);
        return false;
    }
    return true;
}

bool Clipboard::copyWithTTL(const char* data, size_t n, DWORD ttl_ms)
{
    // Store the original value in locked, guard-paged memory so it cannot be
    // swapped to disk during the TTL window.
    seal::secure_string<> val;
    val.s.assign(data, data + n);

    // setText() expects const std::string&; create a short-lived copy, call,
    // then wipe immediately. The copy exists only for the duration of the
    // Win32 clipboard API call.
    std::string tmp(val.s.begin(), val.s.end());
    bool ok = setText(tmp);
    seal::Cryptography::cleanseString(tmp);
    if (!ok)
    {
        return false;
    }

    // Joinable TTL thread: Sleeps for the TTL in short increments (so it
    // can respond to stop_requested during shutdown), then checks whether
    // the clipboard still holds our value before clearing.
    // The lock serializes concurrent copyWithTTL calls so the unique_ptr
    // reset (which joins the previous thread) is not a data race.
    std::lock_guard<std::mutex> ttlLock(s_TtlMutex);
    s_TtlThread = std::make_unique<std::jthread>(
        [val = std::move(val), ttl_ms](std::stop_token stop) mutable
        {
            // Sleep in 100ms increments so the thread can exit promptly
            // when Clipboard::shutdown() or the jthread destructor requests stop.
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ttl_ms);
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (stop.stop_requested())
                {
                    seal::Cryptography::cleanseString(val);
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            // Check stop one more time before entering the clipboard API
            // sequence. shutdown() may have been called while we were in the
            // final sleep increment; this prevents entering blocking Win32
            // clipboard calls after the process has started tearing down.
            if (stop.stop_requested())
            {
                seal::Cryptography::cleanseString(val);
                return;
            }

            // Open clipboard without emptying - we only want to read-compare.
            // ClipboardLock intentionally skips EmptyClipboard (see its comment).
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
                // Round-trip current clipboard UTF-16 back to UTF-8 into locked
                // memory so the comparison buffer is also non-pageable.
                int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
                seal::secure_string<> cur;
                if (need > 0)
                {
                    cur.s.resize(static_cast<size_t>(need), '\0');
                    int written = WideCharToMultiByte(
                        CP_UTF8, 0, w, -1, cur.s.data(), need, nullptr, nullptr);
                    if (written > 0 && !cur.empty() && cur.s.back() == '\0')
                    {
                        cur.s.pop_back();
                    }
                }
                GlobalUnlock(h);

                // Constant-time compare to prevent a timing side-channel
                // from leaking clipboard contents byte-by-byte.
                same = seal::Cryptography::ctEqualAny(cur.s, val.s);
            }

            // Only clear if nobody else has changed the clipboard
            if (same)
            {
                EmptyClipboard();
            }

            seal::Cryptography::cleanseString(val);
            seal::Cryptography::trimWorkingSet();
        });

    return true;
}

bool Clipboard::copyWithTTL(const char* s, DWORD ttl_ms)
{
    if (!s)
        return copyWithTTL("", 0, ttl_ms);
    return copyWithTTL(s, std::strlen(s), ttl_ms);
}

void Clipboard::shutdown()
{
    std::lock_guard<std::mutex> lock(s_TtlMutex);
    s_TtlThread.reset();  // requests stop + joins + destroys
}

bool Clipboard::copyInputFile()
{
    std::string buf;
    if (!utils::read_bin("seal", buf))
    {
        return false;
    }
    bool ok = copyWithTTL(buf);
    seal::Cryptography::cleanseString(buf);
    return ok;
}

// Shared state for the measurement hook callback. Accessed only from the
// thread that installed the hook, but stored as atomics for correctness
// documentation and to prevent subtle reordering issues.
std::atomic<LONGLONG> s_CallNextDuration{0};
std::atomic<bool> s_HookFired{false};

// Temporary WH_KEYBOARD_LL callback that times only CallNextHookEx.
// If we are the only hook in the chain, CallNextHookEx returns in <0.1ms.
// Any third-party hook adds its processing time to the measured delta.
static LRESULT CALLBACK MeasureHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    LARGE_INTEGER before, after;
    QueryPerformanceCounter(&before);
    LRESULT r = CallNextHookEx(nullptr, nCode, wParam, lParam);
    QueryPerformanceCounter(&after);
    s_CallNextDuration.store(after.QuadPart - before.QuadPart, std::memory_order_relaxed);
    s_HookFired.store(true, std::memory_order_release);
    return r;
}

// Heuristic check for suspicious global keyboard hooks.
// Returns true if a third-party hook is likely intercepting keystrokes.
// Advisory only - typeSecret() proceeds regardless but emits a warning.
static bool isKeyboardHookPresent()
{
    // Heuristic 1 - zero-size foreground window check.
    // A common keylogger technique is a transparent overlay that owns the
    // foreground but renders nothing visible. A legitimate window always has
    // non-zero dimensions, so a zero-size rect is a strong indicator of a
    // hook-injection overlay.
    HWND fg = GetForegroundWindow();
    if (fg)
    {
        RECT rc{};
        GetWindowRect(fg, &rc);
        if (rc.right - rc.left <= 0 || rc.bottom - rc.top <= 0)
        {
            OutputDebugStringA(
                "[seal] WARN: foreground window has zero size (possible hook overlay)\n");
            return true;
        }
    }

    // Heuristic 2 - timing-based hook chain detection.
    // Install a temporary WH_KEYBOARD_LL hook whose callback times only
    // CallNextHookEx (not the message pump or Sleep). Take 3 samples and
    // use the median to filter scheduling jitter. An empty chain returns
    // in <0.1ms; a threshold of 2ms provides 20x headroom while catching
    // any hook that does meaningful work (disk I/O, IPC, network).
    LARGE_INTEGER freq{};
    QueryPerformanceFrequency(&freq);

    HHOOK hHook = SetWindowsHookExW(WH_KEYBOARD_LL, MeasureHookProc, nullptr, 0);
    if (!hHook)
        return false;  // Can't install hook - inconclusive, proceed

    INPUT dummyInput[2]{};
    dummyInput[0].type = INPUT_KEYBOARD;
    dummyInput[0].ki.wVk = 0;
    dummyInput[0].ki.wScan = 0;
    dummyInput[0].ki.dwFlags = KEYEVENTF_UNICODE;
    dummyInput[1] = dummyInput[0];
    dummyInput[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;

    constexpr int NUM_SAMPLES = 3;
    double samples[NUM_SAMPLES] = {0.0, 0.0, 0.0};
    int validSamples = 0;

    for (int i = 0; i < NUM_SAMPLES; ++i)
    {
        s_HookFired.store(false, std::memory_order_relaxed);
        SendInput(2, dummyInput, sizeof(INPUT));

        // Pump messages until the hook fires or a 50ms safety timeout.
        // No Sleep - tight PeekMessage loop eliminates the ~10ms noise
        // that made the previous 15ms threshold unreliable.
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        MSG msg;
        while (!s_HookFired.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline)
        {
            if (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
                DispatchMessageW(&msg);
        }

        if (s_HookFired.load(std::memory_order_acquire))
        {
            samples[validSamples++] =
                static_cast<double>(s_CallNextDuration.load(std::memory_order_relaxed)) * 1000.0 /
                static_cast<double>(freq.QuadPart);
        }
    }

    UnhookWindowsHookEx(hHook);

    if (validSamples == 0)
        return false;  // Hook never fired - inconclusive

    // Sort and take the median to filter outliers from scheduling jitter.
    std::sort(samples, samples + validSamples);
    double median = samples[validSamples / 2];

    if (median > 2.0)
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

    // Heuristic: Warn if keyboard hooks are detected (keylogger risk).
    // This is best-effort - a determined attacker can evade detection.
    if (isKeyboardHookPresent())
    {
        OutputDebugStringA("[seal] WARN: suspicious keyboard hooks detected before auto-type\n");
    }

    // Resolve length and validate. Work directly from the caller's buffer
    // to avoid copying secrets into pageable std::wstring memory.
    if (len < 0)
        len = static_cast<int>(wcslen(bytes));
    // Strip trailing null if the caller included one in the length
    if (len > 0 && bytes[len - 1] == L'\0')
        --len;
    if (len <= 0)
        return false;

    // Give the user time to switch focus to the target window
    Sleep(delay_ms);

    // Build key-down / key-up pairs for each UTF-16 code unit.
    // KEYEVENTF_UNICODE tells SendInput to use the scan-code field as a raw
    // Unicode code point, bypassing virtual-key translation entirely.
    std::vector<INPUT> seq;
    seq.reserve(static_cast<size_t>(len) * 2);
    for (int i = 0; i < len; ++i)
    {
        INPUT down{};
        down.type = INPUT_KEYBOARD;
        down.ki.wScan = bytes[i];
        down.ki.dwFlags = KEYEVENTF_UNICODE;
        INPUT up = down;
        up.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        seq.push_back(down);
        seq.push_back(up);
    }

    // Send one event at a time with a randomised inter-key delay (5 + tick % 8
    // = 5..12ms) after each down/up pair. The jitter prevents input-rate
    // limiters in web apps and remote desktops from dropping or reordering
    // keystrokes that arrive faster than their processing loop.
    for (size_t i = 0; i < seq.size(); ++i)
    {
        SendInput(1, &seq[i], sizeof(INPUT));
        if ((i & 1) == 1)
        {
            Sleep(5 + (GetTickCount64() & 7));
        }
    }

    // Scrub sensitive keystroke data before returning. SecureZeroMemory is
    // not elided by the compiler (unlike memset), so the INPUT array is
    // guaranteed to be zeroed in physical memory.
    SecureZeroMemory(seq.data(), seq.size() * sizeof(INPUT));
    return true;
}

bool openInputInNotepad()
{
    const char* file = "seal";
    HINSTANCE h = ShellExecuteA(nullptr, "open", "notepad.exe", file, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(h) <= 32)
    {
        // Fallback: Use CreateProcessW instead of system() to avoid
        // command injection risks from cmd /c.
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        wchar_t cmdLine[] = L"notepad.exe seal";
        BOOL ok = CreateProcessW(
            nullptr, cmdLine, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
        if (ok)
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return true;
        }
        return false;
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

    // Overwrite every character cell with spaces so previously displayed
    // secrets (e.g. decrypted passwords shown during console mode) cannot
    // be recovered by visual inspection or screen-scraping tools. We also
    // reset attributes and the cursor position to leave a clean slate.
    FillConsoleOutputCharacterA(hOut, ' ', cells, home, &written);
    FillConsoleOutputAttribute(hOut, info.wAttributes, cells, home, &written);
    SetConsoleCursorPosition(hOut, home);
}

}  // namespace seal
