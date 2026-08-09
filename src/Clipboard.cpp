#include "Clipboard.hpp"
#include "Utils.hpp"

#include <shellapi.h>
#include <tlhelp32.h>

#include <atomic>
#include <bit>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>

namespace
{

// RAII for OpenClipboard / CloseClipboard. A writer calls EmptyClipboard()
// itself after locking.
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

// TTL thread in a unique_ptr. Clipboard::shutdown() resets (= joins) it before
// main() returns, so static-destruction order does not matter: a DLL unload
// could invalidate the clipboard API and deadlock the join.
std::unique_ptr<std::jthread> s_TtlThread;

// Serialises access to s_TtlThread so concurrent copyWithTTL calls cannot race
// on the jthread assignment.
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
    // GMEM_MOVEABLE: the clipboard API may relocate the block.
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

    // SetClipboardData takes ownership on success; only GlobalFree on failure.
    if (!SetClipboardData(CF_UNICODETEXT, hMem))
    {
        GlobalFree(hMem);
        return false;
    }
    return true;
}

bool Clipboard::copyWithTTL(const char* data, size_t n, DWORD ttl_ms)
{
    // Locked, guard-paged storage so the value cannot swap during the TTL.
    seal::secure_string<> val;
    val.assign(data, data + n);

    // setText() needs std::string&; short-lived copy, wiped after the call.
    std::string tmp(val.begin(), val.end());
    bool ok = setText(tmp);
    seal::Cryptography::cleanseString(tmp);
    if (!ok)
    {
        return false;
    }

    // TTL thread: sleeps in short increments (so stop_requested wakes it),
    // checks the clipboard still holds the copied value, then clears. The lock
    // serialises copyWithTTL so the unique_ptr reset (= join previous) is
    // race-free.
    std::lock_guard<std::mutex> ttlLock(s_TtlMutex);
    s_TtlThread = std::make_unique<std::jthread>(
        [val = std::move(val), ttl_ms](std::stop_token stop) mutable
        {
            // 100 ms increments so stop_requested is seen quickly.
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

            // Check stop once more before any Win32 clipboard call; shutdown
            // may have fired during the final sleep increment.
            if (stop.stop_requested())
            {
                seal::Cryptography::cleanseString(val);
                return;
            }

            // Read-compare only; ClipboardLock intentionally skips EmptyClipboard.
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
                // Round-trip UTF-16 -> UTF-8 in locked memory (non-pageable).
                int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
                seal::secure_string<> cur;
                if (need > 0)
                {
                    cur.resize(static_cast<size_t>(need));
                    int written =
                        WideCharToMultiByte(CP_UTF8, 0, w, -1, cur.data(), need, nullptr, nullptr);
                    if (written > 0 && !cur.empty() && cur.back() == '\0')
                    {
                        cur.pop_back();
                    }
                }
                GlobalUnlock(h);

                // Constant-time compare - no byte-by-byte timing leak.
                same = seal::Cryptography::ctEqual(cur, val);
            }

            // Clear only if the clipboard still holds the copied value.
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

// Shared state for the measurement hook. The atomics make the cross-thread
// publish explicit and rule out reordering.
std::atomic<LONGLONG> s_CallNextDuration{0};
std::atomic<bool> s_HookFired{false};

// Performance counter as long long via bit_cast - avoids LARGE_INTEGER
// QuadPart union access (type-punning).
inline long long perfCounter()
{
    LARGE_INTEGER v;
    QueryPerformanceCounter(&v);
    return std::bit_cast<long long>(v);
}

inline long long perfFrequency()
{
    LARGE_INTEGER v;
    QueryPerformanceFrequency(&v);
    return std::bit_cast<long long>(v);
}

// Temporary low-level keyboard callback that times CallNextHookEx only. A
// single-hook chain returns in <0.1 ms; any third-party hook inflates that.
static LRESULT CALLBACK MeasureHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    long long before = perfCounter();
    LRESULT r = CallNextHookEx(nullptr, nCode, wParam, lParam);
    long long after = perfCounter();
    s_CallNextDuration.store(after - before, std::memory_order_relaxed);
    s_HookFired.store(true, std::memory_order_release);
    return r;
}

// Heuristic for suspicious global keyboard hooks. Advisory only - typeSecret()
// proceeds either way and just emits a warning.
static bool isKeyboardHookPresent()
{
    // Heuristic 1: zero-size foreground window. A keylogger sometimes owns the
    // foreground with an invisible overlay; a real window has non-zero size.
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

    // Heuristic 2: hook-chain latency. Time CallNextHookEx only, not the pump
    // or Sleep. Three samples plus a median filter jitter. An empty chain
    // returns in <0.1 ms; >2 ms catches a hook doing real work (disk, IPC,
    // network).
    long long freq = perfFrequency();

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

        // Pump until the hook fires or 50 ms pass. A tight PeekMessage loop
        // without Sleep removes the ~10 ms scheduler noise.
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
                static_cast<double>(freq);
        }
    }

    UnhookWindowsHookEx(hHook);

    if (validSamples == 0)
        return false;  // Hook never fired - inconclusive

    // Median filters scheduling jitter.
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

    // Best-effort keylogger heuristic; a determined attacker evades it.
    if (isKeyboardHookPresent())
    {
        OutputDebugStringA("[seal] WARN: suspicious keyboard hooks detected before auto-type\n");
    }

    // Work straight from the caller's buffer; a copy into a pageable
    // std::wstring would leak the secret.
    if (len < 0)
        len = static_cast<int>(wcslen(bytes));
    // Strip trailing NUL if the caller included one in the length.
    if (len > 0 && bytes[len - 1] == L'\0')
        --len;
    if (len <= 0)
        return false;

    // Let the user focus the target window.
    Sleep(delay_ms);

    // Key-down/up pairs per UTF-16 unit. KEYEVENTF_UNICODE uses the
    // scan-code field as a raw code point, bypassing VK translation.
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

    // Send each character as one down+up pair in a single SendInput call, with
    // 30..45 ms of jitter between characters.
    //
    // Windows 11's modern Notepad and other async/TSF text stacks drop or
    // transpose a character when the UNICODE events arrive too fast or split
    // across separate calls - an early keystroke lands as its neighbour, e.g.
    // "gmx.de" typed as "gmx.ee". One call per pair plus this pacing types
    // reliably, and the jitter still defeats web-app and RDP rate limiters that
    // key off machine-perfect timing.
    //
    // seq holds [down, up] adjacently per character, so &seq[i] points at a
    // contiguous pair.
    bool allSent = true;
    for (size_t i = 0; i + 1 < seq.size(); i += 2)
    {
        const UINT sent = SendInput(2, &seq[i], sizeof(INPUT));
        if (sent != 2)
        {
            allSent = false;
            break;
        }
        Sleep(30 + (GetTickCount64() & 15));
    }

    // Scrub keystroke data; SecureZeroMemory cannot be elided (unlike memset).
    SecureZeroMemory(seq.data(), seq.size() * sizeof(INPUT));
    return allSent;
}

bool openInputInNotepad()
{
    const char* file = "seal";
    HINSTANCE h = ShellExecuteA(nullptr, "open", "notepad.exe", file, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(h) <= 32)
    {
        // Fallback: CreateProcessW instead of system() (no cmd /c).
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

    // Overwrite every cell so a secret printed earlier cannot be screen-scraped,
    // then reset attributes and cursor.
    FillConsoleOutputCharacterA(hOut, ' ', cells, home, &written);
    FillConsoleOutputAttribute(hOut, info.wAttributes, cells, home, &written);
    SetConsoleCursorPosition(hOut, home);
}

}  // namespace seal
