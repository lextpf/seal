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

// shutdown joins before DLL teardown can invalidate clipboard entry points.
std::unique_ptr<std::jthread> s_TtlThread;

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
    // keep the TTL copy in guarded storage.
    seal::secure_string<> val;
    val.assign(data, data + n);

    // setText requires a pageable copy; wipe it immediately.
    std::string tmp(val.begin(), val.end());
    bool ok = setText(tmp);
    seal::Cryptography::cleanseString(tmp);
    if (!ok)
    {
        return false;
    }

    // hold the mutex through replacement and join of the previous scrub thread.
    std::lock_guard<std::mutex> ttlLock(s_TtlMutex);
    s_TtlThread = std::make_unique<std::jthread>(
        [val = std::move(val), ttl_ms](std::stop_token stop) mutable
        {
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

            // shutdown may have arrived during the final sleep.
            if (stop.stop_requested())
            {
                seal::Cryptography::cleanseString(val);
                return;
            }

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

                same = seal::Cryptography::ctEqual(cur, val);
            }

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

std::atomic<LONGLONG> s_CallNextDuration{0};
std::atomic<bool> s_HookFired{false};

// bit_cast avoids LARGE_INTEGER union type-punning.
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

// measure only CallNextHookEx, excluding message-pump latency.
static LRESULT CALLBACK MeasureHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    long long before = perfCounter();
    LRESULT r = CallNextHookEx(nullptr, nCode, wParam, lParam);
    long long after = perfCounter();
    s_CallNextDuration.store(after - before, std::memory_order_relaxed);
    s_HookFired.store(true, std::memory_order_release);
    return r;
}

// advisory only; typeSecret logs a warning and continues.
static bool isKeyboardHookPresent()
{
    // an invisible foreground overlay is a possible hook indicator.
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

    // three hook-latency samples and a median reduce scheduler jitter.
    long long freq = perfFrequency();

    HHOOK hHook = SetWindowsHookExW(WH_KEYBOARD_LL, MeasureHookProc, nullptr, 0);
    if (!hHook)
        return false;  // can't install hook - inconclusive, proceed

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

        // pump without sleep to avoid scheduler noise; stop after 50 ms.
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
        return false;  // hook never fired - inconclusive

    // median filters scheduling jitter.
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

    if (isKeyboardHookPresent())
    {
        OutputDebugStringA("[seal] WARN: suspicious keyboard hooks detected before auto-type\n");
    }

    // read the caller buffer directly to avoid a pageable plaintext copy.
    if (len < 0)
        len = static_cast<int>(wcslen(bytes));
    if (len > 0 && bytes[len - 1] == L'\0')
        --len;
    if (len <= 0)
        return false;

    Sleep(delay_ms);

    // KEYEVENTF_UNICODE carries a UTF-16 code unit in wScan, bypassing VK translation.
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

    // send adjacent down/up events together and pace pairs by 30..45 ms.
    // windows 11 text stacks can transpose faster input, e.g. "gmx.de" to "gmx.ee".
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

    SecureZeroMemory(seq.data(), seq.size() * sizeof(INPUT));
    return allSent;
}

bool openInputInNotepad()
{
    const char* file = "seal";
    HINSTANCE h = ShellExecuteA(nullptr, "open", "notepad.exe", file, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(h) <= 32)
    {
        // fallback: CreateProcessW instead of system() (no cmd /c).
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

    FillConsoleOutputCharacterA(hOut, ' ', cells, home, &written);
    FillConsoleOutputAttribute(hOut, info.wAttributes, cells, home, &written);
    SetConsoleCursorPosition(hOut, home);
}

}  // namespace seal
