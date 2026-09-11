#pragma once

#include "Cryptography.hpp"

#include <cstddef>
#include <string>

namespace seal
{

/**
 * @class Clipboard
 * @brief Clipboard writes with a background TTL scrub.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup IO_Clipboard
 *
 * One process-wide thread checks the clipboard after the TTL and clears matching content.
 * Each successful copy replaces the scrub thread and joins the previous one. The mutex
 * protects timer replacement and shutdown, not the initial clipboard write. Serialize
 * callers when write order must match timer ownership.
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * flowchart LR
 *     Copy["copyWithTTL()"] --> Sleep["poll 100 ms\nuntil TTL"]
 *     Sleep -->|stop requested| Stop["wipe copy,\nleave clipboard"]
 *     Sleep --> Compare{"content\nunchanged?"}
 *     Compare -->|yes| Clear["empty clipboard"]
 *     Compare -->|no| Skip["leave clipboard"]
 * ```
 *
 * @warning The TTL covers only the live clipboard. No history or cloud exclusion formats are set;
 *          Windows may retain other copies after EmptyClipboard().
 */
class Clipboard
{
public:
    Clipboard() = delete;
    Clipboard(const Clipboard&) = delete;
    Clipboard& operator=(const Clipboard&) = delete;

    /**
     * @fn bool copyWithTTL(const char* data, size_t n, DWORD ttl_ms = 6000)
     * @brief Copy UTF-8 text and schedule one scrub attempt.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Internal copies are cleansed. The caller retains and wipes `data`.
     * Stop is checked between 100 ms sleeps; cancellation leaves the clipboard intact.
     * The scrub compares text, not clipboard ownership: an identical replacement also clears.
     * Failed writes leave the previous scrub thread running.
     *
     * @verbatim
     * t=0        setText(value); wipe the temp UTF-8 copy; spawn jthread
     *  |         poll: test stop_requested, then sleep 100 ms, repeat
     *  v
     * t=ttl_ms   deadline (default 6000 ms) -> re-check stop
     *            OpenClipboard fails -> leave intact, no retry
     *            ctEqual(clipboard, value) ? EmptyClipboard : leave intact
     *            cleanse(value) + trimWorkingSet
     * @endverbatim
     *
     * @param data Non-null UTF-8 buffer readable for `n` bytes; copied before return.
     *             Embedded nulls prevent the scrub comparison from matching the copied text.
     * @param n Byte count; zero fails.
     * @param ttl_ms Milliseconds before the scrub attempt.
     * @return True if the initial write succeeds. False starts no thread; if the clipboard opened,
     *         it is already empty.
     * @post Only the newest copy keeps a timer. Unchanged content remains if the clipboard cannot
     *       open at the deadline; there is no retry.
     */
    [[nodiscard]] static bool copyWithTTL(const char* data, size_t n, DWORD ttl_ms = 6000);

    /**
     * @fn bool copyWithTTL(const S& s, DWORD ttl_ms = 6000)
     * @brief Apply the byte-buffer contract to a contiguous char range.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return False for an empty range.
     */
    template <std::ranges::contiguous_range S>
        requires std::same_as<std::remove_cv_t<std::ranges::range_value_t<S>>, char>
    [[nodiscard]] static bool copyWithTTL(const S& s, DWORD ttl_ms = 6000)
    {
        return copyWithTTL(std::ranges::data(s), std::ranges::size(s), ttl_ms);
    }

    /**
     * @fn bool copyWithTTL(const char (&s)[N], DWORD ttl_ms = 6000)
     * @brief Exclude the final array element from the copy.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @pre The last element is the null terminator.
     */
    template <size_t N>
    [[nodiscard]] static bool copyWithTTL(const char (&s)[N], DWORD ttl_ms = 6000)
    {
        static_assert(N > 0, "empty char array?");
        return copyWithTTL(s, N - 1, ttl_ms);
    }

    /**
     * @fn bool copyWithTTL(const char* s, DWORD ttl_ms = 6000)
     * @brief Copy null-terminated UTF-8 text.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return False for a null pointer or empty string.
     */
    [[nodiscard]] static bool copyWithTTL(const char* s, DWORD ttl_ms = 6000);

    /**
     * @fn bool copyInputFile()
     * @brief Copy the file named seal from the current directory with a 6000 ms TTL.
     * @author Alex (<https://github.com/lextpf>)
     *
     * The file buffer is pageable and is cleansed before return.
     *
     * @return False if the read or clipboard write fails, including an empty file.
     */
    [[nodiscard]] static bool copyInputFile();

    /**
     * @fn void shutdown()
     * @brief Stop and join the scrub thread before static destruction.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Call from main() while clipboard DLL entry points remain valid. Cancellation leaves the live
     * clipboard intact. Repeated calls are safe; a later copy starts a new thread.
     * The join can wait for a 100 ms poll interval.
     */
    static void shutdown();

private:
    /**
     * @fn bool setText(const std::string& text)
     * @brief Replace the clipboard with UTF-16 text.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Windows owns the pageable GMEM_MOVEABLE buffer after SetClipboardData succeeds; seal cannot
     * wipe it. Invalid UTF-8 is rejected.
     *
     * @return False for open, conversion, allocation or placement failure; also for empty text or
     *         more than INT_MAX bytes.
     * @post A successful open empties the clipboard, including on subsequent failure.
     */
    [[nodiscard]] static bool setText(const std::string& text);
};

/**
 * @fn bool typeSecret(const wchar_t* bytes, int len, DWORD delay_ms = 4000)
 * @brief Inject UTF-16 code units into the focused window.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup IO_Clipboard
 *
 * Each down/up pair uses one SendInput call, then waits `30 + (t % 16)` ms, where `t` is the tick
 * count. This 30..45 ms pacing prevents dropped or transposed input in Windows 11 text stacks.
 * The INPUT buffer is pageable and contains the UTF-16 code units until it is wiped.
 * The caller retains ownership of the source buffer throughout the blocking call.
 *
 * @verbatim
 * hook heuristic                   advisory keylogger probe, up to 150 ms
 * Sleep(delay_ms)                  initial focus grace (default 4000 ms)
 * for each UTF-16 code unit c:
 *     SendInput(2, pair)           down + up in one call: wScan=c, KEYEVENTF_UNICODE
 *     Sleep(30..45 ms)             pacing after every down/up pair
 * SecureZeroMemory(seq)            wipe the INPUT buffer
 * @endverbatim
 *
 * @param bytes Null returns false.
 * @param len Code-unit count, or -1 for null-terminated input; one trailing null is dropped.
 * @param delay_ms Focus grace in milliseconds.
 * @return False for empty input or a pair accepted as fewer than two events. Earlier
 *         events remain delivered; failure cannot undo partial typing.
 * @pre The target window has keyboard focus when typing starts.
 * @note An advisory hook probe runs first, for up to 150 ms. A zero-size foreground window or
 *       median CallNextHookEx latency above 2 ms logs a warning; typing still proceeds.
 */
[[nodiscard]] bool typeSecret(const wchar_t* bytes, int len, DWORD delay_ms = 4000);

/**
 * @fn bool openInputInNotepad()
 * @brief Launch Notepad on the file named seal in the current directory.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup IO_Clipboard
 *
 * Uses ShellExecuteA, then CreateProcessW on failure. Does not wait for Notepad to exit.
 *
 * @return True if either launch succeeds.
 */
[[nodiscard]] bool openInputInNotepad();

/**
 * @fn void wipeConsoleBuffer()
 * @brief Erase the active console screen buffer and reset its cursor.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup IO_Clipboard
 *
 * Terminal-owned scrollback is unaffected. Does nothing when stdout is not a console buffer.
 */
void wipeConsoleBuffer();

}  // namespace seal
