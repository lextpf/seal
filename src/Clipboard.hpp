#pragma once

#include "Cryptography.hpp"

#include <cstddef>
#include <string>

namespace seal
{

/**
 * @class Clipboard
 * @brief Windows clipboard writes that scrub themselves after a time-to-live.
 * @author Alex (https://github.com/lextpf)
 * @ingroup IO_Clipboard
 *
 * A static facade over the Win32 clipboard API. An anonymous-namespace RAII
 * guard (`ClipboardLock`) owns the `OpenClipboard` / `CloseClipboard` pair.
 *
 * ## :material-clipboard-text: Text placement
 *
 * setText() converts a UTF-8 `std::string` to UTF-16 and places it as
 * `CF_UNICODETEXT`. The clipboard is emptied before the write, so stale data
 * from another application is never left behind.
 *
 * ## :material-timer-sand: TTL scrubbing
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
 * copyWithTTL() writes the value, then a background thread waits out the TTL
 * (default 6 s) and empties the clipboard only when a constant-time compare
 * (`Cryptography::ctEqual`) shows it still holds that value. Content another
 * application has since placed there is left alone.
 *
 * @warning The value is placed as a plain `CF_UNICODETEXT` item. seal registers
 *          none of the exclusion formats
 *          (`ExcludeClipboardContentFromMonitorProcessing`,
 *          `CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard`), so
 *          Windows Clipboard History and Cloud Clipboard can keep their own
 *          copy. `EmptyClipboard()` does not remove those copies: the TTL
 *          bounds the live clipboard only.
 *
 * @par Single scrub thread
 * One scrub thread exists process-wide, held in a file-static
 * `std::unique_ptr<std::jthread>` behind a mutex. A second copyWithTTL() starts
 * its own thread and, as the `unique_ptr` is reassigned, stops and joins the
 * pending one. The earlier value then keeps no timer, which is safe because the
 * new call has already overwritten the clipboard. The mutex is held across that
 * join, so a concurrent copyWithTTL() or shutdown() blocks until it completes.
 * shutdown() performs the same stop-and-join and runs before static destruction.
 *
 * ## :material-file-lock: Input-file helper
 *
 * copyInputFile() reads the `seal` binary input file into memory and delegates
 * to copyWithTTL(), giving CLI users a one-shot read-and-scrub workflow.
 */
class Clipboard
{
public:
    Clipboard() = delete;
    Clipboard(const Clipboard&) = delete;
    Clipboard& operator=(const Clipboard&) = delete;

    /**
     * @brief Copy a byte buffer to the clipboard and auto-scrub after a timeout.
     *
     * Writes @p n bytes of UTF-8 data through setText(), then runs the scrub
     * described above on a `std::jthread`.
     *
     * Both internal copies of the secret - the locked buffer handed to the scrub
     * thread and the short-lived `std::string` setText() needs - are cleansed.
     * The caller's @p data buffer is never touched; the caller wipes it.
     *
     * @par Scrub timeline
     * @verbatim
     * t=0        setText(value); wipe the temp UTF-8 copy; spawn jthread
     *  |         poll: test stop_requested, then sleep 100 ms, repeat
     *  v
     * t=ttl_ms   deadline (default 6000 ms) -> re-check stop
     *            OpenClipboard fails -> leave intact, no retry
     *            ctEqual(clipboard, value) ? EmptyClipboard : leave intact
     *            cleanse(value) + trimWorkingSet
     * @endverbatim
     * Stop is observed only between sleeps, so a cancel takes up to 100 ms to
     * land, and a cancelled scrub leaves the clipboard as it is.
     *
     * @param data   Raw UTF-8 byte buffer, copied before the call returns.
     * @param n      Length of @p data in bytes. Zero fails, because setText()
     *               rejects an empty conversion.
     * @param ttl_ms Milliseconds before the clipboard is scrubbed.
     * @return `true` when the initial clipboard set succeeded. On `false` no
     *         scrub thread is started, and the clipboard is already empty
     *         whenever setText() got as far as opening it.
     *
     * @pre @p data is readable for @p n bytes.
     * @post A background thread, joined by shutdown(), clears the clipboard
     *       after @p ttl_ms, unless another application replaced the content or
     *       the clipboard cannot be opened at the deadline. The scrub runs once
     *       and is not retried, so in the second case the value stays on the
     *       clipboard.
     * @post A scrub still pending from an earlier call is stopped and joined;
     *       only the newest value keeps a timer.
     *
     * @see setText, shutdown, Cryptography::ctEqual
     */
    [[nodiscard]] static bool copyWithTTL(const char* data, size_t n, DWORD ttl_ms = 6000);

    /**
     * @brief Copy a contiguous `char` range to the clipboard with TTL scrub.
     *
     * Delegates to the `(const char*, size_t)` overload. Accepts any contiguous
     * range whose value type decays to `char` (e.g. `std::string`,
     * `std::string_view`, `secure_string`). An empty range fails, like any empty
     * input.
     */
    template <std::ranges::contiguous_range S>
        requires std::same_as<std::remove_cv_t<std::ranges::range_value_t<S>>, char>
    [[nodiscard]] static bool copyWithTTL(const S& s, DWORD ttl_ms = 6000)
    {
        return copyWithTTL(std::ranges::data(s), std::ranges::size(s), ttl_ms);
    }

    /**
     * @brief Copy a fixed-size `char` array to the clipboard with TTL scrub.
     *
     * Overload for string literals and `char[N]` arrays. @p N counts the null
     * terminator, which is excluded from the copied content.
     */
    template <size_t N>
    [[nodiscard]] static bool copyWithTTL(const char (&s)[N], DWORD ttl_ms = 6000)
    {
        static_assert(N > 0, "empty char array?");
        return copyWithTTL(s, N - 1, ttl_ms);
    }

    /**
     * @brief Copy a null-terminated C string to the clipboard with TTL scrub.
     *
     * @p s is a null-terminated UTF-8 string. A null pointer becomes an empty
     * string, which the clipboard write rejects, so it returns `false`.
     */
    [[nodiscard]] static bool copyWithTTL(const char* s, DWORD ttl_ms = 6000);

    /**
     * @brief Read the `seal` input file and copy its contents to the clipboard.
     *
     * Reads the file named `seal` in the current working directory via
     * `utils::read_bin`, then delegates to copyWithTTL() with the default
     * 6000 ms TTL. The heap buffer holding the file is cleansed before
     * returning; it is pageable memory while the read is in flight.
     *
     * @return `true` when the file was read and the clipboard was set. An empty
     *         file returns `false`.
     *
     * @see copyWithTTL, seal::utils::read_bin
     */
    [[nodiscard]] static bool copyInputFile();

    /**
     * @brief Explicitly join the TTL scrub thread before static destruction.
     *
     * Call this from `main()`, or from an RAII guard on the stack of `main`, so
     * the thread joins while the process is still fully initialised. Left to
     * static destruction, the `jthread` destructor can run after a DLL unload
     * has invalidated the clipboard API entry points and deadlock the join.
     *
     * Stopping the thread cancels the pending scrub: a value copied less than
     * one TTL ago stays on the clipboard after the process exits, and only the
     * user or the next clipboard writer removes it. The call is idempotent, safe
     * with no scrub pending, and blocks for up to one 100 ms poll interval. A
     * later copyWithTTL() starts a fresh thread.
     */
    static void shutdown();

private:
    /**
     * @brief Set UTF-8 text on the Windows clipboard, converting to UTF-16.
     *
     * The conversion passes `MB_ERR_INVALID_CHARS`, so malformed UTF-8 fails
     * instead of being substituted. The block handed to Windows is
     * `GMEM_MOVEABLE` and `SetClipboardData` takes ownership of it; it is not
     * locked memory and seal does not wipe it.
     *
     * @param text UTF-8 string to place on the clipboard. An empty string fails,
     *             because the conversion then yields no code units.
     * @return `true` when the text was set. `false` when the clipboard cannot be
     *         opened, when @p text is empty, longer than `INT_MAX` or not valid
     *         UTF-8, or when the global allocation or `SetClipboardData` fails.
     *
     * @pre No other process holds the clipboard open.
     * @post Once the open succeeded the clipboard has been emptied, so every
     *       later failure leaves it empty rather than holding its previous
     *       content.
     */
    [[nodiscard]] static bool setText(const std::string& text);
};

/**
 * @brief Type a UTF-16 string into the active window using `SendInput`.
 * @ingroup IO_Clipboard
 *
 * Waits @p delay_ms milliseconds so the user can switch focus, then synthesizes
 * `KEYEVENTF_UNICODE` key-down and key-up pairs for each wide character.
 *
 * Both events of one character travel in a single `SendInput` call, and a delay follows every
 * pair. Windows 11 text stacks (modern Notepad, TSF-based editors) drop or transpose
 * characters when the events arrive faster or split across separate calls.
 *
 * The `INPUT` sequence is wiped with `SecureZeroMemory` before the function returns. The
 * plaintext is read straight from the caller's buffer and never copied into a pageable string.
 *
 * @par Injection timeline
 * @verbatim
 * hook heuristic                   advisory keylogger probe, up to 150 ms
 * Sleep(delay_ms)                  initial focus grace (default 4000 ms)
 * for each UTF-16 code unit c:
 *     SendInput(2, pair)           down + up in one call: wScan=c, KEYEVENTF_UNICODE
 *     Sleep(30..45 ms)             pacing after every down/up pair
 * SecureZeroMemory(seq)            wipe the INPUT buffer
 * @endverbatim
 *
 * The per-pair delay is @f$ 30 + (t \bmod 16) @f$ ms, with @f$ t @f$ the current tick
 * count, so it walks the range [30, 45] ms. The tick count paces the loop; it is not a
 * random source.
 *
 * @param bytes    UTF-16 string to type. A null pointer returns `false`.
 * @param len      Number of wide characters, or `-1` for null-terminated. A trailing null
 *                 inside @p len is dropped; a length of zero after that returns `false`.
 * @param delay_ms Delay in milliseconds before typing begins.
 * @return `true` when every pair was accepted. `false` for a null or empty string, or as
 *         soon as one `SendInput` call reports fewer than 2 events - the remaining
 *         characters are then not sent.
 *
 * @pre The target window has keyboard focus when typing begins.
 * @post Every intermediate buffer is wiped.
 *
 * @note A best-effort keylogger heuristic runs first: a zero-size foreground window, or a
 *       median `CallNextHookEx` latency above 2 ms over three synthetic events, writes a
 *       warning through `OutputDebugStringA`. Typing proceeds either way.
 */
[[nodiscard]] bool typeSecret(const wchar_t* bytes, int len, DWORD delay_ms = 4000);

/**
 * @brief Open the `seal` input file in Notepad.
 * @ingroup IO_Clipboard
 *
 * Tries `ShellExecuteA` first and falls back to `CreateProcessW` with
 * `notepad.exe seal` when that fails, as it does on a restricted account. The
 * file name is relative, so Notepad resolves it against the current working
 * directory. The call returns as soon as the launch is accepted and does not
 * wait for Notepad to exit.
 *
 * @return `true` when Notepad was launched.
 */
[[nodiscard]] bool openInputInNotepad();

/**
 * @brief Overwrite the entire console screen buffer with spaces.
 * @ingroup IO_Clipboard
 *
 * Fills every cell of the active console buffer with `' '`, re-applies the
 * current attributes, and resets the cursor to the home position, so a secret
 * printed earlier cannot be read off the screen. A terminal that keeps its own
 * scrollback is not touched.
 *
 * The function does nothing when standard output is not a console screen buffer,
 * so a redirected or GUI-only process is unaffected.
 */
void wipeConsoleBuffer();

}  // namespace seal
