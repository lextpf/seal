#pragma once

#include "Cryptography.h"

#include <cstddef>
#include <string>

namespace seal
{

/**
 * @class Clipboard
 * @brief Static utility class for Windows clipboard operations with
 *        automatic TTL-based scrubbing of sensitive data.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Clipboard
 *
 * Wraps the Win32 clipboard API behind a simple static interface.
 * Internally, an anonymous-namespace RAII guard (`ClipboardLock`)
 * manages `OpenClipboard` / `CloseClipboard` lifetime so callers
 * never need to worry about cleanup.
 *
 * ## :material-clipboard-text: Text Placement
 *
 * setText() converts a UTF-8 `std::string` to UTF-16 via
 * `MultiByteToWideChar` and places it on the clipboard as
 * `CF_UNICODETEXT`. The clipboard is emptied before writing so
 * stale data from other applications is never leaked.
 *
 * ## :material-timer-sand: TTL Scrubbing
 *
 * copyWithTTL() copies data to the clipboard and then spawns a
 * detached background thread that sleeps for a configurable
 * duration (default 6 s). When the thread wakes it performs a
 * constant-time comparison (`Cryptography::ctEqualAny`) of the current
 * clipboard content against the original value and empties the
 * clipboard only if the content is unchanged - so a manual paste
 * by the user between apps is never clobbered.
 *
 * ## :material-file-lock: Input-File Helper
 *
 * copyInputFile() reads the `seal` binary input file into memory
 * and delegates to copyWithTTL, giving CLI users a one-shot
 * "read-and-scrub" workflow.
 */
class Clipboard
{
public:
    Clipboard() = delete;
    Clipboard(const Clipboard&) = delete;
    Clipboard& operator=(const Clipboard&) = delete;

    /**
     * @brief Set UTF-8 text on the Windows clipboard, converting to UTF-16.
     *
     * Opens the clipboard, empties it, converts @p text from UTF-8 to
     * UTF-16 with `MultiByteToWideChar`, and places the result as
     * `CF_UNICODETEXT`. The clipboard is closed automatically when the
     * internal RAII guard goes out of scope.
     *
     * @param text UTF-8 encoded string to place on the clipboard.
     * @return `true` if the text was set successfully, `false` on conversion
     *         failure or if the clipboard could not be opened.
     *
     * @pre No other process holds the clipboard open.
     */
    [[nodiscard]] static bool setText(const std::string& text);

    /**
     * @brief Copy a byte buffer to the clipboard and auto-scrub after a timeout.
     *
     * Copies @p n bytes of UTF-8 data to the clipboard via setText, then
     * spawns a detached thread that sleeps for @p ttl_ms milliseconds. When
     * the thread wakes it re-opens the clipboard, performs a constant-time
     * comparison of the current content against the original value, and
     * empties the clipboard only if the content is unchanged. The original
     * buffer is securely wiped regardless.
     *
     * @param data   Pointer to the raw UTF-8 byte buffer.
     * @param n      Length of @p data in bytes.
     * @param ttl_ms Milliseconds before the clipboard is scrubbed (default 6000).
     * @return `true` if the initial clipboard set succeeded.
     *
     * @post A detached background thread will clear the clipboard after
     *       @p ttl_ms if the content has not been replaced by another
     *       application.
     *
     * @see setText
     * @see Cryptography::ctEqualAny
     */
    [[nodiscard]] static bool copyWithTTL(const char* data, size_t n, DWORD ttl_ms = 6000);

    /**
     * @brief Copy a contiguous `char` range to the clipboard with TTL scrub.
     *
     * Convenience overload that delegates to the `(const char*, size_t)`
     * overload. Accepts any contiguous range whose value type decays to
     * `char` (e.g. `std::string`, `std::string_view`, `secure_string`).
     *
     * @tparam S Contiguous range of `char`.
     * @param s      Source range to copy.
     * @param ttl_ms Scrub delay in milliseconds (default 6000).
     * @return `true` if the clipboard was set successfully.
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
     * Overload for string literals and `char[N]` arrays. The trailing null
     * terminator is excluded from the copied content.
     *
     * @tparam N Array size (including null terminator).
     * @param s      Source array.
     * @param ttl_ms Scrub delay in milliseconds (default 6000).
     * @return `true` if the clipboard was set successfully.
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
     * Overload for raw `const char*` pointers. A null pointer is treated as
     * an empty string.
     *
     * @param s      Null-terminated UTF-8 string (may be null).
     * @param ttl_ms Scrub delay in milliseconds (default 6000).
     * @return `true` if the clipboard was set successfully.
     */
    [[nodiscard]] static bool copyWithTTL(const char* s, DWORD ttl_ms = 6000);

    /**
     * @brief Read the `seal` input file and copy its contents to the clipboard.
     *
     * Reads the file via `utils::read_bin`, then delegates to copyWithTTL so the
     * clipboard is automatically scrubbed after the default TTL.
     *
     * @return `true` if the file was read and clipboard was set successfully.
     *
     * @see copyWithTTL
     * @see seal::utils::read_bin
     */
    [[nodiscard]] static bool copyInputFile();
};

/**
 * @brief Type a UTF-16 string into the active window using `SendInput`.
 *
 * Waits @p delay_ms milliseconds (to let the user switch focus), then
 * synthesizes `KEYEVENTF_UNICODE` key-down / key-up pairs for each wide
 * character. A small randomised inter-keystroke delay is added after each
 * pair to improve compatibility with input-rate-limited applications.
 *
 * Both the `INPUT` sequence and the working copy of the string are securely
 * wiped with `SecureZeroMemory` before the function returns.
 *
 * @param bytes    UTF-16 string to type.
 * @param len      Number of wide characters, or `-1` for null-terminated.
 * @param delay_ms Delay in milliseconds before typing begins (default 4000).
 * @return `true` if the input was valid and keystrokes were dispatched
 *         (individual `SendInput` results are not verified).
 *
 * @pre The target window must have keyboard focus when typing begins.
 * @post All intermediate buffers are securely wiped.
 */
[[nodiscard]] bool typeSecret(const wchar_t* bytes, int len, DWORD delay_ms = 4000);

/**
 * @brief Open the `seal` input file in Notepad.
 *
 * Attempts `ShellExecuteA` first; falls back to `cmd /c start notepad.exe`
 * if `ShellExecuteA` fails (e.g. on restricted accounts).
 *
 * @return `true` if Notepad was launched successfully.
 */
[[nodiscard]] bool openInputInNotepad();

/**
 * @brief Overwrite the entire console screen buffer with spaces.
 *
 * Fills every cell in the active console buffer with `' '` and resets the
 * cursor to the home position. Used to prevent visual inspection of
 * previously displayed sensitive data.
 */
void wipeConsoleBuffer();

}  // namespace seal
