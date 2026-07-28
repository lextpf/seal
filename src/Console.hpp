#pragma once

#include "Clipboard.hpp"
#include "Cryptography.hpp"
#include "Utils.hpp"

#include <conio.h>
#include <wincred.h>

#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace seal
{

/**
 * @class MaskedCredentialView
 * @brief Interactive masked console UI for decrypted credential triples.
 * @author Alex (https://github.com/lextpf)
 * @ingroup MaskedCredentialView
 *
 * Presents decrypted credentials as masked (`********`) rows in the Windows
 * console. Each row shows the service name in clear text and the username and
 * password fields as asterisks.
 *
 * ## :material-mouse: Interaction
 *
 * A click on a masked field starts a `COUNTDOWN_SEC` (3 s) countdown that lets
 * the user focus the target window, then typeSecret() injects the real value
 * into the focused application with `SendInput`. typeSecret() is called with a
 * delay of 0, so the countdown is the whole grace period. Enter or Escape
 * dismisses the view.
 *
 * @see typeSecret
 *
 * ## :material-console: Console State
 *
 * Layout is computed once at construction from the current console window
 * size; entries past the visible area are clipped. run() saves the console
 * input mode, enables mouse input for hit-testing, and restores the original
 * mode on return through the `scoped_console` guard local to run().
 *
 * ## :material-view-column: Masked Row & Hit Regions
 *
 * Each entry renders as one row. The two 8-column `********` spans
 * (`MASKED_WIDTH` = 8) are the click zones, and they line up with the field
 * labels because both are 8 columns wide:
 *
 * @verbatim
 * N) <service>:********:********
 *              username password
 * @endverbatim
 *
 * With `u0` = width of `"N) <service>:"`, the hit regions are `[u0, u0+7]`
 * (username) and `[u0+9, u0+16]` (password), separated by the inert `:`. Long
 * service names are truncated with `...` to fit, and a click outside both
 * spans on a matched row is ignored.
 */
class MaskedCredentialView
{
public:
    /// Callback that decrypts one entry on demand, addressed by display-row index.
    /// The index selects the row in @p serviceNames. One input token can hold several
    /// triples, so the index is flat across all rows, not an index inside one token.
    /// Returns a freshly decrypted triple (service, username, password).
    using DecryptOnDemand = std::function<seal::secure_triplet16_t(size_t index)>;

    /**
     * @brief Construct the view over already-decrypted entries.
     *
     * Sets up the layout from the current console window size and draws the
     * masked rows at once. Only the first `windowHeight - 2` entries are
     * shown; the rest are clipped and reported as `[showing n of m]` on the
     * status row. The layout is never recomputed, so resizing the window after
     * construction misplaces the hit regions.
     *
     * @param entries Borrowed; must stay alive for the lifetime of this
     *        object. Every credential in it stays decrypted for that whole
     *        time, so prefer the on-demand constructor unless the caller
     *        already holds the plaintext.
     *
     * @pre The process owns a console with valid input and output handles.
     */
    explicit MaskedCredentialView(const std::vector<seal::secure_triplet16_t>& entries);

    /**
     * @brief Construct the view with on-demand decryption.
     *
     * Only the non-secret service names stay in memory. A credential is
     * decrypted at click time and wiped right after keystroke injection, so at
     * most one plaintext credential exists at a time. Layout and clipping
     * match the other constructor.
     *
     * @param serviceNames Cleartext service names to display. Moved into the
     *        view, so the caller keeps no lifetime duty.
     * @param decryptEntry Called at click time with the row index into
     *        @p serviceNames. It must return the triple for that row; the view
     *        types `secondary` for the username span and `tertiary` for the
     *        password span, then lets the triple wipe itself. An exception from
     *        this callback is not caught: it propagates out of run() and out of
     *        interactiveMaskedWin(); see run() for the console-state effect.
     *
     * @pre The process owns a console with valid input and output handles.
     */
    MaskedCredentialView(std::vector<std::wstring> serviceNames, DecryptOnDemand decryptEntry);

    MaskedCredentialView(const MaskedCredentialView&) = delete;
    MaskedCredentialView& operator=(const MaskedCredentialView&) = delete;

    /**
     * @brief Run the interactive event loop until dismissed.
     *
     * Enables mouse input, disables quick-edit mode (which would swallow the
     * clicks), flushes pending console input, then blocks the calling thread
     * until the user presses Enter or Escape, or until `ReadConsoleInput`
     * fails. Only a left-button press with no movement flag counts as a click,
     * and the countdown sleeps this thread one second per step.
     *
     * On return the previous console input mode is restored and the cursor
     * sits one row below the status line, so later output does not overwrite
     * the view.
     *
     * @throw std::exception On-demand mode calls the decrypt callback inside this
     *        loop and does not catch its exceptions. The `scoped_console` guard
     *        still restores the console input mode, but the cursor stays where the
     *        view drew it.
     */
    void run();

private:
    /// @brief Hit-test region for one masked credential row.
    struct HitRegion
    {
        SHORT row;            ///< Console row (Y coordinate).
        SHORT usernameStart;  ///< First column of the masked username field.
        SHORT usernameEnd;    ///< Last column of the masked username field.
        SHORT passwordStart;  ///< First column of the masked password field.
        SHORT passwordEnd;    ///< Last column of the masked password field.
    };

    static constexpr int COUNTDOWN_SEC = 3;  ///< Seconds between a click and typing.
    static constexpr int MASKED_WIDTH = 8;   ///< Columns per masked field, and its click width.

    /// @brief Draw the header, every visible row and the overflow status, and
    /// rebuild the hit regions from the drawn columns.
    void render();
    /// @brief Replace the status row with narrow text (padded with blanks first).
    void setStatus(const std::string& msg);
    /// @brief Replace the status row with wide text, for service names.
    void setStatusW(const std::wstring& msg);
    /// @brief Resolve a console click to a row and field, then type that field.
    /// @param x Console column of the click.
    /// @param y Console row of the click.
    void handleClick(SHORT x, SHORT y);

    HANDLE m_Input;   ///< STD_INPUT_HANDLE, borrowed; never closed by this class.
    HANDLE m_Output;  ///< STD_OUTPUT_HANDLE, borrowed; never closed by this class.
    const std::vector<seal::secure_triplet16_t>* m_pEntries =
        nullptr;                               ///< Borrowed pre-decrypted entries; null on demand.
    std::vector<std::wstring> m_ServiceNames;  ///< Non-secret names for on-demand mode.
    DecryptOnDemand m_DecryptEntry;            ///< Click-time decryptor (on-demand mode only).
    bool m_OnDemandMode = false;               ///< True on the on-demand decrypt path.
    std::vector<HitRegion> m_Regions;          ///< One entry per drawn row, in draw order.
    SHORT m_StatusRow = 0;                     ///< Row used for countdown and overflow messages.
    SHORT m_Width = 0;                         ///< Console buffer width captured at construction.
    int m_ShowCount = 0;                       ///< Rows drawn; entries past this are clipped.
};

/**
 * @brief Display credentials in a masked interactive console view.
 * @ingroup MaskedCredentialView
 *
 * Convenience wrapper around MaskedCredentialView; blocks until the user
 * dismisses the view. Equivalent to:
 * ```cpp
 * MaskedCredentialView view(entries);
 * view.run();
 * ```
 *
 * @param entries Borrowed for the duration of the call.
 *
 * @see MaskedCredentialView
 */
void interactiveMaskedWin(const std::vector<seal::secure_triplet16_t>& entries);

/**
 * @brief Display credentials with on-demand decryption.
 * @ingroup MaskedCredentialView
 *
 * Only service names stay in memory. The callback decrypts a credential at click
 * time; the view wipes it after typing. Blocks until the user dismisses the view.
 *
 * @param serviceNames Cleartext service names to display; moved into the view.
 * @param decryptEntry Decrypts one credential by row index.
 *
 * @throw std::exception An exception from @p decryptEntry is not caught and
 *        passes through this call.
 */
void interactiveMaskedWin(std::vector<std::wstring> serviceNames,
                          MaskedCredentialView::DecryptOnDemand decryptEntry);

/**
 * @brief Read multiple non-empty lines from a stream until a terminator.
 * @ingroup CLI
 *
 * Reads lines from @p in until `?` (censored) or `!` (uncensored) appears on its
 * own line. Empty and whitespace-only lines are skipped. Trimming applies only to
 * those tests: a kept line is stored as read, with its leading and trailing spaces.
 *
 * @param in Input stream to read from.
 * @return A pair of (collected lines, uncensored flag). The flag is `true`
 *         when the input ended with `!`, `false` for `?` or EOF.
 */
std::pair<std::vector<std::string>, bool> readBulkLinesDualFrom(std::istream& in);

/**
 * @brief Read bulk lines from the console with Escape cancellation.
 * @ingroup CLI
 *
 * Reads the console one character at a time and supports:
 * - **Enter** to submit a line
 * - **Backspace** to delete the last character
 * - **Escape** to cancel (returns `false`)
 * - **Ctrl+C** / **Ctrl+Z** to interrupt / signal EOF
 * - `?` or `!` on its own line to terminate (sets uncensored flag)
 * - `:open` / `:o` / `:edit` to launch the seal file in Notepad
 * - `:copy` / `:clip` / `:copyfile` / `:copyinput` to copy the seal file to the clipboard
 * - `:clear` / `:none` to empty the clipboard
 *
 * A command line is executed and dropped: it never becomes a collected line.
 * Extended-key prefixes (`0x00`, `0xE0`) consume the following code and are
 * ignored, and every other control character is discarded, so a paste that
 * injects `0x16` cannot corrupt a path.
 *
 * @param[out] out Written only on success; left untouched when this returns
 *             `false` or throws.
 * @return `true` when input completed normally, `false` when Escape cancelled
 *         it.
 *
 * @throw std::runtime_error on Ctrl+C (`"Interrupted"`) or Ctrl+Z (`"EOF"`).
 *
 * @note Typed characters are echoed in clear text, not masked. This reader is
 *       for paths and hex tokens; use readPasswordConsole() for secrets.
 *
 * @see readBulkLinesDualFrom
 */
bool readBulkLinesDualOrEsc(std::pair<std::vector<std::string>, bool>& out);

/**
 * @brief Prompt for a password using the Windows Credentials UI.
 * @ingroup CLI
 *
 * Shows the `CredUIPromptForWindowsCredentialsW` dialog with
 * `CREDUIWIN_ENUMERATE_CURRENT_USER`, which pre-selects the logged-in account
 * so the user types only the password. The password lands in a
 * `basic_secure_string<wchar_t>`; username and domain are unpacked and
 * discarded.
 *
 * @par Unpacking
 * The buffer is unpacked with `CRED_PACK_PROTECTED_CREDENTIALS` first, then
 * retried once with flag 0 on `ERROR_NOT_CAPABLE` or `ERROR_NOT_SUPPORTED`.
 * The unpack buffers are fixed at 256 wide characters for username and domain
 * and 512 for the password, so a longer password cannot be returned.
 *
 * @param caption Dialog title bar text (default `"seal AES-256-GCM"`).
 * @param message Dialog body text (default `"Enter your master password."`).
 * @param secureDesktop When true (the default), request `CREDUIWIN_SECURE_PROMPT`
 *        so the dialog renders on Windows' secure desktop, dimmed and isolated
 *        from user-session keyloggers and hooks. Best-effort: policy or an RDP
 *        session can fall back to the normal desktop, and the API does not
 *        report that.
 * @return The entered password in a secure wide string. Confirming an empty
 *         password field returns an empty string.
 *
 * @throw std::runtime_error when the user cancels (`"User canceled"`) or a
 *        credential packing or unpacking call fails. Every non-success result
 *        from the dialog is reported as `"User canceled"`, so a genuine dialog
 *        failure is indistinguishable from a cancel.
 *
 * @post RAII guards scrub every intermediate buffer (packed credentials,
 *       username, domain, password) with `SecureZeroMemory`.
 */
seal::basic_secure_string<wchar_t> readPasswordSecureDesktop(
    const wchar_t* caption = L"seal AES-256-GCM",
    const wchar_t* message = L"Enter your master password.",
    bool secureDesktop = true);

/**
 * @brief Read a password from the console with masked echo.
 * @ingroup CLI
 *
 * Prints @p prompt, then reads characters one at a time via `_getch()`.
 * Each character is echoed as `*`. Backspace removes the last character.
 * Enter submits. Escape or Ctrl+C throws. Extended-key prefixes (`0x00`,
 * `0xE0`) consume the following code and are ignored; any other control
 * character is accepted as part of the password.
 *
 * The prompt, the `*` echo and the closing newline all go to stderr, so stdout
 * stays pipe-clean for the command's real output. Characters accumulate in a
 * locked-page narrow secure string and are widened once at the end into the
 * returned locked-page wide string. No plaintext sits in a pageable `std::string`.
 *
 * @param prompt Text shown before the masked input (default `"Password: "`).
 * @return The entered password in a secure wide string. Submitting nothing
 *         returns an empty string; that is not an error here, so a caller that
 *         rejects an empty password has to check it.
 * @throw std::runtime_error on Escape (`"Cancelled"`) or Ctrl+C
 *        (`"Interrupted"`).
 *
 * @note Characters arrive in the console's active codepage and are widened
 *       with `GetConsoleCP()` (often Windows-1252), not UTF-8. scrypt is fed
 *       the raw wide code units, so the codepage is part of key derivation for
 *       non-ASCII passwords.
 */
seal::basic_secure_string<wchar_t> readPasswordConsole(const char* prompt = "Password: ");

}  // namespace seal
