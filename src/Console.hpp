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
 * Presents decrypted credentials as masked (`********`) rows in the
 * Windows console. Each row shows the service name in clear text and
 * the username / password fields as asterisks.
 *
 * ## :material-mouse: Interaction
 *
 * The user clicks a masked field to begin a 3-second countdown, after
 * which the real value is typed into the currently focused application
 * via `SendInput` keystroke injection (delegated to typeSecret()).
 * Press Enter or Escape to dismiss the view.
 *
 * @see typeSecret
 *
 * ## :material-console: Console State
 *
 * Layout is computed at construction from the current console window
 * size; entries that exceed the visible area are clipped. The interactive
 * loop (run()) saves the console input mode, enables mouse input for
 * hit-testing, and restores the original mode automatically on return
 * (RAII via the `scoped_console` guard local to run()).
 *
 * ## :material-view-column: Masked Row & Hit Regions
 *
 * Each entry renders as one row; the two 8-column `********` spans
 * (`MASKED_WIDTH` = 8) are the click zones. Because the field labels and
 * the masked spans are both 8 columns wide, they line up exactly:
 *
 * @verbatim
 * N) <service>:********:********
 *              username password
 * @endverbatim
 *
 * With `u0` = width of `"N) <service>:"`, the row's hit regions are
 * `[u0, u0+7]` (username) and `[u0+9, u0+16]` (password), separated by the
 * inert `:`. A click inside a span starts a `COUNTDOWN_SEC` (3 s) grace -
 * letting the user focus the target window - then types that field via
 * typeSecret(). Long service names are truncated with `...` to fit.
 */
class MaskedCredentialView
{
public:
    /// Callback that decrypts a single entry on demand by aggregate index.
    /// Returns a freshly decrypted triple (service, username, password).
    using DecryptOnDemand = std::function<seal::secure_triplet16_t(size_t index)>;

    /**
     * @brief Construct the view with pre-decrypted entries (legacy path).
     *
     * Sets up layout based on the current console window size and draws
     * all masked credential rows. If more entries exist than fit in the
     * window, only the first `windowHeight - 2` entries are shown.
     *
     * @param entries Decrypted credential triples to display. The caller
     *        must keep `entries` alive for the lifetime of this object.
     *
     * @pre The process must own a console with valid input and output handles.
     */
    explicit MaskedCredentialView(const std::vector<seal::secure_triplet16_t>& entries);

    /**
     * @brief Construct the view with on-demand decryption (secure path).
     *
     * Only service names (non-secret) are held in memory. Credentials
     * are decrypted via the callback at click time and wiped immediately
     * after keystroke injection, limiting plaintext exposure to one
     * credential at a time.
     *
     * @param serviceNames Service/platform names to display (cleartext).
     * @param decryptEntry Callback invoked at click time to decrypt one credential.
     */
    MaskedCredentialView(std::vector<std::wstring> serviceNames, DecryptOnDemand decryptEntry);

    MaskedCredentialView(const MaskedCredentialView&) = delete;
    MaskedCredentialView& operator=(const MaskedCredentialView&) = delete;

    /**
     * @brief Run the interactive event loop until dismissed.
     *
     * Enables mouse input, then blocks until the user presses Enter or
     * Escape. Mouse clicks on masked fields trigger a countdown and
     * keystroke injection via `seal::typeSecret`. Console input mode
     * is restored automatically when the method returns.
     */
    void run();

private:
    /// @brief Hit-test region for one masked credential row.
    struct HitRegion
    {
        SHORT row;            ///< Console row (Y coordinate)
        SHORT usernameStart;  ///< First column of the masked username field
        SHORT usernameEnd;    ///< Last column of the masked username field
        SHORT passwordStart;  ///< First column of the masked password field
        SHORT passwordEnd;    ///< Last column of the masked password field
    };

    static constexpr int COUNTDOWN_SEC = 3;
    static constexpr int MASKED_WIDTH = 8;

    void render();
    void setStatus(const std::string& msg);
    void setStatusW(const std::wstring& msg);
    void handleClick(SHORT x, SHORT y);

    HANDLE m_Input;
    HANDLE m_Output;
    const std::vector<seal::secure_triplet16_t>* m_pEntries =
        nullptr;                               ///< Legacy pre-decrypted data
    std::vector<std::wstring> m_ServiceNames;  ///< Non-secret names for on-demand mode
    DecryptOnDemand m_DecryptEntry;            ///< Click-time decryptor (on-demand mode only)
    bool m_OnDemandMode = false;               ///< True when using the on-demand decrypt path
    std::vector<HitRegion> m_Regions;
    SHORT m_StatusRow = 0;
    SHORT m_Width = 0;
    int m_ShowCount = 0;
};

/**
 * @brief Display credentials in a masked interactive console view.
 *
 * Convenience wrapper that constructs a `MaskedCredentialView` and runs
 * its event loop. Equivalent to:
 * ```cpp
 * MaskedCredentialView view(entries);
 * view.run();
 * ```
 *
 * @param entries Decrypted credential triples to display.
 *
 * @see MaskedCredentialView
 */
void interactiveMaskedWin(const std::vector<seal::secure_triplet16_t>& entries);

/**
 * @brief Display credentials with on-demand decryption.
 *
 * Only service names are held in memory. Credentials are decrypted
 * via the callback at click time and wiped immediately after typing.
 *
 * @param serviceNames Service/platform names to display.
 * @param decryptEntry Callback invoked to decrypt one credential by index.
 */
void interactiveMaskedWin(std::vector<std::wstring> serviceNames,
                          MaskedCredentialView::DecryptOnDemand decryptEntry);

/**
 * @brief Read multiple non-empty lines from a stream until a terminator.
 *
 * Reads lines from `in` until `?` (censored mode) or `!` (uncensored mode)
 * is entered on its own line. Empty and whitespace-only lines are skipped.
 *
 * @param in Input stream to read from.
 * @return A pair of (collected lines, uncensored flag). The flag is `true`
 *         if the input was terminated with `!`, `false` for `?` or EOF.
 */
std::pair<std::vector<std::string>, bool> readBulkLinesDualFrom(std::istream& in);

/**
 * @brief Read bulk lines from the console with Escape cancellation.
 *
 * Character-by-character console input reader that supports:
 * - **Enter** to submit a line
 * - **Backspace** to delete the last character
 * - **Escape** to cancel (returns `false`)
 * - **Ctrl+C** / **Ctrl+Z** to interrupt / signal EOF
 * - `?` or `!` on its own line to terminate (sets uncensored flag)
 * - `:open` / `:o` / `:edit` to launch the seal file in Notepad
 * - `:copy` / `:clip` / `:copyfile` / `:copyinput` to copy the seal file to the clipboard
 * - `:clear` / `:none` to empty the clipboard
 *
 * @param[out] out Receives the collected lines and uncensored flag on success.
 * @return `true` if input was completed normally, `false` if cancelled via
 *         Escape.
 *
 * @throw std::runtime_error on Ctrl+C (`"Interrupted"`) or Ctrl+Z (`"EOF"`).
 *
 * @see readBulkLinesDualFrom
 */
bool readBulkLinesDualOrEsc(std::pair<std::vector<std::string>, bool>& out);

/**
 * @brief Prompt for a password using the Windows Credentials UI.
 *
 * Displays the `CredUIPromptForWindowsCredentialsW` dialog with
 * `CREDUIWIN_ENUMERATE_CURRENT_USER`, pre-selecting the logged-in account
 * so only the password need be typed. The password field from the dialog
 * is extracted into a `basic_secure_string<wchar_t>`, and all intermediate
 * credential buffers are securely wiped via RAII guards.
 *
 * @param caption Dialog title bar text (default `"seal AES-256-GCM"`).
 * @param message Dialog body text (default `"Enter your master password."`).
 * @return The entered password in a secure wide string.
 *
 * @throw std::runtime_error if the user cancels the dialog or the
 *        credential packing/unpacking API calls fail.
 *
 * @note This does not request the secure desktop: `CREDUIWIN_SECURE_PROMPT`
 *       is not passed, so unless a system policy forces secure credential
 *       prompting the dialog appears on the normal desktop and offers no
 *       inherent protection against keyloggers.
 *
 * @post All intermediate buffers (packed credentials, username, domain,
 *       password) are scrubbed with `SecureZeroMemory`.
 */
seal::basic_secure_string<wchar_t> readPasswordSecureDesktop(
    const wchar_t* caption = L"seal AES-256-GCM",
    const wchar_t* message = L"Enter your master password.");

/**
 * @brief Read a password from the console with masked echo.
 *
 * Prints @p prompt, then reads characters one at a time via `_getch()`.
 * Each character is echoed as `*`. Backspace removes the last character.
 * Enter submits. Escape or Ctrl+C throws.
 *
 * The password is stored directly in a locked-page secure wide string
 * so it never sits in pageable `std::string` memory.
 *
 * @param prompt Text shown before the masked input (default: "Password: ").
 * @return The entered password in a secure wide string.
 * @throw std::runtime_error on Escape or Ctrl+C.
 *
 * @note Characters are read via `_getch()` in the console's active codepage
 *       (often Windows-1252), not UTF-8.
 */
seal::basic_secure_string<wchar_t> readPasswordConsole(const char* prompt = "Password: ");

}  // namespace seal
