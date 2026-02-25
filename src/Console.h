#pragma once

#include "Cryptography.h"
#include "Utils.h"
#include "Clipboard.h"

#include <wincred.h>
#include <conio.h>

#include <iostream>
#include <string>
#include <vector>

namespace sage {

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
 * via `SendInput` keystroke injection (delegated to TypeSecret()).
 * Press Enter or Escape to dismiss the view.
 *
 * ## :material-console: Console State
 *
 * On construction the console input mode is saved, and mouse input is
 * enabled for hit-testing. On destruction the original mode is restored
 * automatically (RAII). Layout adapts to the current console window
 * size; entries that exceed the visible area are clipped.
 */
class MaskedCredentialView
{
public:
    /**
     * @brief Construct the view and render masked entries to the console.
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
    explicit MaskedCredentialView(const std::vector<sage::secure_triplet16_t>& entries);

    MaskedCredentialView(const MaskedCredentialView&) = delete;
    MaskedCredentialView& operator=(const MaskedCredentialView&) = delete;

    /**
     * @brief Run the interactive event loop until dismissed.
     *
     * Enables mouse input, then blocks until the user presses Enter or
     * Escape. Mouse clicks on masked fields trigger a countdown and
     * keystroke injection via `sage::typeSecretUTF8`. Console input mode
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
    const std::vector<sage::secure_triplet16_t>& m_Entries;
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
void interactiveMaskedWin(const std::vector<sage::secure_triplet16_t>& entries);

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
 * - `:open` / `:edit` to launch the sage file in Notepad
 * - `:copy` / `:clip` to copy the sage file to the clipboard
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
 * Displays the `CredUIPromptForWindowsCredentialsW` dialog, which runs on
 * the secure desktop to prevent keylogging. The password field from the
 * dialog is extracted into a `basic_secure_string<wchar_t>`, and all
 * intermediate credential buffers are securely wiped via RAII guards.
 *
 * @param caption Dialog title bar text (default `"sage AES-256-GCM"`).
 * @param message Dialog body text (default `"Enter your master password."`).
 * @return The entered password in a secure wide string.
 *
 * @throw std::runtime_error if the user cancels the dialog or the
 *        credential packing/unpacking API calls fail.
 *
 * @post All intermediate buffers (packed credentials, username, domain,
 *       password) are scrubbed with `SecureZeroMemory`.
 */
sage::basic_secure_string<wchar_t> readPasswordSecureDesktop(
    const wchar_t* caption = L"sage AES-256-GCM",
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
 */
sage::basic_secure_string<wchar_t> readPasswordConsole(
    const char* prompt = "Password: ");

} // namespace sage
