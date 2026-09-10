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
 * @brief masked console rows with click-triggered credential typing.
 * @author Alex (https://github.com/lextpf)
 * @ingroup MaskedCredentialView
 *
 * service names remain visible; username and password spans use eight asterisks each.
 * a click starts a 3 s countdown before SendInput. enter or escape dismisses the view.
 * layout is fixed at construction; resizing can misalign hit regions. overflow rows are clipped.
 *
 * with `u0` equal to the width of `"N) <service>:"`, the inclusive click ranges are
 * `[u0, u0+7]` for username and `[u0+9, u0+16]` for password. the colon is inert.
 * long service names are truncated to fit.
 *
 * @verbatim
 * N) <service>:********:********
 *              username password
 * @endverbatim
 */
class MaskedCredentialView
{
public:
    /**
     * @brief decrypt one credential by its flat display-row index.
     */
    using DecryptOnDemand = std::function<seal::secure_triplet16_t(size_t index)>;

    /**
     * @brief borrow plaintext entries for the view lifetime.
     *
     * construction draws up to `windowHeight - 2` rows. prefer on-demand decryption unless
     * the caller already holds plaintext.
     * @param entries must outlive the view; credentials remain decrypted throughout.
     * @pre the process owns valid console input and output handles.
     */
    explicit MaskedCredentialView(const std::vector<seal::secure_triplet16_t>& entries);

    /**
     * @brief decrypt only the clicked credential and wipe it after typing.
     *
     * @param serviceNames moved into the view.
     * @param decryptEntry receives a flat display-row index; returns service, username and
     *        password as `primary`, `secondary` and `tertiary`. exceptions propagate from run().
     * @pre the process owns valid console input and output handles.
     */
    MaskedCredentialView(std::vector<std::wstring> serviceNames, DecryptOnDemand decryptEntry);

    MaskedCredentialView(const MaskedCredentialView&) = delete;
    MaskedCredentialView& operator=(const MaskedCredentialView&) = delete;

    /**
     * @brief block until enter, escape or a console read failure.
     *
     * flush pending input and disable quick-edit mode so clicks reach the view.
     * restore the input mode on normal and exceptional exit. on normal exit, also move
     * the cursor below the status line. countdowns block the calling thread.
     * @throw std::exception propagated from the decrypt callback.
     */
    void run();

private:
    struct HitRegion
    {
        SHORT row;            ///< console row (Y coordinate).
        SHORT usernameStart;  ///< first column of the masked username field.
        SHORT usernameEnd;    ///< last column of the masked username field.
        SHORT passwordStart;  ///< first column of the masked password field.
        SHORT passwordEnd;    ///< last column of the masked password field.
    };

    static constexpr int COUNTDOWN_SEC = 3;  ///< seconds between a click and typing.
    static constexpr int MASKED_WIDTH = 8;   ///< Columns per masked field, and its click width.

    void render();
    void setStatus(const std::string& msg);
    void setStatusW(const std::wstring& msg);
    /**
     * @brief resolve a console click to a row and field, then type that field.
     * @param x console column of the click.
     * @param y console row of the click.
     */
    void handleClick(SHORT x, SHORT y);

    HANDLE m_Input;   ///< STD_INPUT_HANDLE, borrowed; never closed by this class.
    HANDLE m_Output;  ///< STD_OUTPUT_HANDLE, borrowed; never closed by this class.
    const std::vector<seal::secure_triplet16_t>* m_pEntries =
        nullptr;                               ///< borrowed pre-decrypted entries; null on demand.
    std::vector<std::wstring> m_ServiceNames;  ///< non-secret names for on-demand mode.
    DecryptOnDemand m_DecryptEntry;            ///< Click-time decryptor (on-demand mode only).
    bool m_OnDemandMode = false;
    std::vector<HitRegion> m_Regions;  ///< one entry per drawn row, in draw order.
    SHORT m_StatusRow = 0;             ///< Row used for countdown and overflow messages.
    SHORT m_Width = 0;                 ///< console buffer width captured at construction.
    int m_ShowCount = 0;               ///< Rows drawn; entries past this are clipped.
};

/**
 * @brief block in a masked view over borrowed plaintext entries.
 * @ingroup MaskedCredentialView
 *
 * ```cpp
 * MaskedCredentialView view(entries);
 * view.run();
 * ```
 *
 * @param entries must remain valid until the call returns.
 * @see MaskedCredentialView
 *

 */
void interactiveMaskedWin(const std::vector<seal::secure_triplet16_t>& entries);

/**
 * @brief block in a masked view with click-time decryption.
 * @ingroup MaskedCredentialView
 *
 * @param serviceNames moved into the view.
 * @param decryptEntry exceptions propagate to the caller.
 * @see MaskedCredentialView
 */
void interactiveMaskedWin(std::vector<std::wstring> serviceNames,
                          MaskedCredentialView::DecryptOnDemand decryptEntry);

/**
 * @brief collect non-blank lines until a standalone terminator or EOF.
 * @ingroup CLI
 *
 * trim only to detect blank lines and `?`/`!`; retain accepted lines verbatim.
 * @return collected lines and a flag that is true only for the `!` terminator.
 */
std::pair<std::vector<std::string>, bool> readBulkLinesDualFrom(std::istream& in);

/**
 * @brief collect echoed console input with escape cancellation.
 * @ingroup CLI
 *
 * use for paths and hex tokens; use readPasswordConsole() for secrets.
 * commands execute without entering the result. extended keys and other control bytes are ignored.
 *
 * | input                                       | effect                         |
 * |---------------------------------------------|--------------------------------|
 * | enter / backspace                           | submit / remove last character |
 * | escape                                      | return false                   |
 * | Ctrl+C / Ctrl+Z                             | throw interrupt / EOF          |
 * | `?` / `!`                                   | finish censored / uncensored   |
 * | `:open`, `:o`, `:edit`                      | open the seal file in notepad  |
 * | `:copy`, `:clip`, `:copyfile`, `:copyinput` | copy the seal file             |
 * | `:clear`, `:none`                           | clear the clipboard            |
 *
 * @param[out] out unchanged on cancellation or exception.
 * @return true on completion, false on escape.
 * @throw std::runtime_error on Ctrl+C or Ctrl+Z.
 */
bool readBulkLinesDualOrEsc(std::pair<std::vector<std::string>, bool>& out);

/**
 * @brief read a password through the credentials dialog into locked memory.
 * @ingroup CLI
 *
 * username and domain are discarded. all intermediate buffers are wiped on scope exit.
 * unpacking retries without protection flags on ERROR_NOT_CAPABLE or ERROR_NOT_SUPPORTED.
 * buffers have 256 wchar_t slots for username/domain and 512 for password, including terminators.
 *
 * @param secureDesktop requests the secure desktop; policy can select the normal
 *        desktop without reporting the fallback.
 * @return the entered password, possibly empty.
 * @throw std::runtime_error on packing/unpacking failure or dialog cancellation.
 *        every dialog error is reported as `"User canceled"`.
 */
seal::basic_secure_string<wchar_t> readPasswordSecureDesktop(
    const wchar_t* caption = L"seal AES-256-GCM",
    const wchar_t* message = L"Enter your master password.",
    bool secureDesktop = true);

/**
 * @brief read masked console input into locked memory.
 * @ingroup CLI
 *
 * prompt, echo and newline go to stderr. enter submits; backspace removes a character.
 * extended-key sequences are ignored; other control bytes remain part of the password.
 * input uses the active console codepage and is widened with GetConsoleCP(), not UTF-8.
 * these wide code units determine the scrypt key for non-ASCII passwords.
 *
 * @return the entered password, possibly empty; callers enforce any non-empty requirement.
 * @throw std::runtime_error on escape (`"Cancelled"`) or Ctrl+C (`"Interrupted"`).
 */
seal::basic_secure_string<wchar_t> readPasswordConsole(const char* prompt = "Password: ");

}  // namespace seal
