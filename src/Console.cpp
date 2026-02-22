#include "Console.h"

#include <commdlg.h>

namespace
{

// RAII guard for CoTaskMem-allocated credential buffers.
// Securely wipes and frees the buffer on destruction.
struct CoTaskMemGuard
{
    LPVOID ptr = nullptr;
    ULONG size = 0;

    CoTaskMemGuard() = default;

    ~CoTaskMemGuard()
    {
        if (ptr && size)
        {
            SecureZeroMemory(ptr, size);
        }
        if (ptr)
        {
            CoTaskMemFree(ptr);
        }
    }

    CoTaskMemGuard(const CoTaskMemGuard&) = delete;
    CoTaskMemGuard& operator=(const CoTaskMemGuard&) = delete;
};

// RAII guard that securely wipes a fixed-size wchar_t buffer on scope exit.
template<size_t N>
struct SecureWCharBuffer
{
    wchar_t data[N]{};
    DWORD count = static_cast<DWORD>(N);

    SecureWCharBuffer() = default;

    ~SecureWCharBuffer()
    {
        SecureZeroMemory(data, sizeof(data));
    }

    SecureWCharBuffer(const SecureWCharBuffer&) = delete;
    SecureWCharBuffer& operator=(const SecureWCharBuffer&) = delete;
};

} // namespace

namespace sage {

MaskedCredentialView::MaskedCredentialView(const std::vector<sage::secure_triplet16_t>& entries)
    : m_Input(GetStdHandle(STD_INPUT_HANDLE))
    , m_Output(GetStdHandle(STD_OUTPUT_HANDLE))
    , m_Entries(entries)
{
    CONSOLE_SCREEN_BUFFER_INFO info{};
    GetConsoleScreenBufferInfo(m_Output, &info);
    m_Width = info.dwSize.X;

    SHORT winTop = info.srWindow.Top;
    SHORT winBot = info.srWindow.Bottom;
    SHORT winH = static_cast<SHORT>(winBot - winTop + 1);

    // Reserve rows for header + entries + status line
    int maxItems = std::max<SHORT>(0, static_cast<SHORT>(winH - 2));
    m_ShowCount = static_cast<int>(std::min<size_t>(static_cast<size_t>(maxItems), m_Entries.size()));

    render();
}

void MaskedCredentialView::render()
{
    CONSOLE_SCREEN_BUFFER_INFO info{};
    GetConsoleScreenBufferInfo(m_Output, &info);

    SHORT winTop = info.srWindow.Top;
    SHORT winBot = info.srWindow.Bottom;
    int needed = 1 + m_ShowCount + 1;

    SHORT startY = static_cast<SHORT>(winBot - needed + 1);
    if (startY < winTop)
    {
        startY = winTop;
    }

    // Clear the display area
    std::string blank(static_cast<size_t>(m_Width), ' ');
    for (SHORT r = startY; r < startY + needed && r <= winBot; ++r)
    {
        COORD c{ 0, r };
        DWORD written = 0;
        SetConsoleCursorPosition(m_Output, c);
        WriteConsoleA(m_Output, blank.c_str(), static_cast<DWORD>(blank.size()), &written, nullptr);
    }

    // Header line
    SetConsoleCursorPosition(m_Output, { 0, startY });
    DWORD written;
    WriteConsoleA(m_Output,
        "--- Decrypted entries (Click **** to copy; Enter/Esc to continue) ---",
        69, &written, nullptr);
    SetConsoleCursorPosition(m_Output, { 0, static_cast<SHORT>(startY + 1) });

    // Masked credential rows
    m_Regions.clear();
    m_Regions.reserve(static_cast<size_t>(m_ShowCount));

    for (int i = 0; i < m_ShowCount; ++i)
    {
        GetConsoleScreenBufferInfo(m_Output, &info);
        SHORT y = info.dwCursorPosition.Y;

        std::wstring idx = std::to_wstring(i + 1) + L") ";
        // Space needed for ":********:********"
        constexpr int MASKED_TAIL = 1 + MASKED_WIDTH + 1 + MASKED_WIDTH;

        int maxService = std::max<SHORT>(0, static_cast<SHORT>(m_Width - static_cast<int>(idx.size()) - MASKED_TAIL));

        std::wstring svc(m_Entries[static_cast<size_t>(i)].primary.data(),
                         m_Entries[static_cast<size_t>(i)].primary.size());

        // Truncate long service names with ellipsis
        if (static_cast<int>(svc.size()) > maxService)
        {
            if (maxService >= 1)
            {
                int keep = std::max(0, maxService - 3);
                svc = svc.substr(0, keep) + (keep > 0 ? L"..." : L"");
            }
            else
            {
                svc.clear();
            }
        }

        std::wstring prefix = idx + svc + L":";
        std::wstring line = prefix + L"********:********";

        SetConsoleCursorPosition(m_Output, { 0, y });
        WriteConsoleW(m_Output, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);
        SetConsoleCursorPosition(m_Output, { 0, static_cast<SHORT>(y + 1) });

        SHORT u0 = static_cast<SHORT>(prefix.size());
        SHORT u1 = static_cast<SHORT>(u0 + MASKED_WIDTH - 1);
        SHORT p0 = static_cast<SHORT>(u1 + 2);
        SHORT p1 = static_cast<SHORT>(p0 + MASKED_WIDTH - 1);
        m_Regions.push_back(HitRegion{ y, u0, u1, p0, p1 });
    }

    GetConsoleScreenBufferInfo(m_Output, &info);
    m_StatusRow = info.dwCursorPosition.Y;

    // Show overflow indicator if not all entries fit
    if (static_cast<size_t>(m_ShowCount) < m_Entries.size())
    {
        setStatus("[showing " + std::to_string(m_ShowCount) + " of " + std::to_string(m_Entries.size()) + "]");
    }
}

void MaskedCredentialView::setStatus(const std::string& msg)
{
    CONSOLE_SCREEN_BUFFER_INFO info{};
    GetConsoleScreenBufferInfo(m_Output, &info);
    std::string blank(static_cast<size_t>(info.dwSize.X), ' ');
    COORD c{ 0, m_StatusRow };
    DWORD written;
    SetConsoleCursorPosition(m_Output, c);
    WriteConsoleA(m_Output, blank.c_str(), static_cast<DWORD>(blank.size()), &written, nullptr);
    SetConsoleCursorPosition(m_Output, c);
    WriteConsoleA(m_Output, msg.c_str(), static_cast<DWORD>(msg.size()), &written, nullptr);
}

void MaskedCredentialView::setStatusW(const std::wstring& msg)
{
    CONSOLE_SCREEN_BUFFER_INFO info{};
    GetConsoleScreenBufferInfo(m_Output, &info);
    std::string blank(static_cast<size_t>(info.dwSize.X), ' ');
    COORD c{ 0, m_StatusRow };
    DWORD written;
    SetConsoleCursorPosition(m_Output, c);
    WriteConsoleA(m_Output, blank.c_str(), static_cast<DWORD>(blank.size()), &written, nullptr);
    SetConsoleCursorPosition(m_Output, c);
    WriteConsoleW(m_Output, msg.c_str(), static_cast<DWORD>(msg.size()), &written, nullptr);
}

void MaskedCredentialView::handleClick(SHORT x, SHORT y)
{
    for (size_t i = 0; i < m_Regions.size(); ++i)
    {
        if (y != m_Regions[i].row)
        {
            continue;
        }

        const auto& entry = m_Entries[i];
        std::wstring svc(entry.primary.data(), entry.primary.size());

        if (x >= m_Regions[i].usernameStart && x <= m_Regions[i].usernameEnd)
        {
            // Countdown before typing username into the focused window
            for (int s = COUNTDOWN_SEC; s >= 1; --s)
            {
                setStatus("Focus target field; typing USERNAME in " + std::to_string(s) + "s");
                Sleep(1000);
            }
            (void)sage::typeSecret(entry.secondary.data(), static_cast<int>(entry.secondary.size()), 0);
            setStatusW(L"[typed] " + svc + L" username");
        }
        else if (x >= m_Regions[i].passwordStart && x <= m_Regions[i].passwordEnd)
        {
            // Countdown before typing password into the focused window
            for (int s = COUNTDOWN_SEC; s >= 1; --s)
            {
                setStatus("Focus target field; typing PASSWORD in " + std::to_string(s) + "s");
                Sleep(1000);
            }
            (void)sage::typeSecret(entry.tertiary.data(), static_cast<int>(entry.tertiary.size()), 0);
            setStatusW(L"[typed] " + svc + L" password");
        }
        break;
    }
}

void MaskedCredentialView::run()
{
    // Enable mouse input for click detection on masked fields
    DWORD oldMode = 0;
    GetConsoleMode(m_Input, &oldMode);
    DWORD newMode = (oldMode | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE;
    sage::scoped_console modeGuard(m_Input, newMode);
    FlushConsoleInputBuffer(m_Input);

    INPUT_RECORD rec{};
    DWORD nread = 0;
    while (ReadConsoleInput(m_Input, &rec, 1, &nread))
    {
        if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown)
        {
            WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;
            if (vk == VK_RETURN || vk == VK_ESCAPE)
            {
                break;
            }
        }

        if (rec.EventType == MOUSE_EVENT)
        {
            const auto& m = rec.Event.MouseEvent;
            if (m.dwEventFlags == 0 && (m.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED))
            {
                handleClick(m.dwMousePosition.X, m.dwMousePosition.Y);
            }
        }
    }

    // Move cursor below the status line for subsequent output
    SetConsoleCursorPosition(m_Output, { 0, static_cast<SHORT>(m_StatusRow + 1) });
}

void interactiveMaskedWin(const std::vector<sage::secure_triplet16_t>& entries)
{
    MaskedCredentialView view(entries);
    view.run();
}

std::pair<std::vector<std::string>, bool> readBulkLinesDualFrom(std::istream& in)
{
    std::vector<std::string> lines;
    std::string l;
    bool uncensored = false;
    while (true)
    {
        if (!std::getline(in, l))
        {
            break;
        }
        std::string t = sage::utils::trim(l);
        if (t == "?" || t == "!")
        {
            uncensored = (t == "!");
            break;
        }
        if (!t.empty())
        {
            lines.push_back(l);
        }
    }
    return { std::move(lines), uncensored };
}

// Returns: 1 = terminator found (break), 0 = line handled (continue)
static int handleNewline(std::string& cur, std::vector<std::string>& lines, bool& uncensored)
{
    std::string t = sage::utils::trim(cur);

    // Terminator: '?' for censored, '!' for uncensored output
    if (t == "?" || t == "!")
    {
        uncensored = (t == "!");
        std::cout << "\n";
        return 1;
    }

    // Console commands
    if (t == ":open" || t == ":o" || t == ":edit")
    {
        if (!sage::openInputInNotepad())
            std::cerr << "(failed to launch Notepad)\n";
        cur.clear();
        std::cout << "\n";
        return 0;
    }

    if (t == ":copy" || t == ":clip" || t == ":copyfile" || t == ":copyinput")
    {
        bool ok = sage::Clipboard::copyInputFile();
        std::cout << (ok ? "(fence copied to clipboard)" : "(failed to copy fence)") << "\n";
        cur.clear();
        return 0;
    }

    if (t == ":none" || t == ":clear")
    {
        (void)sage::Clipboard::copyWithTTL("");
        std::cout << "(clipboard cleaned)\n";
        cur.clear();
        return 0;
    }

    if (!t.empty())
    {
        lines.push_back(cur);
    }
    cur.clear();
    std::cout << "\n";
    return 0;
}

bool readBulkLinesDualOrEsc(std::pair<std::vector<std::string>, bool>& out)
{
    std::vector<std::string> lines;
    std::string cur;
    bool uncensored = false;

    for (;;)
    {
        int ch = _getch();

        if (ch == 27)
            return false;
        if (ch == 3)
            throw std::runtime_error("Interrupted");
        if (ch == 26)
            throw std::runtime_error("EOF");

        if (ch == '\r' || ch == '\n')
        {
            if (handleNewline(cur, lines, uncensored) == 1)
                break;
            continue;
        }

        // Backspace
        if (ch == 8)
        {
            if (!cur.empty())
            {
                cur.pop_back();
                std::cout << "\b \b" << std::flush;
            }
            continue;
        }

        // Skip extended key sequences (arrow keys, function keys, etc.)
        if (ch == 0 || ch == 224)
        {
            (void)_getch();
            continue;
        }

        cur.push_back(static_cast<char>(ch));
        std::cout << static_cast<char>(ch) << std::flush;
    }

    out = { std::move(lines), uncensored };
    return true;
}

sage::basic_secure_string<wchar_t> readPasswordSecureDesktop(
    const wchar_t* caption,
    const wchar_t* message)
{
    CREDUI_INFOW ui{};
    ui.cbSize = sizeof(ui);
    ui.hwndParent = nullptr;
    ui.pszCaptionText = caption;
    ui.pszMessageText = message;

    // Build an empty pre-filled credential buffer for the dialog
    DWORD inLen = 0;
    wchar_t userPrefill[] = L"";
    wchar_t passEmpty[] = L"";
    (void)CredPackAuthenticationBufferW(0, userPrefill, passEmpty, nullptr, &inLen);

    std::vector<BYTE> inBuf(inLen);
    if (!CredPackAuthenticationBufferW(0, userPrefill, passEmpty, inBuf.data(), &inLen))
    {
        throw std::runtime_error("CredPackAuthenticationBufferW failed");
    }

    // Show the Windows Credentials dialog
    DWORD authPkg = 0;
    CoTaskMemGuard cred;

    HRESULT hr = CredUIPromptForWindowsCredentialsW(
        &ui, 0, &authPkg,
        inBuf.data(), inLen,
        &cred.ptr, &cred.size,
        nullptr, CREDUIWIN_ENUMERATE_CURRENT_USER);

    if (hr != ERROR_SUCCESS)
    {
        throw std::runtime_error("User canceled");
    }

    // Unpack the credential buffer into separate fields (RAII-wiped on scope exit)
    SecureWCharBuffer<256> user;
    SecureWCharBuffer<256> dom;
    SecureWCharBuffer<512> pass;

    BOOL ok = CredUnPackAuthenticationBufferW(
        CRED_PACK_PROTECTED_CREDENTIALS,
        cred.ptr, cred.size,
        user.data, &user.count,
        dom.data, &dom.count,
        pass.data, &pass.count);

    // Fallback: some systems don't support protected credentials
    if (!ok)
    {
        DWORD err = GetLastError();
        if (err == ERROR_NOT_CAPABLE || err == ERROR_NOT_SUPPORTED)
        {
            user.count = static_cast<DWORD>(256);
            dom.count = static_cast<DWORD>(256);
            pass.count = static_cast<DWORD>(512);
            ok = CredUnPackAuthenticationBufferW(
                0, cred.ptr, cred.size,
                user.data, &user.count,
                dom.data, &dom.count,
                pass.data, &pass.count);
        }
    }

    if (!ok)
    {
        throw std::runtime_error("CredUnPackAuthenticationBufferW failed");
    }

    // Copy password into a secure string
    size_t passLen = wcsnlen(pass.data, pass.count);
    sage::basic_secure_string<wchar_t> out;
    out.s.resize(passLen);
    for (size_t i = 0; i < passLen; ++i)
    {
        out.s[i] = static_cast<char16_t>(pass.data[i]);
    }

    return out;
    // ~SecureWCharBuffer and ~CoTaskMemGuard handle all cleanup automatically
}

} // namespace sage
