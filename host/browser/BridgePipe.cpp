#include "BridgePipe.hpp"

#include "../../src/SignerUtils.hpp"

#include <string>

namespace seal::browser_host
{
namespace
{

constexpr DWORD kConnectTimeoutMs = 5000;
// Candidate-pipe scan cap; only one should match our signer.
constexpr int kPipeBruteForceLimit = 32;

}  // namespace

// Open the seal bridge pipe. Each `seal-fill-*` candidate's server must
// match our publisher's SPKI thumbprint - a same-user attacker can pre-
// create a sorting-earlier pipe but cannot sign with seal's key. Dev mode
// (empty expectedIdentity) accepts the first pipe (mirrors bridge M6).
HANDLE openBridgePipe(const std::string& expectedIdentity)
{
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(L"\\\\.\\pipe\\seal-fill-*", &data);
    if (find == INVALID_HANDLE_VALUE)
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE accepted = INVALID_HANDLE_VALUE;
    int tried = 0;
    do
    {
        if (++tried > kPipeBruteForceLimit)
        {
            break;
        }
        std::wstring fullName = L"\\\\.\\pipe\\";
        fullName += data.cFileName;

        // FILE_FLAG_OVERLAPPED is REQUIRED: the host reads (reverse
        // username-injection directives) and writes (forward click/nav
        // reports) this one duplex handle from two threads concurrently. On a
        // synchronous handle a pending blocking ReadFile holds the file-object
        // lock and would serialize - in fact deadlock - the forward WriteFile.
        HANDLE pipe = CreateFileW(fullName.c_str(),
                                  GENERIC_READ | GENERIC_WRITE,
                                  0,
                                  nullptr,
                                  OPEN_EXISTING,
                                  FILE_FLAG_OVERLAPPED,
                                  nullptr);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            const DWORD err = GetLastError();
            if (err == ERROR_PIPE_BUSY)
            {
                if (WaitNamedPipeW(fullName.c_str(), kConnectTimeoutMs))
                {
                    pipe = CreateFileW(fullName.c_str(),
                                       GENERIC_READ | GENERIC_WRITE,
                                       0,
                                       nullptr,
                                       OPEN_EXISTING,
                                       FILE_FLAG_OVERLAPPED,
                                       nullptr);
                }
            }
            if (pipe == INVALID_HANDLE_VALUE)
            {
                continue;
            }
        }

        // Default client side is BYTE mode; flip to message mode so framed
        // reads/writes are atomic. Failure -> not a real seal bridge.
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr))
        {
            CloseHandle(pipe);
            continue;
        }

        // Signer gate. Without it, a same-user attacker who pre-created a
        // matching pipe would intercept the handshake + click reports.
        DWORD serverPid = 0;
        if (!GetNamedPipeServerProcessId(pipe, &serverPid) || serverPid == 0)
        {
            CloseHandle(pipe);
            continue;
        }
        if (!expectedIdentity.empty())
        {
            const std::wstring serverPath = seal::signer::resolveProcessPath(serverPid);
            if (serverPath.empty() || !seal::signer::winVerifyTrustOk(serverPath))
            {
                CloseHandle(pipe);
                continue;
            }
            const std::string serverIdentity =
                seal::signer::extractSignerIdentityFromFile(serverPath);
            if (serverIdentity.empty() || serverIdentity != expectedIdentity)
            {
                CloseHandle(pipe);
                continue;
            }
        }

        accepted = pipe;
        break;
    } while (FindNextFileW(find, &data));

    FindClose(find);
    return accepted;
}

}  // namespace seal::browser_host
