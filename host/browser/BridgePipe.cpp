#include "BridgePipe.hpp"

#include "../../src/SignerUtils.hpp"

#include <string>

namespace seal::browser_host
{
namespace
{

constexpr DWORD kConnectTimeoutMs = 5000;
// Bound scan cost; enough earlier decoys can hide a valid pipe.
constexpr int kPipeBruteForceLimit = 32;

}  // namespace

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

        // Overlapped I/O permits concurrent duplex traffic. A synchronous read holds
        // the file-object lock and can deadlock the forward writer.
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

        // Message mode requires separate length and payload operations.
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr))
        {
            CloseHandle(pipe);
            continue;
        }

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
