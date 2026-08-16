#include "BridgePipe.hpp"

#include "../../src/SignerUtils.hpp"

#include <string>

namespace seal::browser_host
{
namespace
{

constexpr DWORD kConnectTimeoutMs = 5000;
// Candidate-pipe scan cap. The first match wins, and more than one candidate can
// match: the signer compare is publisher-granular, and a second seal.exe instance
// publishes its own seal-fill-* pipe, so enumeration order decides which bridge this
// host binds to. The cap bounds scan cost. The trade-off is that more decoys than
// this limit enumerating ahead of the real pipe hide it, and the launch then fails
// with exit code 2.
constexpr int kPipeBruteForceLimit = 32;

}  // namespace

// Open the seal bridge pipe. The server behind a `seal-fill-*` candidate has to
// match this host's own publisher SPKI thumbprint: a same-user attacker can
// pre-create a pipe that sorts earlier, but cannot sign it with seal's key. An
// unsigned build passes an empty expectedIdentity and accepts the first reachable
// candidate, matching the degraded mode of the bridge's M6 signer gate.
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

        // FILE_FLAG_OVERLAPPED is load-bearing. Two threads use this one duplex
        // handle at the same time: the reverse reader takes username-injection
        // directives, the forward writer sends click and nav reports. On a
        // synchronous handle a pending blocking ReadFile holds the file-object lock,
        // which serializes and in practice deadlocks the forward WriteFile.
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

        // The client side starts in byte mode; message mode makes each framed read
        // and write atomic. A failure here means the pipe is not a seal bridge.
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr))
        {
            CloseHandle(pipe);
            continue;
        }

        // Signer gate. Without it, a same-user attacker who pre-created a matching
        // pipe would intercept the handshake and every click report.
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
