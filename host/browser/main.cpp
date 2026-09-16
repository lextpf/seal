/*/-============================================================================================-\*\

                                                             ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
                                                             ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
            ::::::::  ::::::::::     :::     :::             ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
           :+:    :+: :+:          :+: :+:   :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
           +:+        +:+         +:+   +:+  +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
           +#++:++#++ +#++:++#   +#++:++#++: +#+             ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
                  +#+ +#+        +#+     +#+ +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇          
           #+#    #+# #+#        #+#     #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
            ########  ########## ###     ### ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
                                                              ⠀ ⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 
                                    << P A S S   M A N A G E R >>
  
\*\-============================================================================================-/*/
/*
 *               A Windows AES-256-GCM encryption utility with Qt6/QML GUI and CLI
 *               providing on-demand credential management, directory encryption,
 *               webcam QR authentication, and global auto-fill.
 *
 *             +--------------------------------------------------------------------+
 *
 *               Repository:   https://github.com/lextpf/seal
 *               License:      GPL
 */

// Relay opaque frames between browser stdio and the authenticated bridge pipe.
// Schema validation belongs to seal.exe. Gates run before relay startup; failures
// also log to %LOCALAPPDATA%\seal\bridge-host-last-exit.log.
//
// Exit codes:
//    0  clean stdin EOF, failed forward write, or bridge pipe termination
//       (distinguished by the logged reason token)
//    1  invalid stdin or stdout handle
//    2  no signer-matching bridge pipe, or event creation failed
//    3  bridge handshake read failed
//    4  handshake write to stdout failed
//    5  handshake echo read from stdin failed
//    6  handshake echo write to the bridge failed
//    7  argv[1] is not a valid extension origin
//    8  parent PID could not be resolved
//    9  stdin is not a pipe served by the parent or a signed browser
//   10  stdout is not a pipe served by the parent or a signed browser
//   11  parent does not own the stdin pipe object  (signed builds only)
//   12  parent does not own the stdout pipe object (signed builds only)
//   13  SEAL_REQUIRE_SIGNED_PEER build is unsigned

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "../../src/SignerUtils.hpp"
#include "BridgePipe.hpp"
#include "ExitLog.hpp"
#include "HandleVerification.hpp"
#include "LaunchOrigin.hpp"
#include "MessageFraming.hpp"

#include <string>
#include <thread>
#include <vector>

int wmain()
{
    using namespace seal::browser_host;

    if (!isLegitimateLaunchOrigin())
    {
        emitExitDiag(7, "bad_launch_origin");
        return 7;
    }

    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdinHandle == INVALID_HANDLE_VALUE || stdoutHandle == INVALID_HANDLE_VALUE)
    {
        emitExitDiag(1, "std_handle_invalid");
        return 1;
    }

    // Parent resolution and stdio-server checks apply even in unsigned builds.
    const DWORD ownPid = GetCurrentProcessId();
    const DWORD parentPid = seal::signer::resolveParentPid(ownPid);
    if (parentPid == 0)
    {
        emitExitDiag(8, "parent_pid_unknown");
        return 8;
    }
    if (!isStdHandleFromProcess(stdinHandle, parentPid))
    {
        emitExitDiag(9, "stdin_server_check_failed");
        return 9;
    }
    if (!isStdHandleFromProcess(stdoutHandle, parentPid))
    {
        emitExitDiag(10, "stdout_server_check_failed");
        return 10;
    }

    // Empty identity selects unsigned development policy.
    const std::string ownIdentity = seal::signer::readOwnSignerIdentity();
    const bool inProductionMode = !ownIdentity.empty();

#ifdef SEAL_REQUIRE_SIGNED_PEER
    // SEAL_REQUIRE_SIGNED_PEER forbids unsigned host startup, matching seal.exe.
    if (!inProductionMode)
    {
        emitExitDiag(13, "unsigned_production");
        return 13;
    }
#endif

    // Check the claimed parent holds each stdio pipe object; this closes the
    // anonymous-pipe exception. Signed builds fail closed on query failure.
    {
        const std::wstring stdinPipeName = getHandlePipeName(stdinHandle);
        const bool stdinOwnershipProven =
            !stdinPipeName.empty() && parentOwnsPipe(parentPid, stdinPipeName);
        if (!stdinOwnershipProven)
        {
            if (inProductionMode)
            {
                emitExitDiag(11, "stdin_parent_ownership_unverified");
                return 11;
            }
            // Unsigned builds log inconclusive ownership and continue.
            writeExitLog(0, "dev_mode_stdin_ownership_skipped");
        }
        const std::wstring stdoutPipeName = getHandlePipeName(stdoutHandle);
        const bool stdoutOwnershipProven =
            !stdoutPipeName.empty() && parentOwnsPipe(parentPid, stdoutPipeName);
        if (!stdoutOwnershipProven)
        {
            if (inProductionMode)
            {
                emitExitDiag(12, "stdout_parent_ownership_unverified");
                return 12;
            }
            writeExitLog(0, "dev_mode_stdout_ownership_skipped");
        }
    }

    HANDLE pipe = openBridgePipe(ownIdentity);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        emitExitDiag(2, "bridge_pipe_not_found");
        return 2;
    }

    // Each duplex direction needs its own manual-reset event. shutdownEvent wakes
    // the reader. Startup failure may leave handles for process-exit cleanup.
    HANDLE pipeReadEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE pipeWriteEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (pipeReadEvent == nullptr || pipeWriteEvent == nullptr || shutdownEvent == nullptr)
    {
        CloseHandle(pipe);
        emitExitDiag(2, "event_create_failed");
        return 2;
    }

    // Relay the nonce frame unchanged; the host does not parse it.
    {
        std::vector<char> hs = readPipeMessage(pipe, pipeReadEvent, shutdownEvent);
        if (hs.empty())
        {
            CloseHandle(pipe);
            emitExitDiag(3, "bridge_handshake_read_failed");
            return 3;
        }
        if (!writeNativeMessage(stdoutHandle, hs))
        {
            CloseHandle(pipe);
            emitExitDiag(4, "stdout_handshake_write_failed");
            return 4;
        }
    }

    {
        std::vector<char> echo = readNativeMessage(stdinHandle);
        if (echo.empty())
        {
            CloseHandle(pipe);
            emitExitDiag(5, "stdin_handshake_echo_failed");
            return 5;
        }
        if (!writePipeMessage(pipe, pipeWriteEvent, echo))
        {
            CloseHandle(pipe);
            emitExitDiag(6, "bridge_handshake_echo_write_failed");
            return 6;
        }
    }

    // Keep overlapped reads independent of forward writes on the duplex pipe.
    std::thread reverseReader(
        [pipe, stdoutHandle, pipeReadEvent, shutdownEvent]()
        {
            while (true)
            {
                std::vector<char> rmsg = readPipeMessage(pipe, pipeReadEvent, shutdownEvent);
                if (rmsg.empty())
                {
                    // shutdownEvent distinguishes requested teardown from bridge death.
                    // On bridge death, ExitProcess must release the native port: the main thread
                    // is blocked on browser stdin and cannot observe the dead pipe. Dropping
                    // the port allows the extension to reconnect.
                    if (WaitForSingleObject(shutdownEvent, 0) != WAIT_OBJECT_0)
                    {
                        emitExitDiag(0, "bridge_pipe_closed");
                        ExitProcess(0);
                    }
                    break;  // orderly teardown: shutdownEvent is signalled
                }
                if (!writeNativeMessage(stdoutHandle, rmsg))
                {
                    break;  // extension stdout closed
                }
            }
        });

    // Relay payloads unchanged; schema validation belongs to seal.exe.
    const char* loopExitReason = "stdin_eof";  // the browser closed this host's stdin
    while (true)
    {
        std::vector<char> msg = readNativeMessage(stdinHandle);
        if (msg.empty())
        {
            break;
        }
        if (!writePipeMessage(pipe, pipeWriteEvent, msg))
        {
            loopExitReason = "bridge_write_failed";
            break;
        }
    }

    // Wake and join the reader before closing shared handles.
    SetEvent(shutdownEvent);
    reverseReader.join();
    CloseHandle(pipe);
    CloseHandle(pipeReadEvent);
    CloseHandle(pipeWriteEvent);
    CloseHandle(shutdownEvent);

    writeExitLog(0, loopExitReason);
    return 0;
}
