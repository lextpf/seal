/*  ============================================================================================  *
 *                                                            ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
 *                                                            ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
 *           ::::::::  ::::::::::     :::     :::             ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
 *          :+:    :+: :+:          :+: :+:   :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
 *          +:+        +:+         +:+   +:+  +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
 *          +#++:++#++ +#++:++#   +#++:++#++: +#+             ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
 *                 +#+ +#+        +#+     +#+ +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇
 *          #+#    #+# #+#        #+#     #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
 *           ########  ########## ###     ### ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
 *                                                            ⠀⠀⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 *
 *                                  << P A S S   M A N A G E R >>
 *
 *  ============================================================================================  *
 *
 *      A Windows AES-256-GCM encryption utility with Qt6/QML GUI and CLI
 *      providing on-demand credential management, directory encryption,
 *      webcam QR authentication, and global auto-fill.
 *
 *    ----------------------------------------------------------------------
 *
 *      Repository:   https://github.com/lextpf/seal
 *      License:      MIT
 */

/**
 * seal-browser - native messaging host.
 *
 * Relays framed messages between the browser's native-messaging stdio channel and
 * seal's in-process BrowserBridge over a named pipe. The browser launches this host
 * when the extension calls connectNative().
 *
 * Payloads are forwarded unchanged in both directions. No message schema is parsed
 * here; validation remains the responsibility of seal.exe.
 *
 * Authentication:
 *   - Accept only seal-fill-* pipes whose server has seal.exe's Authenticode signer.
 *   - BrowserBridge accepts this host only when it has the same signer identity.
 *   - Require this host to have been launched by a signed browser.
 *   - Restrict the pipe with a per-user ACL.
 *   - Verify a per-connection token echo.
 *   - Validate argv[1] as an extension origin.
 *
 * Per-gate implementation details live in the sibling headers.
 *
 * Startup:
 *   wmain evaluates the security gates in cost order, cheapest first. Each failure
 *   has a dedicated exit code. Because Chrome swallows stderr, diagnostics are also
 *   written as a reason token to:
 *
 *       %LOCALAPPDATA%\seal\bridge-host-last-exit.log
 *
 * Exit codes:
 *    0  Clean stdin EOF, failed forward write, or bridge pipe termination
 *       (distinguished by the logged reason token)
 *    1  Invalid stdin or stdout handle
 *    2  No signer-matching bridge pipe, or event creation failed
 *    3  Bridge handshake read failed
 *    4  Handshake write to stdout failed
 *    5  Handshake echo read from stdin failed
 *    6  Handshake echo write to the bridge failed
 *    7  argv[1] is not a valid extension origin
 *    8  Parent PID could not be resolved
 *    9  stdin is not a pipe served by the parent or a signed browser
 *   10  stdout is not a pipe served by the parent or a signed browser
 *   11  Parent does not own the stdin pipe object  (signed builds only)
 *   12  Parent does not own the stdout pipe object (signed builds only)
 *   13  SEAL_REQUIRE_SIGNED_PEER build is unsigned
 */

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
        // A direct exec by malware lands here. A browser launch always passes the
        // extension origin as argv[1].
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

    // Parent PID plus stdio-server check (isStdHandleFromProcess documents the
    // soft-pass rules). The parent PID comes from the OS, not from a signature,
    // so unsigned dev builds enforce these three gates as well.
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

    // SPKI thumbprint of this binary's own publisher certificate. It is empty in an
    // unsigned build, and openBridgePipe then degrades to "first candidate wins".
    // A non-empty identity is what the gates below call production mode.
    const std::string ownIdentity = seal::signer::readOwnSignerIdentity();
    const bool inProductionMode = !ownIdentity.empty();

#ifdef SEAL_REQUIRE_SIGNED_PEER
    // Fail closed. An unsigned host would let openBridgePipe fall back to "first
    // candidate pipe wins" and skip the server signer check, so a build that asks
    // for a signed peer refuses to run unsigned instead. With the flag off, dev
    // builds keep the degraded mode. This mirrors the bridge's startImpl guard in
    // seal.exe.
    if (!inProductionMode)
    {
        emitExitDiag(13, "unsigned_production");
        return 13;
    }
#endif

    // Strict ownership check: enumerate the parent's handles and confirm one points at
    // the same kernel pipe object as this process's stdin. This closes the puppet hole
    // left open by the anonymous-pipe soft-pass in isStdHandleFromProcess. A signed
    // build fails the launch; an unsigned build logs and continues.
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
            // Unsigned build: log and continue. The bridge signer gate and the
            // parent-image check are still in effect.
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
        // Either seal.exe is not running, or no candidate pipe had a trusted signer.
        // Exiting is safe: the browser respawns this host on the next message.
        emitExitDiag(2, "bridge_pipe_not_found");
        return 2;
    }

    // openBridgePipe returns an overlapped handle, so each direction needs its own
    // manual-reset event to keep concurrent read and write completions apart. The
    // shutdown event wakes the reverse reader at teardown. An early return below
    // leaves these handles open, which is harmless because the process exits.
    HANDLE pipeReadEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE pipeWriteEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (pipeReadEvent == nullptr || pipeWriteEvent == nullptr || shutdownEvent == nullptr)
    {
        CloseHandle(pipe);
        emitExitDiag(2, "event_create_failed");
        return 2;
    }

    // Handshake, bridge -> extension: the bridge's hello carries a per-connection
    // nonce. Relay it verbatim; this host neither reads nor stores it.
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

    // Echo, extension -> bridge: the bridge serves no payload until the nonce comes
    // back, so a failure here means the connection never becomes usable.
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

    // Reverse relay, bridge -> extension: a dedicated thread pumps pipe -> stdout for
    // seal's username-injection directives. The overlapped handle lets this read and
    // the forward write run at the same time; a synchronous handle would deadlock,
    // because a pending blocking read holds the file-object lock.
    std::thread reverseReader(
        [pipe, stdoutHandle, pipeReadEvent, shutdownEvent]()
        {
            while (true)
            {
                std::vector<char> rmsg = readPipeMessage(pipe, pipeReadEvent, shutdownEvent);
                if (rmsg.empty())
                {
                    // An empty read means either an orderly teardown, where the main
                    // loop signalled shutdownEvent and is about to join, or the
                    // bridge dying underneath this thread. The shutdown event
                    // separates the two.
                    //
                    // On bridge death nothing here can wake the main thread: it is
                    // parked in a blocking stdin read that only the browser can end.
                    // Without this exit the host lingers and holds the browser's
                    // native-messaging port open. The extension reconnects only once
                    // that port drops, so its backoff and its 30 s alarm both stay
                    // disarmed, and restarting seal never reconnects until the
                    // extension is reloaded by hand. Exiting lets the browser see
                    // the drop and reconnect.
                    //
                    // The three literals below are pinned as text by the source-scan test
                    // BrowserHostBoundary.HostExitsWhenItsBridgePipeDies, which greps this
                    // file for the reason token, the ExitProcess call and the shutdownEvent
                    // test. Rewording any of them fails seal_tests, which never compiles
                    // host/browser/.
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

    // Forward loop, extension -> bridge. Payloads pass through unparsed; the bridge
    // validates them.
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

    // Deterministic teardown: signal the reverse reader, which wakes from its
    // overlapped read wait whatever the timing, join it, then close the handles.
    SetEvent(shutdownEvent);
    reverseReader.join();
    CloseHandle(pipe);
    CloseHandle(pipeReadEvent);
    CloseHandle(pipeWriteEvent);
    CloseHandle(shutdownEvent);
    // Log the success path too. A clean-exit line is positive evidence that the host
    // launched, relayed, and was not stopped at a gate.
    writeExitLog(0, loopExitReason);
    return 0;
}
