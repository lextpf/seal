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
 * seal-browser stdio <-> named-pipe relay between the browser's native-messaging channel
 * and seal's in-process BrowserBridge. The browser spawns it when the WebExtension calls
 * connectNative(); it forwards framed messages both ways and parses none itself.
 *
 * Defence in depth, mutual authentication: each end verifies the other's
 * Authenticode signer - we reject any seal-fill-* pipe not signed like us,
 * and the bridge rejects us unless we're signed like it and launched by a
 * signed browser. A per-user pipe ACL, a per-connection token echo, and an
 * argv[1] native-messaging-origin gate back it up; per-gate specifics live in
 * the sibling modules below.
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
        // Direct exec by malware lands here; the browser's launch always
        // passes the extension origin as argv[1].
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

    // Parent PID + stdio-server check (see isStdHandleFromProcess for
    // the soft-pass rules). OS-derived parent PID works without signing,
    // so dev/unsigned builds enforce this too.
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

    // SPKI thumbprint of our own publisher cert; empty in dev builds, in
    // which case openBridgePipe degrades to "first candidate wins".
    const std::string ownIdentity = seal::signer::readOwnSignerIdentity();
    const bool inProductionMode = !ownIdentity.empty();

    // Strict ownership check: enumerate the parent's handles and confirm
    // one points at our stdin's kernel pipe object. Closes the puppet
    // hole that isStdHandleFromProcess's anonymous-pipe soft-pass leaves
    // open. Production hard-fails; dev logs and continues.
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
            // Dev: log only and continue; bridge signer + parent-image
            // checks remain in effect.
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
        // No seal running, or no candidate pipe with a trusted signer.
        // Exit; browser respawns us on the next message.
        emitExitDiag(2, "bridge_pipe_not_found");
        return 2;
    }

    // The pipe is overlapped (see openBridgePipe). Each direction gets its own
    // manual-reset event; a shutdown event lets the reverse reader wake
    // deterministically at teardown. On an early-return error below the process
    // exits immediately, so leaking these handles there is harmless.
    HANDLE pipeReadEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE pipeWriteEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (pipeReadEvent == nullptr || pipeWriteEvent == nullptr || shutdownEvent == nullptr)
    {
        CloseHandle(pipe);
        emitExitDiag(2, "event_create_failed");
        return 2;
    }

    // Handshake: bridge -> extension.
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

    // Echo: extension -> bridge.
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

    // Reverse relay (bridge -> extension): a dedicated thread pumps pipe -> stdout
    // for seal's username-injection directives. The pipe is OVERLAPPED so this read
    // and the forward write run concurrently; a synchronous handle would deadlock.
    std::thread reverseReader(
        [pipe, stdoutHandle, pipeReadEvent, shutdownEvent]()
        {
            while (true)
            {
                std::vector<char> rmsg = readPipeMessage(pipe, pipeReadEvent, shutdownEvent);
                if (rmsg.empty())
                {
                    break;  // pipe closed / EOF / shutdown signaled
                }
                if (!writeNativeMessage(stdoutHandle, rmsg))
                {
                    break;  // extension stdout closed
                }
            }
        });

    // Main loop: extension -> bridge, no parsing (bridge validates strictly).
    const char* loopExitReason = "stdin_eof";  // browser closed our stdin
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

    // Deterministic teardown: signal the reverse reader (it wakes from its
    // overlapped read wait regardless of timing), join, then close everything.
    SetEvent(shutdownEvent);
    reverseReader.join();
    CloseHandle(pipe);
    CloseHandle(pipeReadEvent);
    CloseHandle(pipeWriteEvent);
    CloseHandle(shutdownEvent);
    // Log the happy path too -- a clean-exit line is positive evidence
    // that the host launched, ran, and wasn't killed at a gate.
    writeExitLog(0, loopExitReason);
    return 0;
}
