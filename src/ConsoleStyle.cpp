#include "ConsoleStyle.h"

#include <iostream>
#include <mutex>
#include <ostream>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace
{

struct StreamState
{
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::once_flag init;
    bool colorEnabled = false;
};

StreamState& stateFor(std::ostream& os)
{
    static StreamState stdoutState;
    static StreamState stderrState;
    static std::once_flag handlesInit;
    std::call_once(handlesInit,
                   []()
                   {
                       stdoutState.handle = GetStdHandle(STD_OUTPUT_HANDLE);
                       stderrState.handle = GetStdHandle(STD_ERROR_HANDLE);
                   });

    if (&os == &std::cout)
        return stdoutState;
    return stderrState;
}

void initialize(StreamState& state)
{
    if (state.handle == INVALID_HANDLE_VALUE || state.handle == nullptr)
        return;

    DWORD mode = 0;
    if (!GetConsoleMode(state.handle, &mode))
        return;

    if (!(mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    {
        (void)SetConsoleMode(state.handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    DWORD verifyMode = 0;
    state.colorEnabled = GetConsoleMode(state.handle, &verifyMode) != 0;
}

const char* codeFor(seal::console::Tone tone)
{
    using Tone = seal::console::Tone;
    switch (tone)
    {
        case Tone::Debug:
            return "\x1b[90m";
        case Tone::Info:
            return "\x1b[36m";
        case Tone::Step:
            return "\x1b[94m";
        case Tone::Success:
            return "\x1b[92m";
        case Tone::Warning:
            return "\x1b[93m";
        case Tone::Error:
            return "\x1b[91m";
        case Tone::Summary:
            return "\x1b[95m";
        case Tone::Banner:
            return "\x1b[96m";
        case Tone::Plain:
        default:
            return "";
    }
}

}  // namespace

namespace seal::console
{

void writeLine(std::ostream& os, Tone tone, std::string_view text)
{
    StreamState& state = stateFor(os);
    std::call_once(state.init, [&state]() { initialize(state); });

    if (state.colorEnabled && tone != Tone::Plain)
    {
        os << codeFor(tone) << text << "\x1b[0m\n";
    }
    else
    {
        os << text << '\n';
    }
}

void writeTagged(std::ostream& os, Tone tone, std::string_view tag, std::string_view text)
{
    StreamState& state = stateFor(os);
    std::call_once(state.init, [&state]() { initialize(state); });

    if (state.colorEnabled && tone != Tone::Plain)
    {
        os << codeFor(tone) << '[' << tag << ']' << "\x1b[0m";
    }
    else
    {
        os << '[' << tag << ']';
    }

    if (!text.empty())
        os << ' ' << text;
    os << '\n';
}

void writeLogLine(std::ostream& os, Tone levelTone, const LogSegments& segs)
{
    StreamState& state = stateFor(os);
    std::call_once(state.init, [&state]() { initialize(state); });

    const bool color = state.colorEnabled;
    const char* dim = color ? "\x1b[90m" : "";
    const char* accent = color ? "\x1b[95m" : "";
    const char* lvl = color ? codeFor(levelTone) : "";
    const char* reset = color ? "\x1b[0m" : "";
    const bool tintMsg = color && (levelTone == Tone::Warning || levelTone == Tone::Error);

    os << dim << '[' << segs.timestamp << ']' << reset << ' ' << lvl << '[' << segs.level << ']'
       << reset << ' ' << accent << '[' << segs.category << ']' << reset << ' ' << dim
       << "[tid=" << segs.threadId << ']' << reset << ' ';
    if (tintMsg)
        os << lvl;
    os << segs.message;
    if (tintMsg)
        os << reset;
    os << '\n';
}

}  // namespace seal::console
