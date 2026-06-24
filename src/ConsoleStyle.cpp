#include "ConsoleStyle.hpp"

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
    {
        return stdoutState;
    }
    return stderrState;
}

void initialize(StreamState& state)
{
    if (state.handle == INVALID_HANDLE_VALUE || state.handle == nullptr)
    {
        return;
    }

    DWORD mode = 0;
    if (!GetConsoleMode(state.handle, &mode))
    {
        return;
    }

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

// Per-category ANSI foreground colour so 9 subsystems are distinguishable
// at a glance in a tail. Unknown categories fall back to bright magenta
// (the pre-change default), preserving behaviour for non-seal callers.
const char* categoryColor(std::string_view cat)
{
    if (cat == "backend")
    {
        return "\x1b[95m";  // bright magenta -- QML bridge / central event hub
    }
    if (cat == "vault")
    {
        return "\x1b[93m";  // bright yellow -- vault data
    }
    if (cat == "crypto")
    {
        return "\x1b[92m";  // bright green -- security primitives
    }
    if (cat == "fill")
    {
        return "\x1b[94m";  // bright blue -- autofill action
    }
    if (cat == "bridge")
    {
        return "\x1b[33m";  // dark yellow -- browser bridge (distinct from vault)
    }
    if (cat == "file")
    {
        return "\x1b[36m";  // cyan -- file I/O
    }
    if (cat == "app")
    {
        return "\x1b[97m";  // bright white -- application lifecycle (distinct from INF cyan)
    }
    if (cat == "camera")
    {
        return "\x1b[91m";  // bright red -- camera enumeration
    }
    if (cat == "qr")
    {
        return "\x1b[35m";  // dark magenta -- QR capture
    }
    return "\x1b[95m";  // default: bright magenta (pre-change behaviour)
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
    {
        os << ' ' << text;
    }
    os << '\n';
}

void writeLogLine(std::ostream& os, Tone levelTone, const LogSegments& segs)
{
    StreamState& state = stateFor(os);
    std::call_once(state.init, [&state]() { initialize(state); });

    const bool color = state.colorEnabled;
    const char* dim = color ? "\x1b[90m" : "";
    // Per-category accent colour; unknown categories -> bright magenta.
    const char* accent = color ? categoryColor(segs.category) : "";
    const char* lvl = color ? codeFor(levelTone) : "";
    const char* reset = color ? "\x1b[0m" : "";
    const bool tintMsg = color && (levelTone == Tone::Warning || levelTone == Tone::Error);

    os << dim << '[' << segs.timestamp << ']' << reset << ' ' << lvl << '[' << segs.level << ']'
       << reset << ' ' << accent << '[' << segs.category << ']' << reset << ' ' << dim
       << "[tid=" << segs.threadId << ']' << reset << ' ';
    if (tintMsg)
    {
        os << lvl;
    }
    os << segs.message;
    if (tintMsg)
    {
        os << reset;
    }
    os << '\n';
}

bool ConfirmDestructive(bool force, std::istream& in, std::ostream& err, const char* prompt)
{
    if (force)
    {
        return true;
    }
    err << prompt << " [y/N]: " << std::flush;
    std::string line;
    if (!std::getline(in, line))
    {
        err << "\n";
        return false;
    }
    // Trim ASCII whitespace; only an explicit y/Y confirms.
    const auto first = line.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
    {
        return false;
    }
    const auto last = line.find_last_not_of(" \t\r\n");
    const std::string trimmed = line.substr(first, last - first + 1);
    return trimmed == "y" || trimmed == "Y";
}

}  // namespace seal::console
