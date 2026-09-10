#pragma once

#include <iosfwd>
#include <string_view>

namespace seal
{
/**
 * @namespace seal::console
 * @brief console output with semantic ANSI colours.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Logging
 *
 * the first write attempts ENABLE_VIRTUAL_TERMINAL_PROCESSING and caches console detection.
 * redirected output is plain text. if a console rejects the VT flag, it still receives escapes.
 * only std::cout and std::cerr have separate state; other streams use stderr's state.
 * calls do not lock complete lines. callers must serialize concurrent writes.
 */
namespace console
{

/**
 * @enum Tone
 * @brief semantic output colours.
 * @ingroup Logging
 */
enum class Tone
{
    Plain,    ///< no colour - emit text unchanged.
    Debug,    ///< bright black / grey - low-signal trace output.
    Info,     ///< cyan - informational status.
    Step,     ///< bright blue - progress step in a multi-phase operation.
    Success,  ///< bright green - successful completion.
    Warning,  ///< bright yellow - recoverable anomaly.
    Error,    ///< bright red - failure.
    Summary,  ///< bright magenta - end-of-run aggregate output.
    Banner    ///< bright cyan - headers and section dividers.
};

/**
 * @brief append a newline and reset any applied ANSI colour.
 * @ingroup Logging
 *
 * Tone::Plain and redirected output use no escape sequences.
 */
void writeLine(std::ostream& os, Tone tone, std::string_view text);

/**
 * @brief colour only the bracketed tag and append a newline.
 * @ingroup Logging
 *
 * output is `[tag] text`; an empty body emits only the tag.
 */
void writeTagged(std::ostream& os, Tone tone, std::string_view tag, std::string_view text);

/**
 * @brief confirm an action with one input line.
 * @ingroup CLI
 *
 * only `y` or `Y`, after trimming ASCII whitespace, confirms. EOF and all other input refuse.
 * @param force skip all I/O and return true.
 * @param err receives the prompt; use stderr to keep stdout available for piped output.
 */
bool ConfirmDestructive(bool force, std::istream& in, std::ostream& err, const char* prompt);

/**
 * @struct LogSegments
 * @brief borrowed segments of a diagnostic line.
 * @ingroup Logging
 *
 * all views must remain valid until writeLogLine() returns.
 */
struct LogSegments
{
    std::string_view timestamp;  ///< formatted wall-clock timestamp (e.g. `HH:mm:ss.zzz`).
    std::string_view level;      ///< Severity token (e.g. `DBG`, `WRN`, `FTL`).
    std::string_view category;   ///< Qt logging category, bare/no prefix (e.g. `vault`).
    std::string_view threadId;   ///< Originating thread identifier.
    std::string_view message;    ///< Log message body.
};

/**
 * @brief write a diagnostic line with separate colours for each segment.
 * @ingroup Logging
 *
 * append a newline. unknown categories use bright magenta; Tone::Warning and Tone::Error also tint
 * the message body. segments are emitted verbatim.
 *
 * @verbatim
 * [timestamp] [level] [category] [tid=threadId] message
 *    dim       tone     accent        dim       default (tinted on Warn/Error)
 * @endverbatim
 */
void writeLogLine(std::ostream& os, Tone levelTone, const LogSegments& segs);

}  // namespace console
}  // namespace seal
