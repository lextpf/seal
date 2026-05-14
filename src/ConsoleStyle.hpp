#pragma once

#include <iosfwd>
#include <string_view>

namespace seal
{
/**
 * @namespace seal::console
 * @brief ANSI-coloured console output primitives for diagnostics and logs.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Logging
 *
 * Thin layer over `std::ostream` that emits semantic tone-coloured
 * text on Windows consoles. The first write to each stream enables
 * `ENABLE_VIRTUAL_TERMINAL_PROCESSING` and caches whether colour is
 * available; subsequent writes pay only a `std::call_once` fast path.
 *
 * If the stream is not a console, or VT processing cannot be enabled
 * (redirected output, legacy terminal), all writes transparently fall
 * back to uncoloured plain text -- callers never need to branch on
 * terminal capability.
 *
 * @note Only `std::cout` and `std::cerr` are tracked; any other stream
 *       is treated as `std::cerr` for the purposes of state lookup.
 */
namespace console
{

/**
 * @brief Semantic colour categories for console output.
 * @ingroup Logging
 *
 * Each tone maps to a fixed ANSI colour code. Callers pick the tone
 * that matches the *meaning* of the message (success, warning, step
 * progress) rather than a raw colour, so the palette can be retuned
 * centrally without touching call sites.
 */
enum class Tone
{
    Plain,    ///< No colour -- emit text unchanged.
    Debug,    ///< Bright black / grey -- low-signal trace output.
    Info,     ///< Cyan -- informational status.
    Step,     ///< Bright blue -- progress step in a multi-phase operation.
    Success,  ///< Bright green -- successful completion.
    Warning,  ///< Bright yellow -- recoverable anomaly.
    Error,    ///< Bright red -- failure.
    Summary,  ///< Bright magenta -- end-of-run aggregate output.
    Banner    ///< Bright cyan -- headers and section dividers.
};

/**
 * @brief Write a tone-coloured line terminated with `'\n'`.
 * @ingroup Logging
 *
 * When colour is available and @p tone is not Plain, the text is
 * wrapped in the tone's ANSI escape and a reset sequence. Otherwise
 * the raw text is written.
 *
 * @param os   Destination stream (typically `std::cout` or `std::cerr`).
 * @param tone Semantic colour category.
 * @param text Line contents (trailing newline is appended automatically).
 */
void writeLine(std::ostream& os, Tone tone, std::string_view text);

/**
 * @brief Write a bracketed tag in colour followed by plain body text.
 * @ingroup Logging
 *
 * Emits `[tag] text\n` where only the bracketed tag receives the
 * tone colour. Used throughout the CLI for subsystem-prefixed
 * diagnostics, e.g. `[CAM] event=probe ok=true`.
 *
 * @param os   Destination stream.
 * @param tone Colour applied to the `[tag]` prefix.
 * @param tag  Short subsystem label (rendered inside square brackets).
 * @param text Message body; omitted if empty (only the tag is written).
 */
void writeTagged(std::ostream& os, Tone tone, std::string_view tag, std::string_view text);

/**
 * @brief Pre-parsed segments of a Qt log line for `writeLogLine`.
 * @ingroup Logging
 *
 * All views must remain valid for the duration of the `writeLogLine`
 * call. Each field is rendered with its own emphasis (timestamp and
 * thread dimmed, category tinted, level coloured by severity).
 */
struct LogSegments
{
    std::string_view timestamp;  ///< Formatted wall-clock timestamp (e.g. `HH:mm:ss.zzz`).
    std::string_view level;      ///< Severity token (e.g. `DEBUG`, `WARN`, `FATAL`).
    std::string_view category;   ///< Qt logging category (e.g. `seal.vault`).
    std::string_view threadId;   ///< Originating thread identifier.
    std::string_view message;    ///< Log message body.
};

/**
 * @brief Write a fully formatted multi-segment log line.
 * @ingroup Logging
 *
 * Renders as:
 * `[timestamp] [level] [category] [tid=threadId] message\n`
 *
 * Timestamp and thread-id brackets are dimmed; the category is tinted
 * magenta; the level bracket uses @p levelTone. For Warning and Error
 * tones the message body is also tinted so the full line reads as a
 * single alert; other tones leave the message in the default colour.
 *
 * @param os        Destination stream (typically `std::cerr`).
 * @param levelTone Colour for the `[level]` bracket and warn/error messages.
 * @param segs      Pre-parsed segments; fields are rendered verbatim.
 */
void writeLogLine(std::ostream& os, Tone levelTone, const LogSegments& segs);

}  // namespace console
}  // namespace seal
