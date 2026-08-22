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
 * Thin layer over `std::ostream` that emits semantic tone-coloured text on
 * Windows consoles. The first write to each stream tries to set
 * `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on that stream's standard handle and
 * caches the outcome; later writes pay only a `std::call_once` fast path.
 *
 * Colour counts as available when the handle is a console, that is when
 * `GetConsoleMode` succeeds. Redirected output (file or pipe) fails that test
 * and falls back to plain text, so callers never branch on terminal
 * capability. The VT bit is not re-tested after the attempt, so a console host
 * that refuses VT processing still receives escape sequences.
 *
 * @note Only `std::cout` and `std::cerr` are tracked; state lookup treats any
 *       other stream as `std::cerr`.
 *
 * @note Each function writes one line through several stream insertions and
 *       takes no lock. Two threads writing to the same stream can interleave
 *       inside a line; serialising them is the caller's job.
 */
namespace console
{

/**
 * @enum Tone
 * @brief Semantic colour categories for console output.
 * @ingroup Logging
 *
 * Each tone maps to a fixed ANSI colour code. Callers pick the tone by message meaning (success,
 * warning, step progress), not a raw colour, so the palette can be retuned in one place.
 *
 * @par Palette (SGR foreground code)
 * | Tone      | SGR  | Colour              |
 * |-----------|------|---------------------|
 * | `Plain`   | none | (uncoloured)        |
 * | `Debug`   | `90` | bright black / grey |
 * | `Info`    | `36` | cyan                |
 * | `Step`    | `94` | bright blue         |
 * | `Success` | `92` | bright green        |
 * | `Warning` | `93` | bright yellow       |
 * | `Error`   | `91` | bright red          |
 * | `Summary` | `95` | bright magenta      |
 * | `Banner`  | `96` | bright cyan         |
 */
enum class Tone
{
    Plain,    ///< No colour - emit text unchanged.
    Debug,    ///< Bright black / grey - low-signal trace output.
    Info,     ///< Cyan - informational status.
    Step,     ///< Bright blue - progress step in a multi-phase operation.
    Success,  ///< Bright green - successful completion.
    Warning,  ///< Bright yellow - recoverable anomaly.
    Error,    ///< Bright red - failure.
    Summary,  ///< Bright magenta - end-of-run aggregate output.
    Banner    ///< Bright cyan - headers and section dividers.
};

/**
 * @brief Write a tone-coloured line terminated with `'\n'`.
 * @ingroup Logging
 *
 * When colour is available and @p tone is not Plain, the text is wrapped in the tone's ANSI escape
 * and a reset sequence. Otherwise the raw text is written.
 *
 * @param os   Destination stream (typically `std::cout` or `std::cerr`).
 * @param tone Semantic colour category; `Tone::Plain` emits no escape sequence.
 * @param text Line contents; the trailing newline is appended for you.
 */
void writeLine(std::ostream& os, Tone tone, std::string_view text);

/**
 * @brief Write a bracketed tag in colour followed by plain body text.
 * @ingroup Logging
 *
 * Emits `[tag] text\n`, with the tone colour on the bracketed tag only. The CLI uses it for
 * subsystem-prefixed diagnostics, e.g. `[CAM] event=probe ok=true`.
 *
 * @param os   Destination stream (typically `std::cout` or `std::cerr`).
 * @param tone Colour applied to the `[tag]` prefix.
 * @param tag  Short subsystem label, rendered inside square brackets.
 * @param text Message body; when empty, only the tag is written.
 */
void writeTagged(std::ostream& os, Tone tone, std::string_view tag, std::string_view text);

/**
 * @brief Interactive y/N gate for destructive or plaintext-emitting actions.
 * @ingroup CLI
 *
 * Prints `<prompt> [y/N]: ` to @p err and reads one line from @p in. Only
 * `y`/`Y` confirms; everything else, EOF and a closed stdin included, refuses.
 * Leading and trailing ASCII whitespace is trimmed first, so `" y "` confirms
 * while `"yes"` and a blank line refuse. One line is consumed, so the caller
 * can keep reading @p in afterwards.
 *
 * @param force  Skip the prompt (e.g. `--force`) and return `true` at once,
 *               reading nothing from @p in and writing nothing to @p err.
 * @param in     Input stream: stdin in production, a stringstream in tests.
 * @param err    Stream for the prompt; stderr keeps stdout pipe-clean.
 * @param prompt Question to display, without the trailing `[y/N]`.
 * @return `true` when the action is confirmed.
 */
bool ConfirmDestructive(bool force, std::istream& in, std::ostream& err, const char* prompt);

/**
 * @struct LogSegments
 * @brief Pre-parsed segments of a Qt log line for `writeLogLine`.
 * @ingroup Logging
 *
 * Every view must stay valid for the duration of the `writeLogLine` call. Each field carries its
 * own emphasis: timestamp and thread dimmed, category tinted, level coloured by severity.
 */
struct LogSegments
{
    std::string_view timestamp;  ///< Formatted wall-clock timestamp (e.g. `HH:mm:ss.zzz`).
    std::string_view level;      ///< Severity token (e.g. `DBG`, `WRN`, `FTL`).
    std::string_view category;   ///< Qt logging category, bare/no prefix (e.g. `vault`).
    std::string_view threadId;   ///< Originating thread identifier.
    std::string_view message;    ///< Log message body.
};

/**
 * @brief Write a fully formatted multi-segment log line.
 * @ingroup Logging
 *
 * Renders as `[timestamp] [level] [category] [tid=threadId] message\n`.
 *
 * Timestamp and thread-id brackets are dimmed. The category gets a
 * per-category tint, so `[vault]` and `[bridge]` stay distinguishable at a
 * glance even though they sit in the same column on every line; an
 * unrecognised category falls back to bright magenta. The level bracket uses
 * @p levelTone. Warning and Error also tint the message body, so the whole
 * line reads as one alert; other tones leave it in the default colour.
 *
 * @par Segment emphasis
 * @verbatim
 * [timestamp] [level] [category] [tid=threadId] message
 *    dim       tone     accent        dim       default (tinted on Warn/Error)
 * @endverbatim
 *
 * @par Category accent (SGR foreground code)
 * | Category  | SGR  | Colour         |
 * |-----------|------|----------------|
 * | `backend` | `95` | bright magenta |
 * | `vault`   | `93` | bright yellow  |
 * | `crypto`  | `92` | bright green   |
 * | `fill`    | `94` | bright blue    |
 * | `bridge`  | `33` | yellow (dark)  |
 * | `file`    | `36` | cyan           |
 * | `app`     | `97` | bright white   |
 * | `camera`  | `91` | bright red     |
 * | `qr`      | `35` | magenta (dark) |
 * | (other)   | `95` | bright magenta |
 *
 * @param os        Destination stream (typically `std::cerr`).
 * @param levelTone Colour for the `[level]` bracket and warn/error messages.
 * @param segs      Pre-parsed segments; fields are rendered verbatim.
 */
void writeLogLine(std::ostream& os, Tone levelTone, const LogSegments& segs);

}  // namespace console
}  // namespace seal
