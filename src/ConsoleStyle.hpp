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
 * back to uncoloured plain text - callers never need to branch on
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
 *
 * @par Palette (SGR foreground code)
 * | Tone      | SGR  | Colour             |
 * |-----------|------|--------------------|
 * | `Plain`   | none | (uncoloured)       |
 * | `Debug`   | `90` | bright black / grey |
 * | `Info`    | `36` | cyan               |
 * | `Step`    | `94` | bright blue        |
 * | `Success` | `92` | bright green       |
 * | `Warning` | `93` | bright yellow      |
 * | `Error`   | `91` | bright red         |
 * | `Summary` | `95` | bright magenta     |
 * | `Banner`  | `96` | bright cyan        |
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
 * @brief Interactive y/N gate for destructive or plaintext-emitting actions.
 * @ingroup CLI
 *
 * Prints `<prompt> [y/N]: ` to @p err and reads one line from @p in.
 * Only `y`/`Y` confirms; everything else (including EOF / closed stdin)
 * refuses. @p force short-circuits to `true` without prompting.
 *
 * @param force  Skip the prompt (e.g. `--force`).
 * @param in     Input stream (stdin in production; stringstream in tests).
 * @param err    Stream for the prompt (stderr keeps stdout pipe-clean).
 * @param prompt Question to display, without the trailing `[y/N]`.
 * @return `true` when the action is confirmed.
 */
bool ConfirmDestructive(bool force, std::istream& in, std::ostream& err, const char* prompt);

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
    std::string_view level;      ///< Severity token (e.g. `DBG`, `WRN`, `FTL`).
    std::string_view category;   ///< Qt logging category, bare/no prefix (e.g. `vault`).
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
 * with a per-category colour (so e.g. `[vault]` and `[bridge]` are
 * visually distinguishable at a glance even though they sit in the
 * same position on every line); the level bracket uses @p levelTone.
 * For Warning and Error tones the message body is also tinted so the
 * full line reads as a single alert; other tones leave the message in
 * the default colour. Unrecognised categories fall back to bright
 * magenta.
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
