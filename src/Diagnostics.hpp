#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace seal
{
/**
 * @namespace seal::diag
 * @brief Structured diagnostic field builders for logfmt-style telemetry.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup Logging
 *
 * Builds canonical `key=value` tokens for single-line log messages
 * (`event=foo result=ok duration_ms=12`). Values are ASCII-sanitised,
 * length-bounded and whitespace-free, so a log parser can tokenise a line
 * by splitting on spaces.
 *
 * ## Design goals
 *
 * - **Parseable** - a value never contains an unescaped space, so
 *   joinFields() output round-trips through a whitespace split.
 * - **Safe by default for paths** - pathSummary() collapses a path to kind, length and
 *   extension and never echoes it. Every other value is echoed after normalisation
 *   (192-byte cap in kv(), 96 in errorFields()), so the caller decides what is safe to
 *   pass: fingerprint or summarise a hostname or a file name before you log it.
 * - **Cheap on the integer path** - integer kv() overloads use `std::to_string`,
 *   the bool overload a literal; only the `double` overload and nextOpId() build
 *   a `std::ostringstream`. Every builder allocates its returned string.
 *
 * Typical use with Qt's logging macros:
 * ```cpp
 * const auto op = seal::diag::nextOpId("vault_load");
 * const auto started = std::chrono::steady_clock::now();
 * // ... work ...
 * qCInfo(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
 *     {"event=vault.load.ok",
 *      seal::diag::kv("op", op),
 *      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
 * ```
 *
 * @par Canonical log line
 * @code
 * event=<dotted.scope.phase> result=<start|ok|fail|...> [reason=<token>]
 *     [sub_reason=<token>] [key=value ...]
 *
 * event=vault.load.ok   result=ok   op=vault_load-000042 duration_ms=12
 * event=vault.load.fail result=fail reason=wrong_password op=vault_load-000043
 * @endcode
 *
 * `event=` and `result=` are literal caller-written tokens; every dynamic value passes
 * through kv(), so the whole line survives a whitespace split. `start`, `ok` and `fail`
 * are the common outcomes, but the set is open: a subsystem adds its own terminal token,
 * for example `result=blocked` (a gate refused), `result=skip`, `result=partial` and
 * `result=warn`. A parser must treat `result=` as an open token set. `sub_reason=` is
 * optional and refines `reason=` where one gate has several distinct failure causes.
 *
 * @par Field builders at a glance
 * | Helper                 | Emits                                          |
 * |------------------------|------------------------------------------------|
 * | `nextOpId(scope)`      | `<scope>-<6-digit seq>` correlation id         |
 * | `kv(key, value)`       | one normalised `key=value` token               |
 * | `joinFields({...})`    | non-empty tokens joined by single spaces       |
 * | `pathSummary(path)`    | `kind= path_len= base_len= ext=` (no raw path) |
 * | `sanitizeAscii(text)`  | printable-ASCII, length-capped value           |
 * | `reasonFromMessage(m)` | stable `reason=` token from error text         |
 * | `errorFields(what)`    | the pair `reason=<token> detail=<text>`        |
 * | `elapsedMs(start)`     | milliseconds since `start`                     |
 *
 * @par Threading
 * Every builder is a pure function of its arguments and is safe on any thread.
 * nextOpId() is the one exception to purity: it advances a process-global counter.
 */
namespace diag
{

/**
 * @brief Generate a monotonically increasing operation identifier.
 * @ingroup Logging
 *
 * Produces a log-safe token `<scope>-<seq>`, where `seq` is a zero-padded
 * 6-digit counter shared by every scope. The scope is lowercased and
 * stripped to `[a-z0-9_-]`; an empty result falls back to `op`.
 *
 * @param scope Short label for the operation class (e.g. `"vault_load"`).
 * @return Unique identifier (e.g. `"vault_load-000042"`).
 *
 * @note The counter is process-global, starts at 1, and increments with
 *       relaxed atomics: ids are unique but not ordered between threads.
 *       Six digits is a minimum width; past 999999 the field grows.
 */
std::string nextOpId(std::string_view scope);

/**
 * @brief ASCII-sanitise and length-bound a string for log output.
 * @ingroup Logging
 *
 * Bytes outside printable ASCII (32..126) become `?`, so length is
 * preserved until the cap applies. An input longer than @p maxLen is
 * truncated to exactly @p maxLen bytes, the last three replaced by `...`.
 * Spaces survive here; only kv() turns them into `_`.
 *
 * @param text   Input string, treated as bytes whatever its encoding.
 * @param maxLen Maximum length of the returned string.
 * @return Sanitised, capped string. Empty @p text, or @p maxLen of 0,
 *         returns the literal `none`.
 *
 * @note With @p maxLen of 1 or 2 the ellipsis does not fit, so an over-long
 *       input is truncated without a `...` marker.
 */
std::string sanitizeAscii(std::string_view text, size_t maxLen = 96);

/**
 * @brief Summarise a filesystem path without echoing its contents.
 * @ingroup Logging
 *
 * Returns four space-joined fields:
 * `kind=<classification> path_len=<bytes> base_len=<bytes> ext=<token>`.
 * `path_len` counts the whole path, `base_len` its final component. `ext`
 * keeps its leading dot and is capped at 16 bytes; it reads `none` without
 * an extension and `unknown` when the path cannot be parsed.
 *
 * @par kind classification (checked top-to-bottom, first match wins)
 * | `kind`      | Condition                       |
 * |-------------|---------------------------------|
 * | `empty`     | path is empty                   |
 * | `stdin`     | path is `-`                     |
 * | `dir_hint`  | last char is `\` or `/`         |
 * | `file_hint` | `ext` is not `none`             |
 * | `opaque`    | none of the above               |
 *
 * @param path Path to summarise. It never appears verbatim in the output.
 * @return Space-separated fields describing the path metadata.
 *
 * @see pathSummary(std::string_view, std::string_view) for a prefixed variant.
 */
std::string pathSummary(std::string_view path);

/**
 * @brief Summarise a path with a caller-supplied key prefix.
 * @ingroup Logging
 *
 * Same four fields as the single-argument overload, each key prefixed, so two
 * paths share one log line without colliding (e.g. `src_kind=file_hint dst_kind=dir_hint ...`).
 *
 * @param path   Path to summarise. It never appears verbatim in the output.
 * @param prefix Normalised like a kv() value: spaces become `_`, bytes outside
 *               `[A-Za-z0-9_.\-/:+]` become `?`, and an empty prefix becomes
 *               the literal `none`.
 * @return The four `<prefix>_*` tokens joined by single spaces.
 */
std::string pathSummary(std::string_view path, std::string_view prefix);

/**
 * @brief Map a human-readable error message to a stable reason token.
 * @ingroup Logging
 *
 * Matches case-insensitive substrings of @p message against a table of
 * canonical reasons: `"wrong password"` -> `wrong_password`, `"bad magic"`
 * -> `corrupt_data`. A message that matches nothing yields `exception`.
 * Bytes above 127 are dropped before matching, so a non-ASCII separator can
 * join two words into one.
 *
 * @par Substring -> reason (checked top-to-bottom, first hit wins)
 * | Matched substring (lowercased)                                | Reason token         |
 * |---------------------------------------------------------------|----------------------|
 * | `wrong password`                                              | `wrong_password`     |
 * | `authentication`, `auth failed`                               | `auth_failed`        |
 * | `timeout`                                                     | `timeout`            |
 * | `cannot open`, `failed to open`                               | `open_failed`        |
 * | `rename`                                                      | `rename_failed`      |
 * | `invalid`                                                     | `invalid_input`      |
 * | `unsupported`                                                 | `unsupported_format` |
 * | `truncated`, `corrupt`, `malformed`, `bad magic`              | `corrupt_data`       |
 * | `payload too short`                                           | `corrupt_data`       |
 * | `no data`, `empty`                                            | `empty_input`        |
 * | (no match)                                                    | `exception`          |
 *
 * @param message Free-form error text, typically `std::exception::what()`.
 * @return One of the reason tokens in the table above.
 */
std::string reasonFromMessage(std::string_view message);

/**
 * @brief Build the standard `reason=<token> detail=<text>` field pair for an
 *        exception message.
 * @ingroup Logging
 *
 * Combines reasonFromMessage() and sanitizeAscii() into the two tokens every
 * `result=fail` catch block appends. They come back pre-joined, so the pair drops
 * into a joinFields() list as one element and expands to two fields on output.
 *
 * @param what Free-form error text, typically `std::exception::what()`.
 * @return `reason=<stable> detail=<sanitised>`, one space between them. The
 *         detail is capped at the sanitizeAscii() default of 96 bytes and then
 *         kv()-normalised, so its spaces become `_`.
 */
std::string errorFields(std::string_view what);

/**
 * @brief Format a `key=value` token from a string value.
 * @ingroup Logging
 *
 * The value is ASCII-sanitised via sanitizeAscii() with a 192-byte cap, then
 * restricted to `[A-Za-z0-9_.\-/:+]`: spaces become `_`, any other disallowed
 * byte becomes `?`, and an empty value collapses to `none`.
 *
 * @param key   Field name, emitted verbatim. The caller supplies a safe key.
 * @param value Field value to normalise. Past 192 bytes it is truncated with a
 *              trailing `...`.
 * @return The token `key=normalised_value`.
 */
std::string kv(std::string_view key, std::string_view value);

/// @copydoc kv(std::string_view, std::string_view)
std::string kv(std::string_view key, const std::string& value);

/**
 * @brief Format a `key=value` token from a C string.
 * @ingroup Logging
 *
 * Required: without it a `const char*` or string-literal value binds to the
 * `bool` overload through pointer-to-bool conversion and silently logs `true`.
 * A null pointer normalises to `none`.
 */
std::string kv(std::string_view key, const char* value);

/**
 * @brief Format a boolean `key=value` token as `key=true` or `key=false`.
 * @ingroup Logging
 */
std::string kv(std::string_view key, bool value);

/**
 * @brief Format a signed integer `key=value` token.
 * @ingroup Logging
 */
std::string kv(std::string_view key, int value);

/**
 * @brief Format an unsigned integer `key=value` token.
 * @ingroup Logging
 */
std::string kv(std::string_view key, unsigned int value);

/**
 * @brief Format a 64-bit signed `key=value` token.
 * @ingroup Logging
 */
std::string kv(std::string_view key, long long value);

/**
 * @brief Format a 64-bit unsigned `key=value` token.
 * @ingroup Logging
 */
std::string kv(std::string_view key, unsigned long long value);

/**
 * @brief Format a floating-point `key=value` token with fixed precision.
 * @ingroup Logging
 * @param key       Field name, emitted verbatim.
 * @param value     Value rendered with `std::fixed`.
 * @param precision Digits after the decimal point (default 2).
 * @return The token `key=<fixed-point value>`.
 */
std::string kv(std::string_view key, double value, int precision = 2);

/**
 * @brief Join pre-built fields into a single space-separated log line.
 * @ingroup Logging
 *
 * Empty fields are skipped, so a conditional token can be passed
 * unconditionally (e.g. from a ternary expression).
 *
 * @param fields Fields to join, typically the output of kv() calls.
 * @return All non-empty fields joined by single spaces.
 */
std::string joinFields(std::initializer_list<std::string> fields);

/**
 * @brief Milliseconds elapsed since @p start on @p Clock.
 * @ingroup Logging
 * @tparam Clock Any clock satisfying `TrivialClock` (e.g. `std::chrono::steady_clock`).
 * @param  start Captured at the start of the measured operation.
 * @return Elapsed whole milliseconds, truncated toward zero. Use a monotonic
 *         clock: on a wall clock a backward time step yields a negative value.
 */
template <class Clock>
long long elapsedMs(const std::chrono::time_point<Clock>& start)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
}

}  // namespace diag
}  // namespace seal
