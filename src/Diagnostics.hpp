#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace seal
{
/**
 * @namespace seal::diag
 * @brief Structured diagnostic field builders for logfmt-style telemetry.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Logging
 *
 * Produces canonical `key=value` tokens assembled into single-line log
 * messages (`event=foo result=ok duration_ms=12`). All values are
 * ASCII-sanitised, length-bounded, and free of whitespace so downstream
 * log parsers can tokenise the output unambiguously.
 *
 * ## Design goals
 *
 * - **Parseable:** values never contain unescaped spaces, so `joinFields`
 *   output round-trips through a simple whitespace split.
 * - **Safe by default:** paths and free-form strings are collapsed to
 *   metadata summaries (length, kind, extension) rather than echoed
 *   verbatim, keeping sensitive filesystem layout out of logs.
 * - **Zero-allocation hot paths:** integer/bool overloads avoid stream
 *   formatting where possible.
 *
 * Typical usage pairs these helpers with Qt's logging macros:
 * ```cpp
 * const auto op = seal::diag::nextOpId("vault_load");
 * const auto started = std::chrono::steady_clock::now();
 * // ... work ...
 * qCInfo(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
 *     {"event=vault.load.ok",
 *      seal::diag::kv("op", op),
 *      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
 * ```
 */
namespace diag
{

/**
 * @brief Generate a monotonically increasing operation identifier.
 * @ingroup Logging
 *
 * Produces a stable, log-safe token of the form `<scope>-<seq>` where
 * `seq` is a zero-padded 6-digit counter shared across all scopes. The
 * scope is lowercased and stripped to `[a-z0-9_-]`; if nothing remains
 * it falls back to `op`.
 *
 * @param scope Short label identifying the operation class (e.g. `"vault_load"`).
 * @return Unique identifier (e.g. `"vault_load-000042"`).
 *
 * @note The counter is process-global and wraps around at
 *       `2^64 - 1`; collisions are effectively impossible.
 */
std::string nextOpId(std::string_view scope);

/**
 * @brief ASCII-sanitise and length-bound a string for log output.
 * @ingroup Logging
 *
 * Non-printable and non-ASCII bytes are replaced with `?`. When the
 * input exceeds @p maxLen, the result is truncated and suffixed with
 * `...` (counting toward the limit). An empty result collapses to
 * the literal `"none"`.
 *
 * @param text   Input string (any encoding; treated as bytes).
 * @param maxLen Maximum length of the returned string (default 96).
 * @return Sanitised, length-capped string suitable for logfmt values.
 */
std::string sanitizeAscii(std::string_view text, size_t maxLen = 96);

/**
 * @brief Summarise a filesystem path without echoing its contents.
 * @ingroup Logging
 *
 * Returns four `key=value` fields joined by spaces:
 * `kind=<classification> path_len=<bytes> base_len=<bytes> ext=<token>`.
 * The `kind` is one of `empty`, `stdin` (for `-`), `dir_hint` (trailing
 * separator), `file_hint` (has an extension), or `opaque`.
 *
 * @param path Path to summarise. Not included verbatim in the output.
 * @return Space-separated fields describing the path metadata.
 *
 * @see pathSummary(std::string_view, std::string_view) for a prefixed variant.
 */
std::string pathSummary(std::string_view path);

/**
 * @brief Summarise a path with a caller-supplied key prefix.
 * @ingroup Logging
 *
 * Same structure as the single-argument overload, but field names are
 * prefixed so multiple paths can coexist on one log line without
 * collision (e.g. `src_kind=file_hint dst_kind=dir_hint ...`).
 *
 * @param path   Path to summarise.
 * @param prefix Key prefix; normalised to `[A-Za-z0-9_.\-/:+]`.
 * @return Space-separated `<prefix>_<field>=<value>` tokens.
 */
std::string pathSummary(std::string_view path, std::string_view prefix);

/**
 * @brief Map a human-readable error message to a stable reason token.
 * @ingroup Logging
 *
 * Pattern-matches case-insensitive substrings of @p message against a
 * table of canonical reasons -- for example `"wrong password"` ->
 * `wrong_password`, `"bad magic"` -> `corrupt_data`. Messages that
 * match nothing fall through to `exception`.
 *
 * @param message Free-form error text (typically from `std::exception::what()`).
 * @return One of: `wrong_password`, `auth_failed`, `timeout`,
 *         `open_failed`, `rename_failed`, `invalid_input`,
 *         `unsupported_format`, `corrupt_data`, `empty_input`,
 *         `exception`.
 */
std::string reasonFromMessage(std::string_view message);

/**
 * @brief Format a `key=value` token from a string value.
 * @ingroup Logging
 *
 * The value is ASCII-sanitised via sanitizeAscii() and further
 * restricted to `[A-Za-z0-9_.\-/:+]`; spaces become `_` and any other
 * disallowed byte becomes `?`. Empty values collapse to `none`.
 *
 * @param key   Field name (emitted verbatim -- caller must supply a safe key).
 * @param value Field value to normalise.
 * @return The token `key=normalised_value`.
 */
std::string kv(std::string_view key, std::string_view value);

/// @copydoc kv(std::string_view, std::string_view)
std::string kv(std::string_view key, const std::string& value);

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
 * @param key       Field name.
 * @param value     Field value.
 * @param precision Digits after the decimal point (default 2).
 * @return The token `key=<fixed-point value>`.
 */
std::string kv(std::string_view key, double value, int precision = 2);

/**
 * @brief Join pre-built fields into a single space-separated log line.
 * @ingroup Logging
 *
 * Empty fields are skipped silently, so conditionally-included tokens
 * can be passed unconditionally (e.g. from a ternary expression).
 *
 * @param fields Fields to join (typically the output of kv() calls).
 * @return All non-empty fields joined by single spaces.
 */
std::string joinFields(std::initializer_list<std::string> fields);

/**
 * @brief Milliseconds elapsed since @p start on @p Clock.
 * @ingroup Logging
 * @tparam Clock Any clock satisfying `TrivialClock` (e.g. `std::chrono::steady_clock`).
 * @param  start Time point captured at the start of the measured operation.
 * @return Elapsed duration in milliseconds.
 */
template <class Clock>
long long elapsedMs(const std::chrono::time_point<Clock>& start)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
}

}  // namespace diag
}  // namespace seal
