#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace seal
{
/**
 * @namespace seal::diag
 * @brief bounded field builders for logfmt diagnostics.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Logging
 *
 * dynamic values must pass through kv(); callers supply safe literal keys and tokens.
 * pathSummary() omits raw paths. other builders echo normalised values, so callers must
 * fingerprint or summarise sensitive input before logging it.
 *
 * `result` is an open token set. `sub_reason` optionally refines `reason`.
 * builders allocate their results and are thread-safe. nextOpId() advances a shared counter.
 *
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
 * @code
 * event=<dotted.scope.phase> result=<start|ok|fail|...> [reason=<token>]
 *     [sub_reason=<token>] [key=value ...]
 *
 * event=vault.load.ok   result=ok   op=vault_load-000042 duration_ms=12
 * event=vault.load.fail result=fail reason=wrong_password op=vault_load-000043
 * @endcode
 */
namespace diag
{

/**
 * @brief allocate a process-wide operation identifier.
 * @ingroup Logging
 *
 * format is `<scope>-<seq>`; the counter starts at 1 with a minimum width of six digits.
 * scope is lowercased and restricted to `[a-z0-9_-]`; an empty result becomes `op`.
 * relaxed atomics provide unique IDs without ordering calls between threads.
 */
std::string nextOpId(std::string_view scope);

/**
 * @brief replace non-printable bytes and cap log text.
 * @ingroup Logging
 *
 * bytes outside ASCII 32..126 become `?`; spaces remain unchanged.
 * @param maxLen byte cap; truncated output ends in `...` only when the cap is at least 3.
 * @return `none` for empty input or a zero cap, otherwise the sanitised text.
 */
std::string sanitizeAscii(std::string_view text, size_t maxLen = 96);

/**
 * @brief describe path metadata without emitting the raw path.
 * @ingroup Logging
 *
 * output fields are `kind`, `path_len`, `base_len` and `ext`. lengths count bytes.
 * the extension includes its dot and is capped at 16 bytes; absent is `none`, parse failure
 * is `unknown`. the first matching classification wins.
 *
 * | kind        | condition                     |
 * |-------------|-------------------------------|
 * | `empty`     | empty input                   |
 * | `stdin`     | `-`                           |
 * | `dir_hint`  | final character is `/` or `\` |
 * | `file_hint` | extension is not `none`       |
 * | `opaque`    | otherwise                     |
 */
std::string pathSummary(std::string_view path);

/**
 * @brief prefix path-summary keys so multiple paths can share a log line.
 * @ingroup Logging
 *
 * @param prefix normalised as a kv() value; empty becomes `none`.
 * @return the four `<prefix>_*` fields joined by spaces.
 * @see pathSummary(std::string_view)
 */
std::string pathSummary(std::string_view path, std::string_view prefix);

/**
 * @brief classify error text with stable reason tokens.
 * @ingroup Logging
 *
 * match case-insensitively after dropping bytes above 127. the first match wins.
 *
 * | substring                           | token                |
 * |-------------------------------------|----------------------|
 * | `wrong password`                    | `wrong_password`     |
 * | `authentication`, `auth failed`     | `auth_failed`        |
 * | `timeout`                           | `timeout`            |
 * | `cannot open`, `failed to open`     | `open_failed`        |
 * | `rename`                            | `rename_failed`      |
 * | `invalid`                           | `invalid_input`      |
 * | `unsupported`                       | `unsupported_format` |
 * | `truncated`, `corrupt`, `malformed` | `corrupt_data`       |
 * | `bad magic`, `payload too short`    | `corrupt_data`       |
 * | `no data`, `empty`                  | `empty_input`        |
 * | no match                            | `exception`          |
 */
std::string reasonFromMessage(std::string_view message);

/**
 * @brief format an exception as reason and detail fields.
 * @ingroup Logging
 *
 * @return `reason=<token> detail=<text>`; detail uses a 96-byte cap and kv() normalisation.
 */
std::string errorFields(std::string_view what);

/**
 * @brief normalise a string value for one logfmt field.
 * @ingroup Logging
 *
 * values are capped at 192 bytes and restricted to `[A-Za-z0-9_.\-/:+]`.
 * spaces become `_`, other disallowed bytes become `?`, and empty values become `none`.
 * @param key emitted verbatim; the caller must supply a safe key.
 */
std::string kv(std::string_view key, std::string_view value);

/// @copydoc kv(std::string_view, std::string_view)
std::string kv(std::string_view key, const std::string& value);

/**
 * @brief normalise a nullable C string for one logfmt field.
 * @ingroup Logging
 *
 * this overload prevents string literals from selecting the bool overload.
 * @param value null becomes `none`.
 * @see kv(std::string_view, std::string_view)
 */
std::string kv(std::string_view key, const char* value);

/**
 * @brief emit a boolean field as true or false.
 * @ingroup Logging
 */
std::string kv(std::string_view key, bool value);

/**
 * @brief emit a decimal integer field.
 * @ingroup Logging
 */
std::string kv(std::string_view key, int value);

/**
 * @brief emit a decimal integer field.
 * @ingroup Logging
 */
std::string kv(std::string_view key, unsigned int value);

/**
 * @brief emit a decimal integer field.
 * @ingroup Logging
 */
std::string kv(std::string_view key, long long value);

/**
 * @brief emit a decimal integer field.
 * @ingroup Logging
 */
std::string kv(std::string_view key, unsigned long long value);

/**
 * @brief emit a fixed-point numeric field.
 * @ingroup Logging
 *
 * @param key emitted verbatim; the caller must supply a safe key.
 * @param precision digits after the decimal point.
 */
std::string kv(std::string_view key, double value, int precision = 2);

/**
 * @brief join non-empty fields with one space between them.
 * @ingroup Logging
 */
std::string joinFields(std::initializer_list<std::string> fields);

/**
 * @brief measure elapsed whole milliseconds.
 * @ingroup Logging
 *
 * fractional milliseconds are truncated toward zero. use a monotonic clock to avoid
 * negative elapsed values after wall-clock adjustments.
 */
template <class Clock>
long long elapsedMs(const std::chrono::time_point<Clock>& start)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
}

}  // namespace diag
}  // namespace seal
