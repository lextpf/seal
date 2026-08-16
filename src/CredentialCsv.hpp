#pragma once

#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace seal::csv
{

/**
 * @struct Credential
 * @brief One credential row parsed from a password-manager CSV export.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 * The three fields are ordinary pageable memory, not locked memory: bulk
 * import is a short-lived path, and locked memory is reserved for long-lived
 * secrets. The caller must cleanse every parsed Credential, and the CSV
 * buffer it was parsed from, as soon as the values are encrypted.
 */
struct Credential
{
    std::string platform;  ///< Display name (CSV `name`, else URL host).
    std::string username;  ///< Username (may be empty).
    std::string password;  ///< Password (never empty after parsing).
};

/**
 * @struct Stats
 * @brief Row-level statistics from a CSV import parse.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 * Every data row lands in one counter, so the four fields add up to the number
 * of rows after the header. @ref ParseChromeCsv adds to the counters and never
 * clears them; reuse one instance only to total several files.
 */
struct Stats
{
    size_t imported = 0;           ///< Rows converted to credentials.
    size_t skippedNoPlatform = 0;  ///< Rows lacking both name and a usable URL host.
    size_t skippedNoPassword = 0;  ///< Rows with an empty password.
    size_t badRows = 0;            ///< Structurally invalid rows (column count).
};

/**
 * @brief Cheap header sniff for the Chrome/Edge password-export format.
 * @ingroup CLI
 * @param firstLine First line of the input (UTF-8 BOM tolerated).
 * @return `true` when the line is a Chrome-style CSV header containing the
 *         `name`, `url`, `username`, and `password` columns.
 *
 * @par Sniff conditions (all required)
 * The line is lowercased after stripping a UTF-8 BOM and cutting at the first
 * `\r`; then every substring test below must hold:
 * | Condition            | Rationale                                        |
 * |----------------------|--------------------------------------------------|
 * | contains `name`      | Chrome header column                             |
 * | contains `url`       | Chrome header column                             |
 * | contains `username`  | Chrome header column                             |
 * | contains `password`  | Chrome header column                             |
 * | contains `,`         | it is comma-separated                            |
 * | must not contain `:` | rejects `plat:user:pass` and URL-bearing headers |
 *
 * These are substring tests on the whole line, not column matches, so
 * `username` alone already satisfies the `name` condition. The sniff only
 * chooses between the `chrome` and `seal` import formats; @ref ParseChromeCsv
 * matches columns exactly by header name and decides whether the file parses.
 */
bool LooksLikeChromeCsv(std::string_view firstLine);

/**
 * @brief Parse a Chrome/Edge password CSV export (RFC 4180).
 * @ingroup CLI
 *
 * Handles quoted fields, doubled-quote escapes, embedded commas and newlines,
 * CRLF/LF endings, an optional UTF-8 BOM, and extra columns such as `note`.
 * Columns are matched by header name, case-insensitively. A row-level problem
 * is counted in @p stats and is never fatal.
 *
 * Blank lines are dropped before anything else, so the header is the first
 * non-blank row wherever it sits. A duplicated header name resolves to its
 * last occurrence.
 *
 * @param content Whole CSV file content. Not required to be valid UTF-8;
 *                bytes are copied through unchanged.
 * @param out     Parsed credentials, appended. Existing elements are kept.
 * @param stats   Per-row outcome counters. Added to, never reset, so pass a
 *                fresh instance for a per-file total.
 * @return `false` when @p content yields no rows at all, or when the header
 *         row does not carry all four required columns. `true` otherwise,
 *         even when every data row was rejected.
 * @post Neither @p out nor the buffer behind @p content is cleansed. The
 *       caller wipes both.
 *
 * @par Column mapping (header matched exactly, case-insensitive)
 * | CSV column      | Credential field                                             |
 * |-----------------|--------------------------------------------------------------|
 * | `name`          | `platform` (falls back to the `url` host when empty)         |
 * | `url`           | host fallback for an empty `name` (`seal::url::extractHost`) |
 * | `username`      | `username`                                                   |
 * | `password`      | `password`                                                   |
 *
 * All four columns must be present or the parse returns `false`. The host
 * fallback is normalised by `seal::url::extractHost`: lower-cased, with
 * scheme, path, credentials, port and a leading `www.` removed. A `url` value
 * with no usable host yields an empty platform, and the row is skipped.
 *
 * @par Row outcome (per data row; counters land in @p stats)
 * @verbatim
 * data row (rows after the header)
 *   |
 *   +-- field count <= max needed column index
 *   |        -> ++badRows                 (structurally short row)
 *   |
 *   +-- platform empty (name empty AND url has no host)
 *   |        -> ++skippedNoPlatform
 *   |
 *   +-- password empty
 *   |        -> ++skippedNoPassword
 *   |
 *   +-- otherwise
 *            -> ++imported, append to out
 * @endverbatim
 */
bool ParseChromeCsv(std::string_view content, std::vector<Credential>& out, Stats& stats);

/**
 * @brief Serialize one CSV row with minimal RFC 4180 quoting and CRLF.
 * @ingroup CLI
 *
 * A field is wrapped in double quotes only when it contains `,`, `"`, CR or
 * LF; an inner `"` is then doubled. Every other field is written verbatim, so
 * leading and trailing spaces survive and no BOM is added. This is the inverse
 * of the tokenizer @ref ParseChromeCsv uses.
 *
 * @param fields Field values in column order. An empty list yields a row that
 *               is only the CRLF.
 * @return Encoded row including the trailing CRLF.
 * @warning The returned string is ordinary pageable heap memory and holds
 *          every field verbatim; the function cleanses nothing. When a field
 *          is a secret, the caller must cleanse the returned row after
 *          writing it, and must account for the copy the output stream keeps
 *          in its own buffer. The CLI `export --format csv` path is the caller
 *          this duty falls on.
 */
std::string WriteCsvRow(std::initializer_list<std::string_view> fields);

}  // namespace seal::csv
