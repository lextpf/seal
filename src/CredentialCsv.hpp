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
 */
struct Credential
{
    std::string platform;  ///< Display name (CSV `name`, else URL host).
    std::string username;  ///< Username (may be empty).
    std::string password;  ///< Password (never empty after parsing).
};

/// @brief Row-level statistics from a CSV import parse.
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
 * | Condition | Rationale |
 * |---|---|
 * | contains `name` | Chrome header column |
 * | contains `url` | Chrome header column |
 * | contains `username` | Chrome header column |
 * | contains `password` | Chrome header column |
 * | contains `,` | it is comma-separated |
 * | does NOT contain `:` | rejects `plat:user:pass` and URL-bearing headers |
 *
 * This is only a fast pre-filter; @ref ParseChromeCsv still matches columns
 * exactly by header name.
 */
bool LooksLikeChromeCsv(std::string_view firstLine);

/**
 * @brief Parse a Chrome/Edge password CSV export (RFC 4180).
 * @ingroup CLI
 *
 * Handles quoted fields, doubled-quote escapes, embedded commas and
 * newlines, CRLF/LF endings, an optional UTF-8 BOM, and extra columns
 * (e.g. `note`), matching columns by header name case-insensitively.
 * Row-level problems are counted in @p stats, never fatal.
 *
 * @param content Whole CSV file content.
 * @param out     Parsed credentials (appended).
 * @param stats   Per-row outcome counters.
 * @return `false` when the header row is not a Chrome-style header.
 *
 * @par Column mapping (header matched exactly, case-insensitive)
 * | CSV column | Credential field |
 * |---|---|
 * | `name` | `platform` (falls back to the `url` host when empty) |
 * | `url` | host fallback for an empty `name` (`seal::url::extractHost`) |
 * | `username` | `username` |
 * | `password` | `password` |
 *
 * All four columns must be present or the parse returns `false`; any other
 * columns (e.g. `note`) are ignored.
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
 * @param fields Field values in column order.
 * @return Encoded row including the trailing CRLF.
 */
std::string WriteCsvRow(std::initializer_list<std::string_view> fields);

}  // namespace seal::csv
