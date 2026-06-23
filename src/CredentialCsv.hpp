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
 * @param firstLine First line of the input (UTF-8 BOM tolerated).
 * @return `true` when the line is a Chrome-style CSV header containing the
 *         `name`, `url`, `username`, and `password` columns.
 */
bool LooksLikeChromeCsv(std::string_view firstLine);

/**
 * @brief Parse a Chrome/Edge password CSV export (RFC 4180).
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
 */
bool ParseChromeCsv(std::string_view content, std::vector<Credential>& out, Stats& stats);

/**
 * @brief Serialize one CSV row with minimal RFC 4180 quoting and CRLF.
 * @param fields Field values in column order.
 * @return Encoded row including the trailing CRLF.
 */
std::string WriteCsvRow(std::initializer_list<std::string_view> fields);

}  // namespace seal::csv
