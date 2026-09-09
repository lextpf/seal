#pragma once

#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace seal::csv
{

/**
 * @struct Credential
 * @brief One imported credential in pageable memory.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CLI
 *
 * Cleanse each row and the source CSV buffer as soon as encryption finishes. Ordinary string
 * destruction does not wipe these fields.
 */
struct Credential
{
    std::string platform;  ///< Display name (CSV `name`, else URL host).
    std::string username;  ///< Username (may be empty).
    std::string password;  ///< Password (never empty after parsing).
};

/**
 * @struct Stats
 * @brief Cumulative parse outcomes; each data row increments one counter.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CLI
 *
 * ParseChromeCsv never resets these counters. Use a fresh instance for each file's totals.
 */
struct Stats
{
    size_t imported = 0;           ///< Rows converted to credentials.
    size_t skippedNoPlatform = 0;  ///< Rows lacking both name and a usable URL host.
    size_t skippedNoPassword = 0;  ///< Rows with an empty password.
    size_t badRows = 0;            ///< Structurally invalid rows (column count).
};

/**
 * @fn bool LooksLikeChromeCsv(std::string_view firstLine)
 * @brief Choose the CSV import format with a substring sniff.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CLI
 *
 * Strips a UTF-8 BOM, cuts at CR and lowercases the line. ParseChromeCsv validates exact column
 * names later; `username` alone satisfies this sniff's `name` test.
 *
 * | Required substrings                          | Forbidden substring |
 * |----------------------------------------------|---------------------|
 * | `name`, `url`, `username`, `password`, comma | Colon               |
 */
bool LooksLikeChromeCsv(std::string_view firstLine);

/**
 * @fn bool ParseChromeCsv(std::string_view content, std::vector<Credential>& out, Stats& stats)
 * @brief Parse password CSV with RFC 4180 quoting and CRLF or LF endings.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CLI
 *
 * Allows a UTF-8 BOM, extra columns and embedded newlines. Blank rows are discarded; the first
 * remaining row is the header. Names match case-insensitively; the last duplicate wins.
 * Quoting is permissive: an unclosed quoted field consumes the rest of the input. Malformed
 * quoting is not checked separately; badRows counts data rows with missing required columns.
 * Parser scratch strings use pageable storage and are not explicitly wiped.
 *
 * | Required column | Destination                                  |
 * |-----------------|----------------------------------------------|
 * | name            | `platform`; empty uses url::extractHost(url) |
 * | url             | Normalized host fallback                     |
 * | username        | `username`                                   |
 * | password        | `password`                                   |
 *
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
 *
 * @param content Bytes pass through without UTF-8 validation.
 * @param out Appended, never cleared.
 * @param stats Incremented, never reset.
 * @return False for no rows or missing required columns; rejected data rows are not fatal.
 * @post Caller must cleanse both out and content.
 */
bool ParseChromeCsv(std::string_view content, std::vector<Credential>& out, Stats& stats);

/**
 * @fn std::string WriteCsvRow(std::initializer_list<std::string_view> fields)
 * @brief Serialize one row with minimal RFC 4180 quoting and a trailing CRLF.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CLI
 *
 * Commas, quotes, CR and LF require quoting; embedded quotes are doubled. Spaces are preserved;
 * no BOM is added. An empty field list produces only CRLF.
 *
 * @warning The returned pageable string is not cleansed. Wipe it after writing secrets and
 *          account for copies in stream buffers.
 */
std::string WriteCsvRow(std::initializer_list<std::string_view> fields);

}  // namespace seal::csv
