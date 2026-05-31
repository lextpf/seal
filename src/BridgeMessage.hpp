#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace seal
{

/**
 * @brief Tag classifier for a bridge message field.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Mirrors the small enumeration the WebExtension content script emits.
 * Mapping to seal::Verdict happens at insertion time on the bridge side:
 * @c BridgeTag::Password  -> Verdict::Password,
 * @c BridgeTag::Username  -> Verdict::Username,
 * @c BridgeTag::Email     -> Verdict::Username,
 * @c BridgeTag::Text      -> ignored (no insertion),
 * @c BridgeTag::Other     -> ignored.
 */
enum class BridgeTag : std::uint8_t
{
    Password,  ///< Direct `<input type="password">` hit; high-confidence password.
    Username,  ///< Login / username field detected by name/id/autocomplete heuristics.
    Email,     ///< `<input type="email">`; mapped to Verdict::Username on insertion.
    Text,      ///< Plain text input or contenteditable; bridge does NOT store these.
    Other,     ///< Click landed on something that isn't a credential field.
};

/**
 * @brief Parser error categories surfaced to telemetry.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Tokens are stable so log parsers can pivot on @c reason= values.
 *
 * @note These tokens are a TELEMETRY CONTRACT. Renaming, reordering,
 *       or repurposing any of them breaks downstream log parsers that
 *       pivot on the exact `reason=` value. Add new categories at the
 *       end; never recycle an existing name.
 */
enum class BridgeParseError : std::uint8_t
{
    None,           ///< Parse succeeded; the output struct is populated.
    Empty,          ///< Payload was zero bytes after framing.
    TooLarge,       ///< Payload exceeded the 4 KB hard cap.
    Malformed,      ///< Generic syntactic error (bad punctuation, unterminated string, ...).
    DepthExceeded,  ///< Nested object/array depth exceeded the bounded-parse limit (4).
    UnknownKey,     ///< A key not in the six-field schema was present.
    MissingKey,     ///< One or more of the six required schema keys was absent.
    DuplicateKey,   ///< A schema key appeared more than once.
    BadType,        ///< A value's JSON type didn't match the schema (e.g. object where int).
    BadValue,       ///< A value parsed but failed range / format validation (e.g. neg PID).
};

/**
 * @brief A parsed bridge message in its canonical raw form.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Plain C++ (no Qt, no @c seal::secure_string), so the parser is testable
 * without USE_QT_UI. The bridge converts this to a BridgeEntry (which
 * holds a QString host) at insertion time.
 */
struct ParsedBridgeMessage
{
    std::int32_t m_Version = 0;          ///< Schema version (currently always 1).
    std::int32_t m_X = 0;                ///< Screen-space click X (logical pixels per Qt).
    std::int32_t m_Y = 0;                ///< Screen-space click Y (logical pixels per Qt).
    BridgeTag m_Tag = BridgeTag::Other;  ///< Field classification reported by content.js.
    std::string m_UrlHost;               ///< Validated [A-Za-z0-9.-_] hostname, <= 253 bytes.
    std::string m_UrlPathHash;           ///< 64-hex SHA-256 of the URL path (not used yet).
};

/**
 * @brief Stable string token for a parser error category.
 * @param error Error enumeration value.
 * @return Static string suitable for a @c reason= field in logfmt output.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 */
const char* bridgeParseErrorToken(BridgeParseError error);

/**
 * @brief Parse a single bridge message payload into its canonical form.
 * @author Alex (https://github.com/lextpf)
 *
 * Bounded recursive-descent parser. Accepts only a top-level JSON object
 * with exactly six keys (@c v, @c x, @c y, @c tag, @c url_host,
 * @c url_path_hash). Rejects messages > 4 KB, nesting depth > 4, unknown
 * keys, duplicate keys, or any value outside the validated shape (see
 * @c BrowserBridge documentation for the schema).
 *
 * The originating browser is identified out-of-band: the bridge accepts
 * connections only from a signed @c seal-browser whose parent is a
 * known browser, and keys its in-memory map by the parent (browser) PID.
 * Including a @c browser_pid claim in the payload would only add an
 * attacker-controllable string that has to match the OS-derived PID, so
 * we drop the field entirely and rely on the parent-process resolution
 * happening server-side (see @c BrowserBridge::Impl::acceptLoop).
 *
 * The parser allocates only @c std::string for the two short string
 * fields (host <= 253 bytes, hash = 64 bytes). It never invokes the
 * @c seal::secure_string allocator or any DPAPI primitive.
 *
 * @param payload  Raw UTF-8 JSON bytes from the pipe.
 * @param out      Populated only when the call returns @c None.
 * @return @c BridgeParseError::None on success; otherwise the most-specific
 *         error category. Output buffer contents are unspecified on error.
 * @ingroup FillController
 */
BridgeParseError parseBridgeMessage(std::string_view payload, ParsedBridgeMessage* out);

}  // namespace seal
