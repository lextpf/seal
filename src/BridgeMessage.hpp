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
 *
 * @par Tag mapping (applied at insertion, see BrowserBridge.cpp mapTag)
 * | BridgeTag  | Verdict             | Stored in map? |
 * |------------|---------------------|----------------|
 * | `Password` | `Verdict::Password` | yes            |
 * | `Username` | `Verdict::Username` | yes            |
 * | `Email`    | `Verdict::Username` | yes            |
 * | `Text`     | none                | no             |
 * | `Other`    | none                | no             |
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
 * @brief Message discriminator for the two bridge report shapes.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * A missing `kind` field means @c Click (the legacy 6-field click report),
 * so every pre-existing message parses byte-identically. A `kind:"nav"`
 * report carries the navigated host plus the `secure`/`form` flags and NO
 * click coordinates; it drives zero-gesture auto-staging and never enters
 * the positional verdict map.
 */
enum class BridgeKind : std::uint8_t
{
    Click,  ///< Legacy click report: {v,x,y,tag,url_host,url_path_hash}.
    Nav,    ///< Navigation report: {v,kind,url_host,secure,form}.
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
    TooLarge,       ///< Payload exceeded the 4 KB cap, or a string field overran its buffer.
    Malformed,      ///< Generic syntactic error (bad punctuation, unterminated string, ...).
    DepthExceeded,  ///< Nested object/array depth exceeded the bounded-parse limit (4).
    UnknownKey,     ///< A key outside the kind-selected schema was present.
    MissingKey,     ///< One or more of the kind-selected required keys was absent.
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
    std::int32_t m_Version = 0;             ///< Schema version (currently always 1).
    BridgeKind m_Kind = BridgeKind::Click;  ///< Report shape; Click when `kind` is absent.
    std::int32_t m_X = 0;                ///< Screen-space click X (logical pixels per Qt). Click.
    std::int32_t m_Y = 0;                ///< Screen-space click Y (logical pixels per Qt). Click.
    BridgeTag m_Tag = BridgeTag::Other;  ///< Field classification reported by content.js. Click.
    std::string m_UrlHost;               ///< Validated [A-Za-z0-9.-] hostname, <= 253 bytes.
    std::string m_UrlPathHash;           ///< 64-hex SHA-256 of the URL path (Click; not used yet).
    bool m_Secure = false;               ///< Nav: page is an https/secure context.
    bool m_HasPasswordForm = false;      ///< Nav: a visible <input type=password> exists.
    bool m_HasUsernameField = false;  ///< Nav: a visible login identifier field exists (optional).
    std::string m_Visit;  ///< Nav: per-document page-load token, [A-Za-z0-9-] <= 64 (optional;
                          ///< empty when absent - staging then fails closed downstream).
};

/**
 * @brief Stable string token for a parser error category.
 * @param error Error enumeration value.
 * @return Static string suitable for a @c reason= field in logfmt output.
 * @ingroup FillController
 */
const char* bridgeParseErrorToken(BridgeParseError error);

/**
 * @brief Parse a single bridge message payload into its canonical form.
 *
 * Bounded recursive-descent parser. Accepts a top-level JSON object in one
 * of two kind-selected shapes: a @b click report (`kind` absent or
 * `"click"`) with exactly @c v, @c x, @c y, @c tag, @c url_host,
 * @c url_path_hash; or a @b nav report (`kind:"nav"`) with exactly @c v,
 * @c kind, @c url_host, @c secure, @c form plus the optional @c user and
 * @c visit keys. Keys legal in the other shape are rejected as unknown.
 * Rejects messages > 4 KB, nesting depth > 4, unknown keys, duplicate keys,
 * or any value outside the validated shape (see @c BrowserBridge
 * documentation for the schema).
 *
 * The originating browser is identified out-of-band: the bridge accepts
 * connections only from a signed @c seal-browser whose parent is a
 * known browser, and keys its in-memory map by the parent (browser) PID.
 * Including a @c browser_pid claim in the payload would only add an
 * attacker-controllable string that has to match the OS-derived PID, so
 * we drop the field entirely and rely on the parent-process resolution
 * happening server-side (see @c BrowserBridge::Impl::acceptorLoop).
 *
 * The parser allocates only @c std::string for the short bounded string
 * fields (@c url_host <= 253 bytes, @c url_path_hash = 64 bytes, and the
 * nav @c visit token <= 64 bytes). It never invokes the
 * @c seal::secure_string allocator or any DPAPI primitive.
 *
 * @par Message schema (keys by report shape)
 * A `reject` cell means the key is rejected as @c UnknownKey in that shape.
 * | Key             | Click    | Nav      |
 * |-----------------|----------|----------|
 * | `v`             | required | required |
 * | `kind`          | optional | required |
 * | `x`             | required | reject   |
 * | `y`             | required | reject   |
 * | `tag`           | required | reject   |
 * | `url_host`      | required | required |
 * | `url_path_hash` | required | reject   |
 * | `secure`        | reject   | required |
 * | `form`          | reject   | required |
 * | `user`          | reject   | optional |
 * | `visit`         | reject   | optional |
 *
 * @par Per-field validation
 * | Field                  | Accepted value                             |
 * |------------------------|--------------------------------------------|
 * | `v`                    | integer, must equal 1                      |
 * | `kind`                 | `"click"` or `"nav"` (absent -> click)     |
 * | `x`, `y`               | integer in [-50000, 50000]                 |
 * | `tag`                  | password / username / email / text / other |
 * | `url_host`             | 1..253 chars, `[A-Za-z0-9.-]`              |
 * | `url_path_hash`        | exactly 64 chars, `[0-9a-f]`               |
 * | `secure`, `form`, `user` | integer 0 or 1                           |
 * | `visit`                | 1..64 chars, `[A-Za-z0-9-]`                |
 * Whole payload <= 4096 bytes; object/array nesting depth <= 4.
 *
 * @param payload  Raw UTF-8 JSON bytes from the pipe.
 * @param out      Populated only when the call returns @c None.
 * @return @c BridgeParseError::None on success; otherwise the most-specific
 *         error category. Output buffer contents are unspecified on error.
 * @ingroup FillController
 */
BridgeParseError parseBridgeMessage(std::string_view payload, ParsedBridgeMessage* out);

}  // namespace seal
