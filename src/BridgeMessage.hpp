#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace seal
{

/**
 * @enum BridgeTag
 * @brief Map extension field tags to stored verdicts.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
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
    Text,      ///< Plain text input or contenteditable; the bridge stores none of these.
    Other,     ///< Click landed on something that isn't a credential field.
};

/**
 * @enum BridgeKind
 * @brief Select the allowed and required keys for a report.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Absent kind means Click. Navigation reports never enter the positional map.
 * Keys belonging only to the other shape produce UnknownKey.
 *
 * @see parseBridgeMessage
 */
enum class BridgeKind : std::uint8_t
{
    /**
     * Click report: required {v,x,y,tag,url_host,secure,url_path_hash},
     * optional {kind,visit}.
     */
    Click,
    /**
     * Navigation report: required {v,kind,url_host,secure,form},
     * optional {user,visit}.
     */
    Nav,
};

/**
 * @enum BridgeParseError
 * @brief Stable parser errors used by log consumers.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * @warning Append new categories; never rename, reorder, or reuse existing ones.
 * @see bridgeParseErrorToken
 */
enum class BridgeParseError : std::uint8_t
{
    None,      ///< Parse succeeded; the output struct is populated.
    Empty,     ///< Payload was zero bytes after framing.
    TooLarge,  ///< Payload exceeded the 4 KB cap, or a string field overran its buffer.
    /**
     * Generic syntactic error: bad punctuation, unterminated string, a
     * non-object payload, or trailing bytes after the closing brace. Also
     * returned when the output pointer is null.
     */
    Malformed,
    /**
     * Depth budget (4) tripped. The schema is flat and every object or array
     * value is refused as @c BadType before the budget can matter, so this is
     * a residual guard that the current grammar cannot reach.
     */
    DepthExceeded,
    UnknownKey,    ///< A key outside the kind-selected schema was present.
    MissingKey,    ///< One or more of the kind-selected required keys was absent.
    DuplicateKey,  ///< A schema key appeared more than once.
    /**
     * An object or array value. No schema key accepts a nested value, so
     * every such value lands here. A scalar of the wrong type (a string for an
     * integer key, or a number or @c true for a string key) is reported as
     * `Malformed`.
     */
    BadType,
    /**
     * A value parsed but failed range, length, or character-class validation
     * (out-of-range coordinate, invalid host token, non-hex path hash, ...).
     */
    BadValue,
};

/**
 * @struct ParsedBridgeMessage
 * @brief Parser output with defaults for fields absent from the accepted shape.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 */
struct ParsedBridgeMessage
{
    std::int32_t m_Version = 0;             ///< Schema version (1 after a successful parse).
    BridgeKind m_Kind = BridgeKind::Click;  ///< Report shape; Click when `kind` is absent.
    std::int32_t m_X = 0;  ///< Raw screen X in WH_MOUSE_LL pixels; click reports only.
    std::int32_t m_Y = 0;  ///< Raw screen Y in WH_MOUSE_LL pixels; click reports only.
    BridgeTag m_Tag = BridgeTag::Other;  ///< Field classification reported by content.js. Click.
    std::string m_UrlHost;               ///< Host token with optional :port, <= 253 bytes.
    std::string m_UrlPathHash;           ///< 64-hex SHA-256 of the URL path. Click; no consumer.
    bool m_Secure = false;               ///< Click/Nav: page is an https/secure context.
    bool m_HasPasswordForm = false;      ///< Nav: a visible <input type=password> exists.
    bool m_HasUsernameField = false;  ///< Nav: a visible login identifier field exists (optional).
    std::string m_Visit;  ///< Optional document token; 1..64 ASCII letters, digits, or hyphens.
};

/**
 * @fn const char* bridgeParseErrorToken(BridgeParseError error)
 * @brief Stable logfmt reason token stored for the process lifetime.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return A static token; unknown enum values return `unknown`.
 */
const char* bridgeParseErrorToken(BridgeParseError error);

/**
 * @fn BridgeParseError parseBridgeMessage(std::string_view payload, ParsedBridgeMessage* out)
 * @brief Parse one bounded, flat bridge report.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Accepts printable ASCII strings with only backslash and quote escapes, and
 * signed decimal integers without leading zeros, fractions, or exponents.
 * Nested values produce BadType; trailing bytes produce Malformed.
 * Browser identity comes from the pipe peer and ancestry, never a payload PID.
 *
 * Strings use fixed stack buffers before allocating retained output fields.
 * A host port must occur once between non-empty parts and be decimal, at most 65535.
 * Host validation checks characters and the optional port, not DNS label structure.
 * It preserves case and does not establish a site binding. Callers must apply the
 * release policy after parsing. A rejected schema cell produces UnknownKey.
 *
 * | Key             | Click    | Nav      |
 * |-----------------|----------|----------|
 * | `v`             | required | required |
 * | `kind`          | optional | required |
 * | `x`             | required | reject   |
 * | `y`             | required | reject   |
 * | `tag`           | required | reject   |
 * | `url_host`      | required | required |
 * | `url_path_hash` | required | reject   |
 * | `secure`        | required | required |
 * | `form`          | reject   | required |
 * | `user`          | reject   | optional |
 * | `visit`         | optional | optional |
 *
 * | Field                    | Accepted value                                         |
 * |--------------------------|--------------------------------------------------------|
 * | `v`                      | integer, must equal 1                                  |
 * | `kind`                   | `"click"` or `"nav"` (absent -> click)                 |
 * | `x`, `y`                 | integer in [-50000, 50000]                             |
 * | `tag`                    | password / username / email / text / other             |
 * | `url_host`               | 1..253 chars, `[A-Za-z0-9.-]` plus at most one `:port` |
 * | `url_path_hash`          | exactly 64 chars, `[0-9a-f]`                           |
 * | `secure`, `form`, `user` | integer 0 or 1                                         |
 * | `visit`                  | 1..64 chars, `[A-Za-z0-9-]`                            |
 *
 * @param payload Empty yields Empty; more than 4096 bytes yields TooLarge.
 * @param out Null yields Malformed. Initialized after size checks; read only on
 *            success, since error output is unspecified.
 * @return None on success; otherwise the most specific error category.
 */
BridgeParseError parseBridgeMessage(std::string_view payload, ParsedBridgeMessage* out);

}  // namespace seal
