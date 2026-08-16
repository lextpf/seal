#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace seal
{

/**
 * @enum BridgeTag
 * @brief Tag classifier for a bridge message field.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup FillController
 *
 * Mirrors the enumeration the extension's content script emits. The bridge maps
 * a tag to a seal::Verdict at insertion time; `text` and `other` insert nothing,
 * so neutral clicks cannot fill the map.
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
    Text,      ///< Plain text input or contenteditable; the bridge stores none of these.
    Other,     ///< Click landed on something that isn't a credential field.
};

/**
 * @enum BridgeKind
 * @brief Message discriminator for the two bridge report shapes.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup FillController
 *
 * A missing `kind` field means @c Click. A click report carries the click
 * coordinates, field tag, host, path hash and `secure` bit, so http and https
 * stay distinguishable downstream. A `kind:"nav"` report carries the navigated
 * host plus the `secure`/`form` flags and no click coordinates; it drives
 * zero-gesture auto-staging and never enters the positional verdict map.
 *
 * The shape selects both the required and the allowed key set. A key legal only
 * in the other shape is rejected as @c BridgeParseError::UnknownKey, so no
 * shape-specific key crosses shapes. @ref parseBridgeMessage holds the key table.
 */
enum class BridgeKind : std::uint8_t
{
    /// Click report: required {v,x,y,tag,url_host,secure,url_path_hash},
    /// optional {kind,visit}.
    Click,
    /// Navigation report: required {v,kind,url_host,secure,form},
    /// optional {user,visit}.
    Nav,
};

/**
 * @enum BridgeParseError
 * @brief Parser error categories surfaced to telemetry.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup FillController
 *
 * @ref bridgeParseErrorToken maps each value to the token that reaches the log.
 *
 * @warning These tokens are a telemetry contract. Renaming, reordering or
 *          repurposing one breaks downstream log parsers that pivot on the
 *          exact `reason=` value. Add new categories at the end and never
 *          recycle an existing name.
 */
enum class BridgeParseError : std::uint8_t
{
    None,      ///< Parse succeeded; the output struct is populated.
    Empty,     ///< Payload was zero bytes after framing.
    TooLarge,  ///< Payload exceeded the 4 KB cap, or a string field overran its buffer.
    /// Generic syntactic error: bad punctuation, unterminated string, a
    /// non-object payload, or trailing bytes after the closing brace. Also
    /// returned when the output pointer is null.
    Malformed,
    /// Depth budget (4) tripped. The schema is flat and every object or array
    /// value is refused as @c BadType before the budget can matter, so this is
    /// a residual guard that the current grammar cannot reach.
    DepthExceeded,
    UnknownKey,    ///< A key outside the kind-selected schema was present.
    MissingKey,    ///< One or more of the kind-selected required keys was absent.
    DuplicateKey,  ///< A schema key appeared more than once.
    /// An object or array value. No schema key accepts a nested value, so
    /// every such value lands here. A scalar of the wrong type (a string for an
    /// integer key, or a number or @c true for a string key) is reported as
    /// @c Malformed.
    BadType,
    /// A value parsed but failed range, length, or character-class validation
    /// (out-of-range coordinate, bad host label, non-hex path hash, ...).
    BadValue,
};

/**
 * @struct ParsedBridgeMessage
 * @brief A parsed bridge message in its canonical raw form.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup FillController
 *
 * Plain C++ with no Qt and no @c seal::secure_string, so the parser is testable
 * without USE_QT_UI. The bridge converts this to a BridgeEntry, which holds a
 * QString host, at insertion time.
 *
 * @ref parseBridgeMessage value-initialises the whole struct before it parses,
 * so a field the accepted shape does not carry keeps the default listed below
 * rather than a value from an earlier call.
 */
struct ParsedBridgeMessage
{
    std::int32_t m_Version = 0;             ///< Schema version (currently always 1).
    BridgeKind m_Kind = BridgeKind::Click;  ///< Report shape; Click when `kind` is absent.
    std::int32_t m_X = 0;  ///< Click screen X, same space as the WH_MOUSE_LL hook. Click.
    std::int32_t m_Y = 0;  ///< Click screen Y, same space as the WH_MOUSE_LL hook. Click.
    BridgeTag m_Tag = BridgeTag::Other;  ///< Field classification reported by content.js. Click.
    std::string m_UrlHost;               ///< Validated hostname with optional :port, <= 253 bytes.
    std::string m_UrlPathHash;           ///< 64-hex SHA-256 of the URL path. Click; no consumer.
    bool m_Secure = false;               ///< Click/Nav: page is an https/secure context.
    bool m_HasPasswordForm = false;      ///< Nav: a visible <input type=password> exists.
    bool m_HasUsernameField = false;  ///< Nav: a visible login identifier field exists (optional).
    std::string m_Visit;  ///< Click/Nav: optional per-document page-load token, [A-Za-z0-9-]
                          ///< <= 64. Empty when absent: a nav then fails staging closed, and
                          ///< a click falls back to host-only binding.
};

/**
 * @brief Stable string token for a parser error category.
 * @param error Error enumeration value to map.
 * @return A static string suitable for a @c reason= field in logfmt output.
 * @ingroup FillController
 */
const char* bridgeParseErrorToken(BridgeParseError error);

/**
 * @brief Parse a single bridge message payload into its canonical form.
 *
 * Bounded and non-recursive. The top-level object must match one of the two
 * kind-selected shapes tabulated below: click (`kind` absent or `"click"`) or
 * nav (`kind:"nav"`). A key legal only in the other shape is @c UnknownKey.
 *
 * @par Grammar
 * Narrower than JSON on purpose. It accepts only objects, printable-ASCII
 * strings (escapes `\\` and `\"` only - no `\uXXXX`, no control bytes, no byte
 * >= 0x80) and signed decimal integers without leading zeros, exponents or
 * fractions. Every value is flat: an object or array value is refused as
 * @c BadType, so nesting never happens and the depth budget stays a residual
 * guard. Trailing bytes after the closing brace are @c Malformed.
 *
 * @par No browser_pid on the wire
 * The originating browser is identified out of band: the bridge accepts
 * connections only from a signed @c seal-browser whose ancestor is a known
 * browser, and keys its in-memory map by that browser PID. A @c browser_pid
 * claim in the payload would only add an attacker-controlled string that has to
 * match the OS-derived PID, so the field does not exist. The resolution happens
 * server-side in @c BrowserBridge::Impl::serveConnection, which pins the peer,
 * walks its ancestry to a signed browser image, and uses that PID as the
 * verdict-map key.
 *
 * @par Allocation
 * Every string value is read into a fixed stack buffer first; an integer is
 * converted in place, straight off the payload. The parser allocates only the
 * @c std::string fields it keeps (@c url_host <= 253 bytes,
 * @c url_path_hash = 64 bytes, @c visit <= 64 bytes). It never invokes the
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
 * | `secure`        | required | required |
 * | `form`          | reject   | required |
 * | `user`          | reject   | optional |
 * | `visit`         | optional | optional |
 *
 * @par Per-field validation
 * |                    Field | Accepted value                                         |
 * |--------------------------|--------------------------------------------------------|
 * |                      `v` | integer, must equal 1                                  |
 * |                   `kind` | `"click"` or `"nav"` (absent -> click)                 |
 * |                 `x`, `y` | integer in [-50000, 50000]                             |
 * |                    `tag` | password / username / email / text / other             |
 * |               `url_host` | 1..253 chars, `[A-Za-z0-9.-]` plus at most one `:port` |
 * |          `url_path_hash` | exactly 64 chars, `[0-9a-f]`                           |
 * | `secure`, `form`, `user` | integer 0 or 1                                         |
 * |                  `visit` | 1..64 chars, `[A-Za-z0-9-]`                            |
 * Whole payload <= 4096 bytes. A `:port` must sit between two non-empty parts,
 * appear once, and parse as a decimal number <= 65535.
 *
 * @param payload  Raw UTF-8 JSON bytes from the pipe. An empty payload is
 *                 @c Empty; more than 4096 bytes is @c TooLarge.
 * @param out      Receives the parsed message. Value-initialised once the
 *                 payload clears the size checks, so no field carries over
 *                 from an earlier call. Read it only when the call returns
 *                 @c None; on error the contents are unspecified. A null
 *                 pointer returns @c Malformed.
 * @return @c BridgeParseError::None on success; otherwise the most-specific
 *         error category.
 * @ingroup FillController
 */
BridgeParseError parseBridgeMessage(std::string_view payload, ParsedBridgeMessage* out);

}  // namespace seal
