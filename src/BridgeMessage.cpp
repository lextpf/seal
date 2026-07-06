#include "BridgeMessage.hpp"

#include <array>
#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace seal
{

namespace
{

constexpr std::size_t kMaxPayloadBytes = 4096;
constexpr int kMaxDepth = 4;
constexpr std::size_t kMaxHostLen = 253;
constexpr std::size_t kHashLen = 64;
constexpr std::size_t kMaxVisitLen = 64;
constexpr std::int32_t kCoordMin = -50000;
constexpr std::int32_t kCoordMax = 50000;

// Bit flags - duplicate-key detection becomes one test per slot.
constexpr std::uint32_t kKeyV = 1U << 0;
constexpr std::uint32_t kKeyX = 1U << 1;
constexpr std::uint32_t kKeyY = 1U << 2;
constexpr std::uint32_t kKeyTag = 1U << 3;
constexpr std::uint32_t kKeyUrlHost = 1U << 4;
constexpr std::uint32_t kKeyUrlPathHash = 1U << 5;
constexpr std::uint32_t kKeyKind = 1U << 6;
constexpr std::uint32_t kKeySecure = 1U << 7;
constexpr std::uint32_t kKeyForm = 1U << 8;
constexpr std::uint32_t kKeyUser = 1U << 9;
constexpr std::uint32_t kKeyVisit = 1U << 10;

// Click report: the legacy six-field shape. `kind` is optional (absent ==
// click); `secure`/`form`/`user`/`visit` are forbidden.
constexpr std::uint32_t kClickRequired =
    kKeyV | kKeyX | kKeyY | kKeyTag | kKeyUrlHost | kKeyUrlPathHash;
constexpr std::uint32_t kClickAllowed = kClickRequired | kKeyKind;

// Nav report: host + secure/form flags, no click coordinates. `user` (a login-identifier
// field for email-first / multi-step logins) and `visit` (the per-document page-load token
// behind the once-per-visit staging latches) are OPTIONAL, so a stale extension sending an
// older nav shape still parses; an absent visit makes staging fail closed downstream.
constexpr std::uint32_t kNavRequired = kKeyV | kKeyKind | kKeyUrlHost | kKeySecure | kKeyForm;
constexpr std::uint32_t kNavAllowed = kNavRequired | kKeyUser | kKeyVisit;

// Hand-rolled bounded recursive-descent JSON parser. Supports only the schema subset:
// objects, ASCII-printable strings, signed decimal ints, structural punctuation. No floats,
// scientific notation, leading zeros, Unicode escapes, or escapes other than \\ and \". Depth
// is capped at every object/array entry to defend the C stack from deep nesting.
class Parser
{
public:
    explicit Parser(std::string_view payload) noexcept
        : m_Begin(payload.data()),
          m_End(payload.data() + payload.size()),
          m_Cursor(payload.data())
    {
    }

    // Top-level: parses an object containing exactly the schema keys;
    // Malformed for anything else.
    BridgeParseError parseObject(ParsedBridgeMessage* out, int depth)
    {
        if (depth >= kMaxDepth)
        {
            return BridgeParseError::DepthExceeded;
        }
        skipWhitespace();
        if (!consume('{'))
        {
            return BridgeParseError::Malformed;
        }
        skipWhitespace();
        std::uint32_t seenKeys = 0;
        bool first = true;
        while (true)
        {
            skipWhitespace();
            if (peek() == '}')
            {
                ++m_Cursor;
                break;
            }
            if (!first)
            {
                if (!consume(','))
                {
                    return BridgeParseError::Malformed;
                }
                skipWhitespace();
            }
            first = false;

            std::array<char, 32> keyBuf{};
            std::size_t keyLen = 0;
            BridgeParseError keyErr = parseAsciiString(keyBuf.data(), keyBuf.size(), &keyLen);
            if (keyErr != BridgeParseError::None)
            {
                return keyErr;
            }
            skipWhitespace();
            if (!consume(':'))
            {
                return BridgeParseError::Malformed;
            }
            skipWhitespace();

            const std::string_view key(keyBuf.data(), keyLen);
            const std::uint32_t bit = keyBit(key);
            if (bit == 0)
            {
                return BridgeParseError::UnknownKey;
            }
            if ((seenKeys & bit) != 0)
            {
                return BridgeParseError::DuplicateKey;
            }
            seenKeys |= bit;

            const BridgeParseError valErr = parseValueForKey(bit, out, depth);
            if (valErr != BridgeParseError::None)
            {
                return valErr;
            }
            skipWhitespace();
        }
        // Kind-selected required/allowed masks. m_Kind was set while parsing
        // the `kind` value (default Click when the key is absent). A key legal
        // only in the other shape is reported as an unknown key; a missing
        // required key as a missing key.
        const std::uint32_t required =
            (out->m_Kind == BridgeKind::Nav) ? kNavRequired : kClickRequired;
        const std::uint32_t allowed =
            (out->m_Kind == BridgeKind::Nav) ? kNavAllowed : kClickAllowed;
        if ((seenKeys & ~allowed) != 0)
        {
            return BridgeParseError::UnknownKey;
        }
        if ((seenKeys & required) != required)
        {
            return BridgeParseError::MissingKey;
        }
        return BridgeParseError::None;
    }

    bool atEnd() const noexcept { return m_Cursor == m_End; }

    // Reject trailing tokens after the top-level object so an attacker
    // cannot smuggle data past the parser.
    BridgeParseError ensureClean()
    {
        skipWhitespace();
        if (!atEnd())
        {
            return BridgeParseError::Malformed;
        }
        return BridgeParseError::None;
    }

private:
    char peek() const noexcept
    {
        if (m_Cursor >= m_End)
        {
            return '\0';
        }
        return *m_Cursor;
    }

    bool consume(char expected) noexcept
    {
        if (m_Cursor >= m_End || *m_Cursor != expected)
        {
            return false;
        }
        ++m_Cursor;
        return true;
    }

    void skipWhitespace() noexcept
    {
        while (m_Cursor < m_End)
        {
            const char c = *m_Cursor;
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            {
                ++m_Cursor;
            }
            else
            {
                break;
            }
        }
    }

    // ASCII string literal, up to bufSize chars. Body must be printable
    // ASCII (0x20..0x7E); only \\ and \" escapes are accepted (no \uXXXX,
    // controls, or bytes >= 0x80).
    BridgeParseError parseAsciiString(char* buf, std::size_t bufSize, std::size_t* outLen) noexcept
    {
        if (!consume('"'))
        {
            return BridgeParseError::Malformed;
        }
        std::size_t n = 0;
        while (m_Cursor < m_End)
        {
            const unsigned char ch = static_cast<unsigned char>(*m_Cursor);
            if (ch == '"')
            {
                ++m_Cursor;
                *outLen = n;
                return BridgeParseError::None;
            }
            if (ch == '\\')
            {
                ++m_Cursor;
                if (m_Cursor >= m_End)
                {
                    return BridgeParseError::Malformed;
                }
                const char esc = *m_Cursor;
                ++m_Cursor;
                char unescaped = '\0';
                if (esc == '\\')
                {
                    unescaped = '\\';
                }
                else if (esc == '"')
                {
                    unescaped = '"';
                }
                else
                {
                    // Keys/values are pure ASCII - reject \n, \t, \uXXXX, etc.
                    return BridgeParseError::BadValue;
                }
                if (n >= bufSize)
                {
                    return BridgeParseError::TooLarge;
                }
                buf[n++] = unescaped;
                continue;
            }
            if (ch < 0x20 || ch > 0x7E)
            {
                return BridgeParseError::BadValue;
            }
            if (n >= bufSize)
            {
                return BridgeParseError::TooLarge;
            }
            buf[n++] = static_cast<char>(ch);
            ++m_Cursor;
        }
        return BridgeParseError::Malformed;
    }

    // Signed decimal int64. Rejects leading zeros (except "0"), spaces,
    // plus signs, non-digit bytes. Out-of-range -> BadValue.
    BridgeParseError parseInt64(std::int64_t* out) noexcept
    {
        const char* start = m_Cursor;
        bool negative = false;
        if (m_Cursor < m_End && *m_Cursor == '-')
        {
            negative = true;
            ++m_Cursor;
        }
        if (m_Cursor >= m_End)
        {
            return BridgeParseError::Malformed;
        }
        const char* digitStart = m_Cursor;
        while (m_Cursor < m_End && *m_Cursor >= '0' && *m_Cursor <= '9')
        {
            ++m_Cursor;
        }
        const std::size_t digitCount = static_cast<std::size_t>(m_Cursor - digitStart);
        if (digitCount == 0)
        {
            return BridgeParseError::Malformed;
        }
        // Only "0" / "-0" allowed - reject other leading zeros.
        if (digitCount > 1 && *digitStart == '0')
        {
            return BridgeParseError::BadValue;
        }
        // No '.', 'e', '+', '-' here - cursor must be at structural punctuation.
        if (m_Cursor < m_End)
        {
            const char trailing = *m_Cursor;
            if (trailing == '.' || trailing == 'e' || trailing == 'E' || trailing == '+' ||
                trailing == '-')
            {
                return BridgeParseError::BadValue;
            }
        }
        std::int64_t value = 0;
        const auto* end = m_Cursor;
        const std::from_chars_result result = std::from_chars(start, end, value);
        if (result.ec != std::errc{} || result.ptr != end)
        {
            return BridgeParseError::BadValue;
        }
        (void)negative;  // Already encoded in the parsed value.
        *out = value;
        return BridgeParseError::None;
    }

    // True for a token byte: alnum or '-', plus '.' when allowDot (host labels
    // are dotted; the visit token is not).
    static bool isTokenChar(char c, bool allowDot) noexcept
    {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '-' || (allowDot && c == '.');
    }

    // Non-empty, length-bounded token whose bytes are all isTokenChar().
    // BadValue on empty, over-length, or an illegal byte; None otherwise.
    static BridgeParseError validateToken(const char* buf,
                                          std::size_t len,
                                          std::size_t maxLen,
                                          bool allowDot) noexcept
    {
        if (len == 0 || len > maxLen)
        {
            return BridgeParseError::BadValue;
        }
        for (std::size_t i = 0; i < len; ++i)
        {
            if (!isTokenChar(buf[i], allowDot))
            {
                return BridgeParseError::BadValue;
            }
        }
        return BridgeParseError::None;
    }

    // Parse a string value, validate it as a bounded token, and store it in
    // `dest`. The +1 buffer slack turns an in-cap overrun into a BadValue
    // length rejection rather than TooLarge. Shared by url_host and visit.
    template <std::size_t MaxLen>
    BridgeParseError parseTokenInto(std::string* dest, bool allowDot) noexcept
    {
        std::array<char, MaxLen + 1> buf{};
        std::size_t len = 0;
        const BridgeParseError err = parseAsciiString(buf.data(), buf.size(), &len);
        if (err != BridgeParseError::None)
        {
            return err;
        }
        const BridgeParseError valErr = validateToken(buf.data(), len, MaxLen, allowDot);
        if (valErr != BridgeParseError::None)
        {
            return valErr;
        }
        dest->assign(buf.data(), len);
        return BridgeParseError::None;
    }

    // Parse a short (<=15 char) string value and map it against `table` by exact
    // match, writing the matched enumerator to `out`. BadValue if unmatched.
    // Shared by the tag and kind keys (their whitelists are the tables).
    template <typename Enum, std::size_t N>
    BridgeParseError parseEnumValue(const std::array<std::pair<std::string_view, Enum>, N>& table,
                                    Enum* out) noexcept
    {
        std::array<char, 16> buf{};
        std::size_t len = 0;
        const BridgeParseError err = parseAsciiString(buf.data(), buf.size(), &len);
        if (err != BridgeParseError::None)
        {
            return err;
        }
        const std::string_view value(buf.data(), len);
        for (const auto& entry : table)
        {
            if (value == entry.first)
            {
                *out = entry.second;
                return BridgeParseError::None;
            }
        }
        return BridgeParseError::BadValue;
    }

    // Key -> kKey* bit; 0 for any unrecognised key.
    static std::uint32_t keyBit(std::string_view key) noexcept
    {
        if (key == std::string_view("v"))
        {
            return kKeyV;
        }
        if (key == std::string_view("x"))
        {
            return kKeyX;
        }
        if (key == std::string_view("y"))
        {
            return kKeyY;
        }
        if (key == std::string_view("tag"))
        {
            return kKeyTag;
        }
        if (key == std::string_view("url_host"))
        {
            return kKeyUrlHost;
        }
        if (key == std::string_view("url_path_hash"))
        {
            return kKeyUrlPathHash;
        }
        if (key == std::string_view("kind"))
        {
            return kKeyKind;
        }
        if (key == std::string_view("secure"))
        {
            return kKeySecure;
        }
        if (key == std::string_view("form"))
        {
            return kKeyForm;
        }
        if (key == std::string_view("user"))
        {
            return kKeyUser;
        }
        if (key == std::string_view("visit"))
        {
            return kKeyVisit;
        }
        return 0;
    }

    // Per-key dispatch with strict type/range checks.
    BridgeParseError parseValueForKey(std::uint32_t keyBit, ParsedBridgeMessage* out, int depth)
    {
        // No schema key legitimately holds an object/array; the depth
        // budget only defends against attacker payloads that try to
        // exhaust the C stack before reaching a value.
        if (peek() == '{' || peek() == '[')
        {
            if (depth + 1 >= kMaxDepth)
            {
                return BridgeParseError::DepthExceeded;
            }
            return BridgeParseError::BadType;
        }

        switch (keyBit)
        {
            case kKeyV:
            {
                std::int64_t value = 0;
                const BridgeParseError err = parseInt64(&value);
                if (err != BridgeParseError::None)
                {
                    return err;
                }
                if (value != 1)
                {
                    return BridgeParseError::BadValue;
                }
                out->m_Version = 1;
                return BridgeParseError::None;
            }
            case kKeyX:
            case kKeyY:
            {
                std::int64_t value = 0;
                const BridgeParseError err = parseInt64(&value);
                if (err != BridgeParseError::None)
                {
                    return err;
                }
                if (value < kCoordMin || value > kCoordMax)
                {
                    return BridgeParseError::BadValue;
                }
                if (keyBit == kKeyX)
                {
                    out->m_X = static_cast<std::int32_t>(value);
                }
                else
                {
                    out->m_Y = static_cast<std::int32_t>(value);
                }
                return BridgeParseError::None;
            }
            case kKeyTag:
            {
                static constexpr std::array<std::pair<std::string_view, BridgeTag>, 5> kTagTable{{
                    {"password", BridgeTag::Password},
                    {"username", BridgeTag::Username},
                    {"email", BridgeTag::Email},
                    {"text", BridgeTag::Text},
                    {"other", BridgeTag::Other},
                }};
                return parseEnumValue(kTagTable, &out->m_Tag);
            }
            case kKeyUrlHost:
                // Hosts cap at 253 bytes (dotted labels allow '.'); parsed into
                // a stack buffer, no secure_string.
                return parseTokenInto<kMaxHostLen>(&out->m_UrlHost, /*allowDot=*/true);
            case kKeyUrlPathHash:
            {
                std::array<char, kHashLen + 1> buf{};
                std::size_t len = 0;
                const BridgeParseError err = parseAsciiString(buf.data(), buf.size(), &len);
                if (err != BridgeParseError::None)
                {
                    return err;
                }
                if (len != kHashLen)
                {
                    return BridgeParseError::BadValue;
                }
                for (std::size_t i = 0; i < kHashLen; ++i)
                {
                    const char c = buf[i];
                    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
                    if (!ok)
                    {
                        return BridgeParseError::BadValue;
                    }
                }
                out->m_UrlPathHash.assign(buf.data(), len);
                return BridgeParseError::None;
            }
            case kKeyKind:
            {
                static constexpr std::array<std::pair<std::string_view, BridgeKind>, 2> kKindTable{{
                    {"click", BridgeKind::Click},
                    {"nav", BridgeKind::Nav},
                }};
                return parseEnumValue(kKindTable, &out->m_Kind);
            }
            case kKeyVisit:
                // Per-document page-load token: random alnum+dash (a UUID is 36
                // chars), no dots. Anything else is fail-closed rejected. The +1
                // buffer slack turns an in-cap overrun into a BadValue length
                // rejection rather than TooLarge, matching url_host.
                return parseTokenInto<kMaxVisitLen>(&out->m_Visit, /*allowDot=*/false);
            case kKeySecure:
            case kKeyForm:
            case kKeyUser:
            {
                std::int64_t value = 0;
                const BridgeParseError err = parseInt64(&value);
                if (err != BridgeParseError::None)
                {
                    return err;
                }
                if (value != 0 && value != 1)
                {
                    return BridgeParseError::BadValue;
                }
                if (keyBit == kKeySecure)
                {
                    out->m_Secure = (value == 1);
                }
                else if (keyBit == kKeyForm)
                {
                    out->m_HasPasswordForm = (value == 1);
                }
                else
                {
                    out->m_HasUsernameField = (value == 1);
                }
                return BridgeParseError::None;
            }
            default:
                return BridgeParseError::UnknownKey;
        }
    }

    const char* m_Begin;
    const char* m_End;
    const char* m_Cursor;
};

}  // namespace

const char* bridgeParseErrorToken(BridgeParseError error)
{
    switch (error)
    {
        case BridgeParseError::None:
            return "ok";
        case BridgeParseError::Empty:
            return "empty";
        case BridgeParseError::TooLarge:
            return "too_large";
        case BridgeParseError::Malformed:
            return "malformed";
        case BridgeParseError::DepthExceeded:
            return "depth_exceeded";
        case BridgeParseError::UnknownKey:
            return "unknown_key";
        case BridgeParseError::MissingKey:
            return "missing_key";
        case BridgeParseError::DuplicateKey:
            return "duplicate_key";
        case BridgeParseError::BadType:
            return "bad_type";
        case BridgeParseError::BadValue:
            return "bad_value";
        default:
            return "unknown";
    }
}

BridgeParseError parseBridgeMessage(std::string_view payload, ParsedBridgeMessage* out)
{
    if (out == nullptr)
    {
        return BridgeParseError::Malformed;
    }
    if (payload.empty())
    {
        return BridgeParseError::Empty;
    }
    if (payload.size() > kMaxPayloadBytes)
    {
        return BridgeParseError::TooLarge;
    }

    *out = ParsedBridgeMessage{};

    Parser parser(payload);
    const BridgeParseError objErr = parser.parseObject(out, 0);
    if (objErr != BridgeParseError::None)
    {
        return objErr;
    }
    return parser.ensureClean();
}

}  // namespace seal
