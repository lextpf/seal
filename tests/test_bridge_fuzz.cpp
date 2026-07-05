#include "../src/BridgeMessage.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>
#include <string>
#include <string_view>

using seal::BridgeParseError;
using seal::BridgeTag;
using seal::parseBridgeMessage;
using seal::ParsedBridgeMessage;

namespace
{

// Canonical six-field body. Tests mutate one piece to probe a single
// rejection path. The wire schema carries no browser_pid -- the bridge
// resolves it out-of-band (GetNamedPipeClientProcessId + parent walk).
std::string buildValid()
{
    return std::string(
               "{\"v\":1,"
               "\"x\":100,"
               "\"y\":200,"
               "\"tag\":\"password\","
               "\"url_host\":\"example.com\","
               "\"url_path_hash\":\"") +
           std::string(64, 'a') + std::string("\"}");
}

// Canonical navigation report: host + secure/form flags, no click coords.
std::string buildValidNav()
{
    return std::string(
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"example.com\","
        "\"secure\":1,\"form\":1}");
}

}  // namespace

class BridgeFuzzTest : public ::testing::Test
{
};

TEST_F(BridgeFuzzTest, ValidMessageParses)
{
    ParsedBridgeMessage parsed;
    const auto err = parseBridgeMessage(buildValid(), &parsed);
    EXPECT_EQ(err, BridgeParseError::None);
    EXPECT_EQ(parsed.m_Version, 1);
    EXPECT_EQ(parsed.m_X, 100);
    EXPECT_EQ(parsed.m_Y, 200);
    EXPECT_EQ(parsed.m_Tag, BridgeTag::Password);
    EXPECT_EQ(parsed.m_UrlHost, std::string("example.com"));
    EXPECT_EQ(parsed.m_UrlPathHash.size(), 64u);
}

TEST_F(BridgeFuzzTest, EmptyInputRejected)
{
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage("", &parsed), BridgeParseError::Empty);
}

TEST_F(BridgeFuzzTest, SingleBraceRejected)
{
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage("{", &parsed), BridgeParseError::Malformed);
}

TEST_F(BridgeFuzzTest, OnlyOpeningBraceAndCommaRejected)
{
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage("{,}", &parsed), BridgeParseError::Malformed);
}

TEST_F(BridgeFuzzTest, OversizedTokenRejected)
{
    ParsedBridgeMessage parsed;
    const std::string oversized(8192, 'a');
    EXPECT_EQ(parseBridgeMessage(oversized, &parsed), BridgeParseError::TooLarge);
}

TEST_F(BridgeFuzzTest, ExactlyFourKilobytesParseable)
{
    // Hard 4 KB ceiling; the boundary itself is accepted. Trailing
    // whitespace within budget is legitimate JSON (ECMA-404).
    std::string body = buildValid();
    body.resize(4096, ' ');
    ParsedBridgeMessage parsed;
    const auto err = parseBridgeMessage(body, &parsed);
    EXPECT_EQ(err, BridgeParseError::None);
}

TEST_F(BridgeFuzzTest, FourKilobytesPlusOneRejected)
{
    std::string body = buildValid();
    body.resize(4097, ' ');
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::TooLarge);
}

TEST_F(BridgeFuzzTest, DeeplyNestedRejectedWithoutStackOverflow)
{
    std::string deeplyNested;
    deeplyNested.reserve(2048);
    deeplyNested = "{\"v\":";
    for (int i = 0; i < 1000; ++i)
    {
        deeplyNested += "{";
    }
    deeplyNested += "1";
    for (int i = 0; i < 1000; ++i)
    {
        deeplyNested += "}";
    }
    deeplyNested += "}";
    ParsedBridgeMessage parsed;
    // Rejected as TooLarge (likely) or DepthExceeded; both fine.
    const auto err = parseBridgeMessage(deeplyNested, &parsed);
    EXPECT_NE(err, BridgeParseError::None);
}

TEST_F(BridgeFuzzTest, MismatchedBracesRejected)
{
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage("{\"v\":1", &parsed), BridgeParseError::Malformed);
    EXPECT_EQ(parseBridgeMessage("\"v\":1}", &parsed), BridgeParseError::Malformed);
}

TEST_F(BridgeFuzzTest, UnicodeEscapeRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\","
                                 "\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\\u00e9\"}");
    ParsedBridgeMessage parsed;
    EXPECT_NE(parseBridgeMessage(body, &parsed), BridgeParseError::None);
}

TEST_F(BridgeFuzzTest, UnicodeBomRejected)
{
    const std::string body = std::string("\xEF\xBB\xBF") + buildValid();
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::Malformed);
}

TEST_F(BridgeFuzzTest, FloatRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1.0,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, ScientificNotationRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1e0,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, TagNotInWhitelistRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"admin\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, TagEmail)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"email\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::None);
    EXPECT_EQ(parsed.m_Tag, BridgeTag::Email);
}

TEST_F(BridgeFuzzTest, TagText)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"text\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::None);
    EXPECT_EQ(parsed.m_Tag, BridgeTag::Text);
}

TEST_F(BridgeFuzzTest, UrlHostWithSlashRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a/b\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, UrlHostWithQueryRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a?b\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, UrlHostWithHashRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a#b\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, UrlHostWithNonAsciiRejected)
{
    // Separate push_back avoids MSVC's hex-escape concatenation with 'b'.
    std::string body =
        "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
        "\"url_host\":\"a";
    body.push_back(static_cast<char>(0xE9));
    body += "b\",\"url_path_hash\":\"";
    body += std::string(64, 'a');
    body += "\"}";
    ParsedBridgeMessage parsed;
    EXPECT_NE(parseBridgeMessage(body, &parsed), BridgeParseError::None);
}

TEST_F(BridgeFuzzTest, UrlHostLength254Rejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"") +
                             std::string(254, 'a') + std::string("\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_NE(parseBridgeMessage(body, &parsed), BridgeParseError::None);
}

TEST_F(BridgeFuzzTest, UrlHostLength253Accepted)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"") +
                             std::string(253, 'a') + std::string("\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::None);
    EXPECT_EQ(parsed.m_UrlHost.size(), 253u);
}

TEST_F(BridgeFuzzTest, PathHashWrongLengthRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(63, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, PathHashUppercaseRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'A') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, PathHashNonHexRejected)
{
    std::string hash(64, 'a');
    hash[20] = 'z';
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             hash + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, CoordinateOutOfRangeRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":50001,\"y\":1,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, CoordinateNegativeOutOfRangeRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":-50001,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, UnknownKeyRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\",\"extra\":1}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::UnknownKey);
}

TEST_F(BridgeFuzzTest, LegacyBrowserPidKeyRejected)
{
    // browser_pid was removed from the schema -- a stale extension or
    // confused peer sending the old field must hit UnknownKey so neither
    // side silently accepts a mismatched contract.
    const std::string body =
        std::string(
            "{\"v\":1,\"browser_pid\":1234,\"x\":1,\"y\":2,\"tag\":\"password\","
            "\"url_host\":\"a\",\"url_path_hash\":\"") +
        std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::UnknownKey);
}

TEST_F(BridgeFuzzTest, DuplicateKeyRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::DuplicateKey);
}

TEST_F(BridgeFuzzTest, MissingKeyRejected)
{
    const std::string body = std::string(
        "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
        "\"url_host\":\"a\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::MissingKey);
}

TEST_F(BridgeFuzzTest, NestedObjectInValueRejected)
{
    const std::string body = std::string(
                                 "{\"v\":{\"nested\":1},\"x\":1,\"y\":2,"
                                 "\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_NE(parseBridgeMessage(body, &parsed), BridgeParseError::None);
}

TEST_F(BridgeFuzzTest, NavMessageParses)
{
    ParsedBridgeMessage parsed;
    const auto err = parseBridgeMessage(buildValidNav(), &parsed);
    EXPECT_EQ(err, BridgeParseError::None);
    EXPECT_EQ(parsed.m_Version, 1);
    EXPECT_EQ(parsed.m_Kind, seal::BridgeKind::Nav);
    EXPECT_EQ(parsed.m_UrlHost, std::string("example.com"));
    EXPECT_TRUE(parsed.m_Secure);
    EXPECT_TRUE(parsed.m_HasPasswordForm);
}

TEST_F(BridgeFuzzTest, NavSecureAndFormZeroParses)
{
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":0,\"form\":0}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::None);
    EXPECT_FALSE(parsed.m_Secure);
    EXPECT_FALSE(parsed.m_HasPasswordForm);
}

TEST_F(BridgeFuzzTest, ClickReportDefaultsToClickKind)
{
    // A legacy message with no `kind` key parses as a Click report.
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(buildValid(), &parsed), BridgeParseError::None);
    EXPECT_EQ(parsed.m_Kind, seal::BridgeKind::Click);
}

TEST_F(BridgeFuzzTest, ClickWithExplicitKindAccepted)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"kind\":\"click\",\"x\":1,\"y\":2,"
                                 "\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::None);
    EXPECT_EQ(parsed.m_Kind, seal::BridgeKind::Click);
}

TEST_F(BridgeFuzzTest, NavWithClickKeyRejected)
{
    // x/y/tag/url_path_hash are click-only; present in a nav report -> unknown.
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":1,\"form\":1,\"x\":5}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::UnknownKey);
}

TEST_F(BridgeFuzzTest, NavMissingSecureRejected)
{
    const std::string body = "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"form\":1}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::MissingKey);
}

TEST_F(BridgeFuzzTest, NavMissingFormRejected)
{
    const std::string body = "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":1}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::MissingKey);
}

TEST_F(BridgeFuzzTest, ClickWithNavFlagRejected)
{
    // secure/form are nav-only; present in a click report -> unknown key.
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"secure\":1,\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::UnknownKey);
}

TEST_F(BridgeFuzzTest, KindBadValueRejected)
{
    const std::string body =
        "{\"v\":1,\"kind\":\"teleport\",\"url_host\":\"a.com\",\"secure\":1,\"form\":1}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, NavSecureOutOfRangeRejected)
{
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":2,\"form\":1}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, NavWithUserFieldParses)
{
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":1,\"form\":0,\"user\":1}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::None);
    EXPECT_FALSE(parsed.m_HasPasswordForm);
    EXPECT_TRUE(parsed.m_HasUsernameField);
}

TEST_F(BridgeFuzzTest, NavUserFieldIsOptional)
{
    // The 5-field nav (no `user`) still parses; user defaults false.
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(buildValidNav(), &parsed), BridgeParseError::None);
    EXPECT_FALSE(parsed.m_HasUsernameField);
}

TEST_F(BridgeFuzzTest, NavUserOutOfRangeRejected)
{
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":1,\"form\":1,\"user\":2}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, ClickWithUserFlagRejected)
{
    // user is nav-only; present in a click report -> unknown key.
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"user\":1,\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::UnknownKey);
}

TEST_F(BridgeFuzzTest, NavWithVisitTokenParses)
{
    // `visit` is the per-document page-load token driving the once-per-visit
    // staging latches (UUID charset: alnum + dash).
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":1,\"form\":1,"
        "\"visit\":\"3f2b-A9\"}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::None);
    EXPECT_EQ(parsed.m_Visit, std::string("3f2b-A9"));
}

TEST_F(BridgeFuzzTest, NavVisitIsOptional)
{
    // A stale extension sending no `visit` still parses; the token defaults
    // empty (staging then fails closed downstream).
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(buildValidNav(), &parsed), BridgeParseError::None);
    EXPECT_TRUE(parsed.m_Visit.empty());
}

TEST_F(BridgeFuzzTest, NavVisitEmptyRejected)
{
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":1,\"form\":1,"
        "\"visit\":\"\"}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, NavVisitLengthBoundary)
{
    // 64 chars is the cap (a UUID is 36); 65 fits the parse buffer but fails
    // the length check, like url_host's 253/254 split.
    const std::string ok = std::string(
                               "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\","
                               "\"secure\":1,\"form\":1,\"visit\":\"") +
                           std::string(64, 'a') + std::string("\"}");
    const std::string tooLong = std::string(
                                    "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\","
                                    "\"secure\":1,\"form\":1,\"visit\":\"") +
                                std::string(65, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(ok, &parsed), BridgeParseError::None);
    EXPECT_EQ(parsed.m_Visit.size(), 64u);
    EXPECT_EQ(parseBridgeMessage(tooLong, &parsed), BridgeParseError::BadValue);
}

TEST_F(BridgeFuzzTest, NavVisitBadCharsetRejected)
{
    // Only [A-Za-z0-9-]: underscores, spaces, dots are rejected fail-closed.
    for (const char* bad : {"ab_c", "a b", "a.b"})
    {
        const std::string body = std::string(
                                     "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\","
                                     "\"secure\":1,\"form\":1,\"visit\":\"") +
                                 bad + std::string("\"}");
        ParsedBridgeMessage parsed;
        EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::BadValue) << bad;
    }
}

TEST_F(BridgeFuzzTest, NavVisitWrongTypeRejected)
{
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":1,\"form\":1,\"visit\":7}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::Malformed);
}

TEST_F(BridgeFuzzTest, ClickWithVisitRejected)
{
    // visit is nav-only; present in a click report -> unknown key.
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\","
                                 "\"url_host\":\"a\",\"visit\":\"abc\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::UnknownKey);
}

TEST_F(BridgeFuzzTest, NavVisitDuplicateRejected)
{
    const std::string body =
        "{\"v\":1,\"kind\":\"nav\",\"url_host\":\"a.com\",\"secure\":1,\"form\":1,"
        "\"visit\":\"abc\",\"visit\":\"def\"}";
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::DuplicateKey);
}

TEST_F(BridgeFuzzTest, RandomFuzzNeverCrashes)
{
    // Random-byte fuzzer; deterministic seed for reproducibility. Random
    // input almost never matches the schema -- assert no crash.
    std::mt19937 rng(0xfeedf00d);
    std::uniform_int_distribution<int> byteDist(0, 255);
    std::uniform_int_distribution<int> lenDist(0, 256);
    for (int iter = 0; iter < 5000; ++iter)
    {
        const int len = lenDist(rng);
        std::string buf;
        buf.resize(static_cast<std::size_t>(len));
        for (int i = 0; i < len; ++i)
        {
            buf[static_cast<std::size_t>(i)] = static_cast<char>(byteDist(rng));
        }
        ParsedBridgeMessage parsed;
        const auto err = parseBridgeMessage(buf, &parsed);
        // Any error code is fine; just assert no UB.
        (void)err;
    }
}

TEST_F(BridgeFuzzTest, RandomFuzzWithValidBaselineNeverCrashes)
{
    // Mutational fuzzer: take the valid baseline and flip random bytes.
    std::mt19937 rng(0xbadcafe);
    std::uniform_int_distribution<int> byteDist(0, 255);
    const std::string baseline = buildValid();
    std::uniform_int_distribution<std::size_t> idxDist(0, baseline.size() - 1);
    for (int iter = 0; iter < 5000; ++iter)
    {
        std::string buf = baseline;
        const int mutations = 1 + (iter % 8);
        for (int m = 0; m < mutations; ++m)
        {
            buf[idxDist(rng)] = static_cast<char>(byteDist(rng));
        }
        ParsedBridgeMessage parsed;
        const auto err = parseBridgeMessage(buf, &parsed);
        (void)err;
    }
}

TEST_F(BridgeFuzzTest, ParsedStructHasNoSecureStringMember)
{
    // Compile-time guard: the parser's output is plain C++ with no
    // locked allocator. secure_string is move-only, so a parser that
    // allocated one would have to store it (defeating type erasure) or
    // leak it -- neither happens here.
    static_assert(std::is_trivially_destructible<decltype(ParsedBridgeMessage{}.m_Version)>::value,
                  "version field must be trivial");
    static_assert(std::is_same<decltype(ParsedBridgeMessage{}.m_UrlHost), std::string>::value,
                  "host field must be std::string, not secure_string");
    static_assert(std::is_same<decltype(ParsedBridgeMessage{}.m_UrlPathHash), std::string>::value,
                  "path-hash field must be std::string, not secure_string");
    SUCCEED();
}
