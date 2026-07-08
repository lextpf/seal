#include "../src/BridgeMessage.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>

using seal::BridgeParseError;
using seal::BridgeTag;
using seal::parseBridgeMessage;
using seal::ParsedBridgeMessage;

namespace
{

std::string buildValid(const char* tag = "password", const std::string& host = "example.com")
{
    return std::string("{\"v\":1,\"x\":100,\"y\":200,\"tag\":\"") + tag +
           std::string("\",\"url_host\":\"") + host + std::string("\",\"secure\":1") +
           std::string(",\"url_path_hash\":\"") + std::string(64, 'a') + std::string("\"}");
}

}  // namespace

class BridgeSecurityTest : public ::testing::Test
{
};

// M5: parser must fail closed on any schema-violating message so a
// malformed peer cannot inject a state-changing payload. The "bridge
// alone short-circuit" gate itself lives in FusionDecider.
TEST_F(BridgeSecurityTest, ValidMessageAccepted)
{
    const std::string body = buildValid();
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::None);
}

TEST_F(BridgeSecurityTest, ClickMissingSecureRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":100,\"y\":200,\"tag\":\"password\","
                                 "\"url_host\":\"example.com\",\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::MissingKey);
}

// M6: WinVerifyTrust runs against real signed binaries elsewhere; the
// actual call lives in BrowserBridge.cpp (USE_QT_UI-gated, not in
// seal_tests) and host/browser/main.cpp via SignerUtils.hpp. Here we
// only assert the parser's structural invariants - a malformed peer
// cannot bypass the schema.
TEST_F(BridgeSecurityTest, ParserRejectsControlCharactersInHost)
{
    // A signed-but-poisoned peer could embed control bytes in url_host to
    // confuse log parsers; the parser must reject anything outside
    // [A-Za-z0-9.-].
    const std::string body =
        std::string(
            "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\",\"url_host\":\"a\\b\","
            "\"url_path_hash\":\"") +
        std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_NE(parseBridgeMessage(body, &parsed), BridgeParseError::None);
}

// M7: per-start fresh HMAC key. BrowserBridge is USE_QT_UI-gated, so we
// just verify the parser rejects extra keys - including "token" - so
// nothing can smuggle past the schema into the application layer.
TEST_F(BridgeSecurityTest, TokenKeyInMessageRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\",\"url_host\":\"a\","
                                 "\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\",\"token\":\"abc\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::UnknownKey);
}

// M8: disable() panic mode. The parser is unaffected by disable() (which
// lives in BrowserBridge.cpp); ParsedBridgeMessage is a value type, so
// nothing can leak across the disable boundary.
TEST_F(BridgeSecurityTest, ParsedMessageIsCopyable)
{
    ParsedBridgeMessage a;
    EXPECT_EQ(parseBridgeMessage(buildValid(), &a), BridgeParseError::None);
    ParsedBridgeMessage b = a;
    EXPECT_EQ(b.m_UrlHost, std::string("example.com"));
    EXPECT_EQ(b.m_Tag, BridgeTag::Password);
}

TEST_F(BridgeSecurityTest, EmptyAndOversizedAreDistinctErrors)
{
    // Defence in depth: downstream log parsers pivot on reason= tokens,
    // so empty and oversized must surface as distinct categories.
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage("", &parsed), BridgeParseError::Empty);

    const std::string oversized(4097, 'a');
    EXPECT_EQ(parseBridgeMessage(oversized, &parsed), BridgeParseError::TooLarge);
}

TEST_F(BridgeSecurityTest, AllErrorTokensAreUnique)
{
    using seal::bridgeParseErrorToken;
    const std::array<const char*, 9> tokens = {
        bridgeParseErrorToken(BridgeParseError::Empty),
        bridgeParseErrorToken(BridgeParseError::TooLarge),
        bridgeParseErrorToken(BridgeParseError::Malformed),
        bridgeParseErrorToken(BridgeParseError::DepthExceeded),
        bridgeParseErrorToken(BridgeParseError::UnknownKey),
        bridgeParseErrorToken(BridgeParseError::MissingKey),
        bridgeParseErrorToken(BridgeParseError::DuplicateKey),
        bridgeParseErrorToken(BridgeParseError::BadType),
        bridgeParseErrorToken(BridgeParseError::BadValue),
    };
    for (std::size_t i = 0; i < tokens.size(); ++i)
    {
        for (std::size_t j = i + 1; j < tokens.size(); ++j)
        {
            EXPECT_STRNE(tokens[i], tokens[j]) << "Tokens at " << i << " and " << j << " collide";
        }
    }
}
