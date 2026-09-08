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

// schema violations must fail closed; FusionDecider separately enforces M5.
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

// this checks schema boundaries; signed-peer verification is exercised separately.
TEST_F(BridgeSecurityTest, ParserRejectsControlCharactersInHost)
{
    // even a trusted peer must not introduce log control bytes through url_host.
    const std::string body =
        std::string(
            "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\",\"url_host\":\"a\\b\","
            "\"url_path_hash\":\"") +
        std::string(64, 'a') + std::string("\"}");
    ParsedBridgeMessage parsed;
    EXPECT_NE(parseBridgeMessage(body, &parsed), BridgeParseError::None);
}

// the schema rejects authentication-token fields; peer identity is out-of-band.
TEST_F(BridgeSecurityTest, TokenKeyInMessageRejected)
{
    const std::string body = std::string(
                                 "{\"v\":1,\"x\":1,\"y\":2,\"tag\":\"password\",\"url_host\":\"a\","
                                 "\"url_path_hash\":\"") +
                             std::string(64, 'a') + std::string("\",\"token\":\"abc\"}");
    ParsedBridgeMessage parsed;
    EXPECT_EQ(parseBridgeMessage(body, &parsed), BridgeParseError::UnknownKey);
}

// parser results contain no shared state across messages.
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
    // reason tokens distinguish empty and oversized payloads for diagnostics.
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
