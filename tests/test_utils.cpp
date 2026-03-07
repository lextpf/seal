/**
 * @file test_utils.cpp
 * @brief Unit tests for utility functions (hex encoding, string manipulation)
 * @author seal Contributors
 * @date 2024
 */

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace std::string_literals;

// Test suite for hex encoding/decoding
class HexUtilsTest : public ::testing::Test
{
};

TEST_F(HexUtilsTest, ToHexBasicEncoding)
{
    std::vector<unsigned char> data = {0x00, 0xFF, 0x0A, 0xB5};
    std::string hex = seal::utils::to_hex(data);

    EXPECT_EQ(hex, "00ff0ab5");
}

TEST_F(HexUtilsTest, ToHexEmptyInput)
{
    std::vector<unsigned char> empty;
    std::string hex = seal::utils::to_hex(empty);

    EXPECT_TRUE(hex.empty());
}

TEST_F(HexUtilsTest, ToHexSingleByte)
{
    std::vector<unsigned char> data = {0x42};
    std::string hex = seal::utils::to_hex(data);

    EXPECT_EQ(hex, "42");
}

TEST_F(HexUtilsTest, ToHexAllBytes)
{
    std::vector<unsigned char> data(256);
    for (size_t i = 0; i < 256; ++i)
    {
        data[i] = static_cast<unsigned char>(i);
    }

    std::string hex = seal::utils::to_hex(data);
    EXPECT_EQ(hex.size(), 512u);  // 256 bytes * 2 hex chars

    // Check first and last
    EXPECT_EQ(hex.substr(0, 2), "00");
    EXPECT_EQ(hex.substr(510, 2), "ff");
}

TEST_F(HexUtilsTest, FromHexBasicDecoding)
{
    std::string hex = "00ff0ab5";
    std::vector<unsigned char> result;

    bool success = seal::utils::from_hex(hex, result);

    EXPECT_TRUE(success);
    EXPECT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0], 0x00);
    EXPECT_EQ(result[1], 0xFF);
    EXPECT_EQ(result[2], 0x0A);
    EXPECT_EQ(result[3], 0xB5);
}

TEST_F(HexUtilsTest, FromHexUppercaseHex)
{
    std::string hex = "00FF0AB5";
    std::vector<unsigned char> result;

    bool success = seal::utils::from_hex(hex, result);

    EXPECT_TRUE(success);
    EXPECT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0], 0x00);
    EXPECT_EQ(result[1], 0xFF);
    EXPECT_EQ(result[2], 0x0A);
    EXPECT_EQ(result[3], 0xB5);
}

TEST_F(HexUtilsTest, FromHexMixedCase)
{
    std::string hex = "00Ff0aB5";
    std::vector<unsigned char> result;

    bool success = seal::utils::from_hex(hex, result);

    EXPECT_TRUE(success);
    EXPECT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0], 0x00);
    EXPECT_EQ(result[1], 0xFF);
    EXPECT_EQ(result[2], 0x0A);
    EXPECT_EQ(result[3], 0xB5);
}

TEST_F(HexUtilsTest, FromHexEmptyString)
{
    std::string hex = "";
    std::vector<unsigned char> result;

    bool success = seal::utils::from_hex(hex, result);

    // from_hex returns false for empty strings (they're considered invalid)
    // This is by design - empty hex strings don't represent valid hex data
    EXPECT_FALSE(success);
    EXPECT_TRUE(result.empty());
}

TEST_F(HexUtilsTest, FromHexOddLengthFails)
{
    std::string hex = "123";  // Odd length
    std::vector<unsigned char> result;

    bool success = seal::utils::from_hex(hex, result);

    EXPECT_FALSE(success);
}

TEST_F(HexUtilsTest, FromHexInvalidCharactersFail)
{
    std::string hex = "12G5";  // 'G' is invalid
    std::vector<unsigned char> result;

    bool success = seal::utils::from_hex(hex, result);

    EXPECT_FALSE(success);
}

TEST_F(HexUtilsTest, FromHexRoundtripWithToHex)
{
    std::vector<unsigned char> original = {0x00, 0xFF, 0x42, 0xAB, 0xCD, 0xEF};

    std::string hex = seal::utils::to_hex(original);
    std::vector<unsigned char> decoded;

    bool success = seal::utils::from_hex(hex, decoded);

    EXPECT_TRUE(success);
    EXPECT_EQ(decoded, original);
}

// Test suite for string manipulation
class StringUtilsTest : public ::testing::Test
{
};

TEST_F(StringUtilsTest, StripSpacesBasicFunctionality)
{
    std::string input = "  hello  world  ";
    std::string result = seal::utils::stripSpaces(input);

    EXPECT_EQ(result, "helloworld");
}

TEST_F(StringUtilsTest, StripSpacesAllSpaces)
{
    std::string input = "   \t\n\r   ";
    std::string result = seal::utils::stripSpaces(input);

    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilsTest, StripSpacesNoSpaces)
{
    std::string input = "helloworld";
    std::string result = seal::utils::stripSpaces(input);

    EXPECT_EQ(result, input);
}

TEST_F(StringUtilsTest, StripSpacesEmptyString)
{
    std::string input = "";
    std::string result = seal::utils::stripSpaces(input);

    EXPECT_TRUE(result.empty());
}

TEST_F(StringUtilsTest, StripSpacesMixedWhitespace)
{
    std::string input = "a\tb\nc\rd e";
    std::string result = seal::utils::stripSpaces(input);

    EXPECT_EQ(result, "abcde");
}

// Test suite for hex token extraction
class HexTokenExtractionTest : public ::testing::Test
{
};

TEST_F(HexTokenExtractionTest, BasicExtraction)
{
    // Minimum packet size is (SALT_LEN + IV_LEN + TAG_LEN) * 2 = (16 + 12 + 16) * 2 = 88 hex chars
    // Create a hex string that's at least 88 characters long
    std::string longHex =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        "abcdef1234567890abcdef1234567890abcdef";
    std::string input = "hello " + longHex + " world";
    auto tokens = seal::utils::extractHexTokens(input);

    EXPECT_EQ(tokens.size(), 1u);
    EXPECT_EQ(tokens[0], longHex);
}

TEST_F(HexTokenExtractionTest, MultipleTokens)
{
    // Minimum packet size is 88 hex chars - create two valid hex tokens
    std::string hex1 =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        "abcdef1234567890abcdef1234567890abcdef";
    std::string hex2 =
        "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        "fedcba9876543210fedcba9876543210fedcba";
    std::string input = "abc " + hex1 + " def " + hex2 + " ghi";
    auto tokens = seal::utils::extractHexTokens(input);

    EXPECT_EQ(tokens.size(), 2u);
    EXPECT_EQ(tokens[0], hex1);
    EXPECT_EQ(tokens[1], hex2);
}

TEST_F(HexTokenExtractionTest, OddLengthHexIgnored)
{
    std::string input = "1234567890abcde";  // Odd length
    auto tokens = seal::utils::extractHexTokens(input);

    EXPECT_TRUE(tokens.empty());
}

TEST_F(HexTokenExtractionTest, TooShortHexIgnored)
{
    // Minimum packet size is 88 hex chars, so a short hex string should be ignored
    std::string input = "1234567890abcdef";  // Only 16 hex chars, way too short
    auto tokens = seal::utils::extractHexTokens(input);

    EXPECT_TRUE(tokens.empty());
}

TEST_F(HexTokenExtractionTest, InvalidHexCharactersIgnored)
{
    std::string input = "1234567890abcdefg";  // Contains 'g'
    auto tokens = seal::utils::extractHexTokens(input);

    EXPECT_TRUE(tokens.empty());
}

TEST_F(HexTokenExtractionTest, EmptyString)
{
    std::string input = "";
    auto tokens = seal::utils::extractHexTokens(input);

    EXPECT_TRUE(tokens.empty());
}

TEST_F(HexTokenExtractionTest, WhitespaceOnly)
{
    std::string input = "   \t\n\r   ";
    auto tokens = seal::utils::extractHexTokens(input);

    EXPECT_TRUE(tokens.empty());
}
