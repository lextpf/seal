/**
 * @file test_crypto.cpp
 * @brief Unit tests for core encryption/decryption functions
 * @author seal Contributors
 * @date 2024
 */

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::string_literals;

// Test suite for Cryptography::encryptPacket and Cryptography::decryptPacket
class CryptoTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Setup code if needed
    }

    void TearDown() override
    {
        // Cleanup code if needed
    }
};

TEST_F(CryptoTest, BasicRoundtrip)
{
    auto password = make_secure_string("test_password_123");
    std::string plaintext = "Hello, World!";

    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    // Encrypt
    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    EXPECT_FALSE(packet.empty());
    EXPECT_GT(packet.size(), plaintext.size());  // Should include salt, IV, tag, etc.

    // Decrypt
    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    EXPECT_EQ(decrypted.size(), plaintext.size());
    std::string decryptedStr(decrypted.begin(), decrypted.end());
    EXPECT_EQ(decryptedStr, plaintext);
}

TEST_F(CryptoTest, DifferentPlaintextsProduceDifferentCiphertexts)
{
    auto password = make_secure_string("test_password");
    std::string plaintext = "Same plaintext";

    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    // Encrypt twice
    auto packet1 =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    auto packet2 =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    // Should produce different ciphertexts (due to random salt/IV)
    EXPECT_NE(packet1, packet2);
}

TEST_F(CryptoTest, WrongPasswordFailsAuthentication)
{
    auto correctPassword = make_secure_string("correct_password");
    auto wrongPassword = make_secure_string("wrong_password");
    std::string plaintext = "Secret message";

    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    // Encrypt with correct password
    auto packet = seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes),
                                                    correctPassword);

    // Try to decrypt with wrong password
    EXPECT_THROW(
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), wrongPassword),
        std::runtime_error);
}

TEST_F(CryptoTest, CorruptedPacketFailsAuthentication)
{
    auto password = make_secure_string("test_password");
    std::string plaintext = "Test message";

    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    // Encrypt
    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    // Corrupt the packet (modify a byte)
    std::vector<unsigned char> corrupted = packet;
    corrupted[corrupted.size() / 2] ^= 0xFF;

    // Should fail authentication
    EXPECT_THROW(
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(corrupted), password),
        std::runtime_error);
}

TEST_F(CryptoTest, TooShortPacketThrows)
{
    auto password = make_secure_string("test_password");
    std::vector<unsigned char> shortPacket(10);  // Too short

    EXPECT_THROW(
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(shortPacket), password),
        std::runtime_error);
}

TEST_F(CryptoTest, EmptyPlaintext)
{
    auto password = make_secure_string("test_password");
    std::vector<unsigned char> empty;

    // Should handle empty input
    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(empty), password);

    EXPECT_FALSE(packet.empty());  // Should still produce a packet

    // Should decrypt to empty
    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    EXPECT_TRUE(decrypted.empty());
}

TEST_F(CryptoTest, LargePlaintext)
{
    auto password = make_secure_string("test_password");
    std::vector<unsigned char> largePlaintext(10000, 0x42);  // 10KB of 0x42

    // Encrypt
    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(largePlaintext), password);

    EXPECT_FALSE(packet.empty());

    // Decrypt
    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    EXPECT_EQ(decrypted, largePlaintext);
}

TEST_F(CryptoTest, BinaryData)
{
    auto password = make_secure_string("test_password");
    std::vector<unsigned char> binaryData = {0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE};

    // Encrypt
    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(binaryData), password);

    // Decrypt
    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    EXPECT_EQ(decrypted, binaryData);
}

TEST_F(CryptoTest, UnicodeText)
{
    auto password = make_secure_string("test_password");
    std::string unicodeText = "Hello 世界 🌍 Привет";

    std::vector<unsigned char> plainBytes(unicodeText.begin(), unicodeText.end());

    // Encrypt
    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    // Decrypt
    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    EXPECT_EQ(decryptedStr, unicodeText);
}
