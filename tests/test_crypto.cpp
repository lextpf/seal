#include "test_helpers.hpp"

#include <gtest/gtest.h>

#include <span>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::string_literals;

class CryptoTest : public ::testing::Test
{
};

TEST_F(CryptoTest, BasicRoundtrip)
{
    auto password = make_secure_string("test_password_123");
    std::string plaintext = "Hello, World!";

    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    EXPECT_FALSE(packet.empty());
    EXPECT_GT(packet.size(), plaintext.size());  // Salt + IV + tag overhead.

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

    auto packet1 =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    auto packet2 =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    // Random salt/IV must produce different ciphertexts.
    EXPECT_NE(packet1, packet2);
}

TEST_F(CryptoTest, WrongPasswordFailsAuthentication)
{
    auto correctPassword = make_secure_string("correct_password");
    auto wrongPassword = make_secure_string("wrong_password");
    std::string plaintext = "Secret message";

    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    auto packet = seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes),
                                                    correctPassword);

    EXPECT_THROW(
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), wrongPassword),
        std::runtime_error);
}

TEST_F(CryptoTest, CorruptedPacketFailsAuthentication)
{
    auto password = make_secure_string("test_password");
    std::string plaintext = "Test message";

    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    std::vector<unsigned char> corrupted = packet;
    corrupted[corrupted.size() / 2] ^= 0xFF;

    EXPECT_THROW(
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(corrupted), password),
        std::runtime_error);
}

TEST_F(CryptoTest, VerifyPacketAcceptsValidPacket)
{
    auto password = make_secure_string("test_password");
    std::string plaintext = "verify me";
    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    EXPECT_NO_THROW(
        seal::Cryptography::verifyPacket(std::span<const unsigned char>(packet), password));
}

TEST_F(CryptoTest, VerifyPacketRejectsWrongPassword)
{
    auto correctPassword = make_secure_string("correct_password");
    auto wrongPassword = make_secure_string("wrong_password");
    std::string plaintext = "verify me";
    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    auto packet = seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes),
                                                    correctPassword);

    EXPECT_THROW(
        seal::Cryptography::verifyPacket(std::span<const unsigned char>(packet), wrongPassword),
        std::runtime_error);
}

TEST_F(CryptoTest, VerifyPacketRejectsCorruptedPacket)
{
    auto password = make_secure_string("test_password");
    std::string plaintext = "verify me";
    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    std::vector<unsigned char> corrupted = packet;
    corrupted[corrupted.size() / 2] ^= 0xFF;

    EXPECT_THROW(
        seal::Cryptography::verifyPacket(std::span<const unsigned char>(corrupted), password),
        std::runtime_error);
}

TEST_F(CryptoTest, TooShortPacketThrows)
{
    auto password = make_secure_string("test_password");
    std::vector<unsigned char> shortPacket(10);  // Below header minimum.

    EXPECT_THROW(
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(shortPacket), password),
        std::runtime_error);
}

TEST_F(CryptoTest, EmptyPlaintext)
{
    auto password = make_secure_string("test_password");
    std::vector<unsigned char> empty;

    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(empty), password);

    EXPECT_FALSE(packet.empty());  // Header still present.

    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    EXPECT_TRUE(decrypted.empty());
}

TEST_F(CryptoTest, LargePlaintext)
{
    auto password = make_secure_string("test_password");
    std::vector<unsigned char> largePlaintext(10000, 0x42);  // 10 KB of 0x42

    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(largePlaintext), password);

    EXPECT_FALSE(packet.empty());

    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    EXPECT_EQ(decrypted, largePlaintext);
}

TEST_F(CryptoTest, BinaryData)
{
    auto password = make_secure_string("test_password");
    std::vector<unsigned char> binaryData = {0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE};

    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(binaryData), password);

    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    EXPECT_EQ(decrypted, binaryData);
}

TEST_F(CryptoTest, UnicodeText)
{
    auto password = make_secure_string("test_password");
    std::string unicodeText = "Hello 世界 🌍 Привет";

    std::vector<unsigned char> plainBytes(unicodeText.begin(), unicodeText.end());

    auto packet =
        seal::Cryptography::encryptPacket(std::span<const unsigned char>(plainBytes), password);

    auto decrypted =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    EXPECT_EQ(decryptedStr, unicodeText);
}
