#include "test_helpers.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
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

    EXPECT_THROW((void)seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet),
                                                         wrongPassword),
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

    EXPECT_THROW((void)seal::Cryptography::decryptPacket(std::span<const unsigned char>(corrupted),
                                                         password),
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

    EXPECT_THROW((void)seal::Cryptography::decryptPacket(
                     std::span<const unsigned char>(shortPacket), password),
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

TEST_F(CryptoTest, WrongMagicRejected)
{
    // A packet whose 4-byte magic is not the live "seal" header must not parse,
    // even when its length is otherwise plausible.
    std::vector<unsigned char> badPacket(
        seal::cfg::MAGIC_LEN + seal::cfg::SALT_LEN + seal::cfg::IV_LEN + seal::cfg::TAG_LEN, 0);
    badPacket[0] = 'x';
    badPacket[1] = 'x';
    badPacket[2] = 'x';
    badPacket[3] = 'x';
    auto pw = seal::utils::utf8ToSecureWide("golden-master-pw");
    EXPECT_THROW(
        (void)seal::Cryptography::decryptPacket(std::span<const unsigned char>(badPacket), pw),
        std::runtime_error);
}

TEST_F(CryptoTest, NewPacketsCarrySelfDescribingHeaderAndRoundtrip)
{
    auto pw = make_secure_string("pw");
    const std::string msg = "payload";
    auto packet = seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(msg.data()),
                                       msg.size()),
        pw);
    ASSERT_GE(packet.size(), 8u);
    EXPECT_EQ(std::memcmp(packet.data(), "seal", 4), 0);
    EXPECT_EQ(packet[4], 0x01);  // alg = scrypt
    EXPECT_EQ(packet[5], 16);    // log2N
    EXPECT_EQ(packet[6], 8);     // r
    EXPECT_EQ(packet[7], 1);     // p
    auto plain = seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), pw);
    EXPECT_EQ(std::string(plain.begin(), plain.end()), msg);
    seal::Cryptography::verifyPacket(std::span<const unsigned char>(packet), pw);
}

TEST_F(CryptoTest, TamperedHeaderFailsAuthentication)
{
    auto pw = make_secure_string("pw");
    const std::string msg = "tamper";
    auto packet = seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(msg.data()),
                                       msg.size()),
        pw);
    // Flip the KDF parameter bytes (5..7) one at a time: every flip must fail
    // either header validation (out-of-cap) or GCM authentication.
    for (size_t i = 5; i < 8; ++i)
    {
        auto bad = packet;
        bad[i] ^= 0x01;
        EXPECT_THROW(
            (void)seal::Cryptography::decryptPacket(std::span<const unsigned char>(bad), pw),
            std::runtime_error)
            << "byte " << i;
    }
}

TEST_F(CryptoTest, OverCapKdfParamsRejectedBeforeKeyDerivation)
{
    auto pw = make_secure_string("pw");
    const std::string msg = "caps";
    auto packet = seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(msg.data()),
                                       msg.size()),
        pw);
    auto bad = packet;
    bad[5] = 31;  // log2N=31 -> 2 GiB-scale scrypt; must be refused by caps
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_THROW((void)seal::Cryptography::decryptPacket(std::span<const unsigned char>(bad), pw),
                 std::runtime_error);
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    // Cap rejection happens before scrypt: it must be near-instant.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 50);
}

TEST_F(CryptoTest, UnknownMagicRejected)
{
    auto pw = make_secure_string("pw");
    std::vector<unsigned char> junk(64, 0xAB);
    EXPECT_THROW((void)seal::Cryptography::decryptPacket(std::span<const unsigned char>(junk), pw),
                 std::runtime_error);
}

TEST(ScopedDpapiUnprotectTest, OkReflectsUnprotectSuccess)
{
    using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;
    SecureWide pw;
    for (const wchar_t* p = L"hunter2"; *p; ++p)
    {
        pw.push_back(*p);
    }
    seal::DPAPIGuard<SecureWide> guard(&pw);  // ctor protects the buffer
    {
        seal::ScopedDpapiUnprotect<seal::DPAPIGuard<SecureWide>> scope(guard);
        EXPECT_TRUE(scope.ok());  // a freshly-protected buffer unprotects successfully
    }
}
