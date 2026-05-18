#include "test_helpers.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::string_literals;

class EncryptDecryptLineTest : public ::testing::Test
{
};

TEST_F(EncryptDecryptLineTest, BasicRoundtrip)
{
    auto password = make_secure_string("test_password_123");
    std::string plaintext = "Hello, World!";

    // Encrypt
    std::string hexOutput = seal::FileOperations::encryptLine(plaintext, password);

    EXPECT_FALSE(hexOutput.empty());
    EXPECT_EQ(hexOutput.size() % 2, 0u);

    auto decrypted = seal::FileOperations::decryptLine(hexOutput, password);
    std::string decryptedStr(decrypted.data(), decrypted.size());

    EXPECT_EQ(decryptedStr, plaintext);
}

TEST_F(EncryptDecryptLineTest, EmptyString)
{
    auto password = make_secure_string("test_password");
    std::string plaintext = "";

    std::string hexOutput = seal::FileOperations::encryptLine(plaintext, password);

    EXPECT_FALSE(hexOutput.empty());

    auto decrypted = seal::FileOperations::decryptLine(hexOutput, password);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(EncryptDecryptLineTest, InvalidHexThrows)
{
    auto password = make_secure_string("test_password");
    std::string invalidHex = "not_valid_hex";

    EXPECT_THROW(seal::FileOperations::decryptLine(invalidHex, password), std::runtime_error);
}

TEST_F(EncryptDecryptLineTest, HexWithSpaces)
{
    auto password = make_secure_string("test_password");
    std::string plaintext = "Test message";

    std::string hexOutput = seal::FileOperations::encryptLine(plaintext, password);

    // Re-format with a space between every byte.
    std::string hexWithSpaces;
    for (size_t i = 0; i < hexOutput.size(); i += 2)
    {
        if (i > 0)
            hexWithSpaces += " ";
        hexWithSpaces += hexOutput.substr(i, 2);
    }

    auto decrypted = seal::FileOperations::decryptLine(hexWithSpaces, password);
    std::string decryptedStr(decrypted.data(), decrypted.size());

    EXPECT_EQ(decryptedStr, plaintext);
}

TEST_F(EncryptDecryptLineTest, WrongPasswordThrows)
{
    auto correctPassword = make_secure_string("correct_password");
    auto wrongPassword = make_secure_string("wrong_password");
    std::string plaintext = "Secret message";

    std::string hexOutput = seal::FileOperations::encryptLine(plaintext, correctPassword);

    EXPECT_THROW(seal::FileOperations::decryptLine(hexOutput, wrongPassword), std::runtime_error);
}

TEST_F(EncryptDecryptLineTest, UnicodeText)
{
    auto password = make_secure_string("test_password");
    std::string unicodeText = "Hello 世界 🌍 Привет";

    std::string hexOutput = seal::FileOperations::encryptLine(unicodeText, password);

    auto decrypted = seal::FileOperations::decryptLine(hexOutput, password);
    std::string decryptedStr(decrypted.data(), decrypted.size());

    EXPECT_EQ(decryptedStr, unicodeText);
}

TEST_F(EncryptDecryptLineTest, LongText)
{
    auto password = make_secure_string("test_password");
    std::string longText(10000, 'A');  // 10KB of 'A'

    std::string hexOutput = seal::FileOperations::encryptLine(longText, password);

    auto decrypted = seal::FileOperations::decryptLine(hexOutput, password);
    std::string decryptedStr(decrypted.data(), decrypted.size());

    EXPECT_EQ(decryptedStr, longText);
}

class FileOperationsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_TestDir = std::filesystem::temp_directory_path() / "lockr_tests";
        std::filesystem::create_directories(m_TestDir);
    }

    void TearDown() override
    {
        if (std::filesystem::exists(m_TestDir))
        {
            std::filesystem::remove_all(m_TestDir);
        }
    }

    std::filesystem::path m_TestDir;

    std::filesystem::path GetTestFile(const std::string& name) { return m_TestDir / name; }
};

TEST_F(FileOperationsTest, EncryptDecryptFileRoundtrip)
{
    auto tempFile = GetTestFile("test_roundtrip.tmp");

    std::string originalContent = "This is test file content\nLine 2\nLine 3";
    {
        std::ofstream out(tempFile, std::ios::binary);
        out << originalContent;
    }

    auto password = make_secure_string("test_password");
    auto encFile = GetTestFile("test_roundtrip.tmp.seal");

    bool encryptSuccess =
        seal::FileOperations::encryptFileTo(tempFile.string(), encFile.string(), password);
    EXPECT_TRUE(encryptSuccess);

    // Encrypted bytes differ from the plaintext.
    std::ifstream in(encFile, std::ios::binary);
    std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(in)),
                                             std::istreambuf_iterator<char>());
    in.close();

    EXPECT_FALSE(encryptedData.empty());
    std::string encryptedStr(encryptedData.begin(), encryptedData.end());
    EXPECT_NE(encryptedStr, originalContent);

    auto decFile = GetTestFile("test_roundtrip_dec.tmp");
    bool decryptSuccess =
        seal::FileOperations::decryptFileTo(encFile.string(), decFile.string(), password);
    EXPECT_TRUE(decryptSuccess);

    std::ifstream in2(decFile, std::ios::binary);
    std::string decryptedContent((std::istreambuf_iterator<char>(in2)),
                                 std::istreambuf_iterator<char>());
    in2.close();

    EXPECT_EQ(decryptedContent, originalContent);
}

TEST_F(FileOperationsTest, EncryptNonExistentFileFails)
{
    auto password = make_secure_string("test_password");
    std::string nonExistent = "nonexistent_file_12345.tmp";
    std::string dest = nonExistent + ".seal";

    bool success = seal::FileOperations::encryptFileTo(nonExistent, dest, password);

    EXPECT_FALSE(success);
}

TEST_F(FileOperationsTest, DecryptWrongPasswordFails)
{
    auto tempFile = GetTestFile("test_wrong_pwd.tmp");

    std::string originalContent = "Test content";
    {
        std::ofstream out(tempFile, std::ios::binary);
        out << originalContent;
    }

    auto correctPassword = make_secure_string("correct_password");
    auto wrongPassword = make_secure_string("wrong_password");
    auto encFile = GetTestFile("test_wrong_pwd.tmp.seal");
    auto decFile = GetTestFile("test_wrong_pwd_dec.tmp");

    bool encryptSuccess =
        seal::FileOperations::encryptFileTo(tempFile.string(), encFile.string(), correctPassword);
    EXPECT_TRUE(encryptSuccess);

    bool decryptSuccess =
        seal::FileOperations::decryptFileTo(encFile.string(), decFile.string(), wrongPassword);
    EXPECT_FALSE(decryptSuccess);
}

TEST_F(FileOperationsTest, EncryptEmptyFile)
{
    auto tempFile = GetTestFile("test_empty.tmp");

    {
        std::ofstream out(tempFile);  // empty
    }

    auto password = make_secure_string("test_password");
    auto encFile = GetTestFile("test_empty.tmp.seal");
    auto decFile = GetTestFile("test_empty_dec.tmp");

    bool encryptSuccess =
        seal::FileOperations::encryptFileTo(tempFile.string(), encFile.string(), password);
    EXPECT_TRUE(encryptSuccess);

    bool decryptSuccess =
        seal::FileOperations::decryptFileTo(encFile.string(), decFile.string(), password);
    EXPECT_TRUE(decryptSuccess);

    std::ifstream in(decFile, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    EXPECT_TRUE(content.empty());
}

TEST_F(FileOperationsTest, DecryptCorruptedFileFails)
{
    auto tempFile = GetTestFile("test_corrupt.tmp");

    std::string originalContent = "Test content";
    {
        std::ofstream out(tempFile, std::ios::binary);
        out << originalContent;
    }

    auto password = make_secure_string("test_password");
    auto encFile = GetTestFile("test_corrupt.tmp.seal");
    auto decFile = GetTestFile("test_corrupt_dec.tmp");

    bool encryptSuccess =
        seal::FileOperations::encryptFileTo(tempFile.string(), encFile.string(), password);
    EXPECT_TRUE(encryptSuccess);

    // Flip a single byte at the midpoint of the ciphertext.
    {
        std::fstream file(encFile, std::ios::binary | std::ios::in | std::ios::out);
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(size / 2, std::ios::beg);
        char byte = 0;
        file.read(&byte, 1);
        byte ^= 0xFF;
        file.seekp(size / 2, std::ios::beg);
        file.write(&byte, 1);
        file.close();
    }

    bool decryptSuccess =
        seal::FileOperations::decryptFileTo(encFile.string(), decFile.string(), password);
    EXPECT_FALSE(decryptSuccess);
}

TEST_F(FileOperationsTest, ParseTriplesRejectsEmptyFields)
{
    std::vector<seal::secure_triplet16_t> out;

    EXPECT_FALSE(seal::FileOperations::parseTriples(":user:pass", out));
    EXPECT_TRUE(out.empty());

    EXPECT_FALSE(seal::FileOperations::parseTriples("svc::pass", out));
    EXPECT_TRUE(out.empty());

    EXPECT_FALSE(seal::FileOperations::parseTriples("svc:user:", out));
    EXPECT_TRUE(out.empty());
}

TEST_F(FileOperationsTest, ParseTriplesTrimsServiceAndUser)
{
    std::vector<seal::secure_triplet16_t> out;

    EXPECT_TRUE(seal::FileOperations::parseTriples(" svc : user :pass", out));
    ASSERT_EQ(out.size(), 1U);
    EXPECT_EQ(seal::FileOperations::tripleToUtf8(out[0]), "svc:user:pass");
}
