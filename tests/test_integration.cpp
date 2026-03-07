/**
 * @file test_integration.cpp
 * @brief Integration tests for high-level functions (encryptLine, decryptLine, file operations)
 * @author seal Contributors
 * @date 2024
 */

#include "test_helpers.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::string_literals;

// Test suite for encryptLine/decryptLine
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
    EXPECT_EQ(hexOutput.size() % 2, 0u);  // Hex should be even length

    // Decrypt
    auto decrypted = seal::FileOperations::decryptLine(hexOutput, password);
    std::string decryptedStr(decrypted.data(), decrypted.size());

    EXPECT_EQ(decryptedStr, plaintext);
}

TEST_F(EncryptDecryptLineTest, EmptyString)
{
    auto password = make_secure_string("test_password");
    std::string plaintext = "";

    std::string hexOutput = seal::FileOperations::encryptLine(plaintext, password);

    EXPECT_FALSE(hexOutput.empty());  // Should still produce hex output

    // Should decrypt to empty
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

    // Encrypt
    std::string hexOutput = seal::FileOperations::encryptLine(plaintext, password);

    // Add spaces to hex
    std::string hexWithSpaces;
    for (size_t i = 0; i < hexOutput.size(); i += 2)
    {
        if (i > 0)
            hexWithSpaces += " ";
        hexWithSpaces += hexOutput.substr(i, 2);
    }

    // Should handle spaces correctly
    auto decrypted = seal::FileOperations::decryptLine(hexWithSpaces, password);
    std::string decryptedStr(decrypted.data(), decrypted.size());

    EXPECT_EQ(decryptedStr, plaintext);
}

TEST_F(EncryptDecryptLineTest, WrongPasswordThrows)
{
    auto correctPassword = make_secure_string("correct_password");
    auto wrongPassword = make_secure_string("wrong_password");
    std::string plaintext = "Secret message";

    // Encrypt with correct password
    std::string hexOutput = seal::FileOperations::encryptLine(plaintext, correctPassword);

    // Try to decrypt with wrong password
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

// Test suite for file operations
class FileOperationsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Create temporary directory for test files
        m_TestDir = std::filesystem::temp_directory_path() / "lockr_tests";
        std::filesystem::create_directories(m_TestDir);
    }

    void TearDown() override
    {
        // Clean up test files
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
    // Create temporary file
    auto tempFile = GetTestFile("test_roundtrip.tmp");

    // Write test data
    std::string originalContent = "This is test file content\nLine 2\nLine 3";
    {
        std::ofstream out(tempFile, std::ios::binary);
        out << originalContent;
    }

    auto password = make_secure_string("test_password");

    // Encrypt file
    bool encryptSuccess =
        seal::FileOperations::encryptFileInPlace(tempFile.string().c_str(), password);
    EXPECT_TRUE(encryptSuccess);

    // Verify file was encrypted (content should be different)
    std::ifstream in(tempFile, std::ios::binary);
    std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(in)),
                                             std::istreambuf_iterator<char>());
    in.close();

    EXPECT_FALSE(encryptedData.empty());
    std::string encryptedStr(encryptedData.begin(), encryptedData.end());
    EXPECT_NE(encryptedStr, originalContent);

    // Decrypt file
    bool decryptSuccess =
        seal::FileOperations::decryptFileInPlace(tempFile.string().c_str(), password);
    EXPECT_TRUE(decryptSuccess);

    // Verify file was decrypted correctly
    std::ifstream in2(tempFile, std::ios::binary);
    std::string decryptedContent((std::istreambuf_iterator<char>(in2)),
                                 std::istreambuf_iterator<char>());
    in2.close();

    EXPECT_EQ(decryptedContent, originalContent);
}

TEST_F(FileOperationsTest, EncryptNonExistentFileFails)
{
    auto password = make_secure_string("test_password");
    std::string nonExistent = "nonexistent_file_12345.tmp";

    bool success = seal::FileOperations::encryptFileInPlace(nonExistent.c_str(), password);

    EXPECT_FALSE(success);
}

TEST_F(FileOperationsTest, DecryptWrongPasswordFails)
{
    // Create temporary file
    auto tempFile = GetTestFile("test_wrong_pwd.tmp");

    std::string originalContent = "Test content";
    {
        std::ofstream out(tempFile, std::ios::binary);
        out << originalContent;
    }

    auto correctPassword = make_secure_string("correct_password");
    auto wrongPassword = make_secure_string("wrong_password");

    // Encrypt with correct password
    bool encryptSuccess =
        seal::FileOperations::encryptFileInPlace(tempFile.string().c_str(), correctPassword);
    EXPECT_TRUE(encryptSuccess);

    // Try to decrypt with wrong password
    bool decryptSuccess =
        seal::FileOperations::decryptFileInPlace(tempFile.string().c_str(), wrongPassword);
    EXPECT_FALSE(decryptSuccess);
}

TEST_F(FileOperationsTest, EncryptEmptyFile)
{
    // Create temporary empty file
    auto tempFile = GetTestFile("test_empty.tmp");

    {
        std::ofstream out(tempFile);
        // File is empty
    }

    auto password = make_secure_string("test_password");

    // Encrypt empty file
    bool encryptSuccess =
        seal::FileOperations::encryptFileInPlace(tempFile.string().c_str(), password);
    EXPECT_TRUE(encryptSuccess);

    // Decrypt
    bool decryptSuccess =
        seal::FileOperations::decryptFileInPlace(tempFile.string().c_str(), password);
    EXPECT_TRUE(decryptSuccess);

    // Verify file is still empty
    std::ifstream in(tempFile, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    EXPECT_TRUE(content.empty());
}

TEST_F(FileOperationsTest, DecryptCorruptedFileFails)
{
    // Create temporary file
    auto tempFile = GetTestFile("test_corrupt.tmp");

    std::string originalContent = "Test content";
    {
        std::ofstream out(tempFile, std::ios::binary);
        out << originalContent;
    }

    auto password = make_secure_string("test_password");

    // Encrypt file
    bool encryptSuccess =
        seal::FileOperations::encryptFileInPlace(tempFile.string().c_str(), password);
    EXPECT_TRUE(encryptSuccess);

    // Corrupt the encrypted file
    {
        std::fstream file(tempFile, std::ios::binary | std::ios::in | std::ios::out);
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(size / 2, std::ios::beg);
        char byte = 0;
        file.read(&byte, 1);
        byte ^= 0xFF;  // Flip bits
        file.seekp(size / 2, std::ios::beg);
        file.write(&byte, 1);
        file.close();
    }

    // Try to decrypt corrupted file
    bool decryptSuccess =
        seal::FileOperations::decryptFileInPlace(tempFile.string().c_str(), password);
    EXPECT_FALSE(decryptSuccess);
}
