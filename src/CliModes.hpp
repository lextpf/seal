#pragma once

#include <string>

namespace seal
{

/// @brief Generate a random password of the given length and copy to clipboard.
/// @param length Desired password length (clamped to 8..128).
/// @return 0 on success.
int HandleGenMode(int length);

/// @brief Securely shred (overwrite + delete) a file.
/// @param path Filesystem path to the file to shred.
/// @return 0 on success, 1 if the file is not found or shredding fails.
int HandleShredMode(const std::string& path);

/// @brief Compute and print the SHA-256 hash of a file.
/// @param path Filesystem path to the file to hash.
/// @return 0 on success, 1 if the file is not found or hashing fails.
int HandleHashMode(const std::string& path);

/// @brief Verify a password against an encrypted file.
/// @param path Filesystem path to the encrypted file.
/// @return 0 if the password is correct, 1 on wrong password or error.
int HandleVerifyMode(const std::string& path);

/// @brief Clear the clipboard and console buffer.
/// @return 0 on success.
int HandleWipeMode();

/// @brief Encrypt a file to a new destination.
/// @param inputPath  Source file to encrypt.
/// @param outputPath Destination path (default: inputPath + ".seal").
/// @return 0 on success, 1 on error.
int HandleFileEncrypt(const std::string& inputPath, const std::string& outputPath);

/// @brief Decrypt a file to a new destination.
/// @param inputPath  Encrypted source file.
/// @param outputPath Destination path (default: strip ".seal" extension).
/// @return 0 on success, 1 on error.
int HandleFileDecrypt(const std::string& inputPath, const std::string& outputPath);

/// @brief Encrypt or decrypt a string with hex/base64 auto-detection.
///
/// In encrypt mode, outputs both hex and base64 representations.
/// In decrypt mode, auto-detects the input format: hex is tried first
/// (even length + all hex digits), then base64.
///
/// @param encryptMode `true` to encrypt plaintext to hex/base64,
///                    `false` to decrypt hex or base64 to plaintext.
/// @param inlineData  Input string (if empty, reads from stdin).
/// @return 0 on success, 1 on error.
int HandleStringMode(bool encryptMode, const std::string& inlineData);

}  // namespace seal
