#pragma once

#include "Clipboard.h"
#include "Console.h"
#include "Cryptography.h"
#include "Utils.h"

#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>

namespace seal
{

/**
 * @class FileOperations
 * @brief Static utility class for file-level encryption, decryption,
 *        batch processing, and stream I/O operations.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FileOperations
 *
 * Wraps every high-level I/O path that moves data between disk (or
 * stdin/stdout) and the AES-256-GCM crypto core. All methods are
 * stateless and static; the class exists only to group related
 * operations under a single namespace-like scope.
 *
 * ## :material-file-lock: Single-File Operations
 *
 * encryptFileInPlace() / decryptFileInPlace() read a file into memory,
 * encrypt or decrypt the contents via `Cryptography::encryptPacket` /
 * `Cryptography::decryptPacket`, and overwrite the original file. encryptLine() / decryptLine() do
 * the same for hex-encoded text strings, returning the result rather than writing to disk.
 *
 * ## :material-folder-lock: Directory & Batch Processing
 *
 * processDirectory() walks a directory tree with `FindFirstFileA`,
 * encrypting or decrypting each file based on its `.seal` extension
 * and renaming in place. processBatch() dispatches mixed CLI input
 * (file paths, hex tokens, raw plaintext) through the appropriate
 * encrypt/decrypt path, with support for masked credential display
 * in censored mode via MaskedCredentialView.
 *
 * ## :material-pipe: Stream Mode
 *
 * streamEncrypt() / streamDecrypt() provide stdin-to-stdout binary
 * piping for shell integration (`seal -e < input > output.seal`).
 *
 * ## :material-format-list-group: Triple Helpers
 *
 * parseTriples() splits `service:username:password` text into secure
 * UTF-16 triplets. tripleToUtf8() serialises a triplet back into a
 * single UTF-8 line. These are used by processBatch() to aggregate
 * decrypted credentials for the masked interactive view.
 */
class FileOperations
{
public:
    FileOperations() = delete;
    FileOperations(const FileOperations&) = delete;
    FileOperations& operator=(const FileOperations&) = delete;

    /**
     * @brief Encrypt a file in place, overwriting the original contents.
     *
     * Reads the entire file into memory, encrypts with AES-256-GCM via
     * `Cryptography::encryptPacket`, then truncates and rewrites the file with the
     * encrypted packet. The plaintext buffer is securely wiped after use.
     *
     * @tparam SecurePwd Secure password container.
     * @param path Filesystem path to the file.
     * @param pwd  Master password for key derivation.
     * @return `true` on success, `false` if the file cannot be opened/written.
     */
    template <class SecurePwd>
    static bool encryptFileInPlace(const std::string& path, const SecurePwd& pwd);

    /**
     * @brief Decrypt a file in place, overwriting the encrypted contents.
     *
     * Reads the encrypted packet, decrypts via `Cryptography::decryptPacket`, then
     * truncates and rewrites with the recovered plaintext. On authentication
     * failure (wrong password or corrupted data) the file is left unchanged.
     *
     * @tparam SecurePwd Secure password container.
     * @param path Filesystem path to the encrypted file.
     * @param pwd  Master password for key derivation.
     * @return `true` on success, `false` on I/O or authentication error.
     */
    template <class SecurePwd>
    static bool decryptFileInPlace(const std::string& path, const SecurePwd& pwd);

    /**
     * @brief Encrypt a UTF-8 string and return the result as a hex string.
     *
     * @tparam SecurePwd Secure password container.
     * @param s   Plaintext string to encrypt.
     * @param pwd Master password for key derivation.
     * @return Hex-encoded encrypted packet.
     */
    template <class SecurePwd>
    [[nodiscard]] static std::string encryptLine(const std::string& s, const SecurePwd& pwd);

    /**
     * @brief Decrypt a hex-encoded packet back to a secure plaintext string.
     *
     * Strips whitespace from the hex input, decodes to binary, then decrypts.
     *
     * @tparam SecurePwd Secure password container.
     * @param rawHex Hex-encoded encrypted packet (spaces allowed).
     * @param pwd    Master password for key derivation.
     * @return Decrypted plaintext in a secure (locked-page) string.
     *
     * @throw std::runtime_error on invalid hex or authentication failure.
     */
    template <class SecurePwd>
    [[nodiscard]] static seal::secure_string<seal::locked_allocator<char>> decryptLine(
        const std::string& rawHex, const SecurePwd& pwd);

    /**
     * @brief Compute the serialized wide-character length of a triple as `s:u:p`.
     * @tparam A Locked allocator type for `wchar_t`.
     * @param t The triple to measure.
     * @return Total wide-character count including the two `:` separators.
     */
    template <class A>
    static size_t tripleLen(const seal::secure_triplet16<A>& t)
    {
        return t.primary.size() + 1 + t.secondary.size() + 1 + t.tertiary.size();
    }

    /**
     * @brief Convert a UTF-16 triple to a single UTF-8 line `service:username:password`.
     * @param t The secure triple to serialize.
     * @return UTF-8 encoded string in regular heap memory.
     * @warning The returned string is **not** in locked memory.
     */
    static std::string tripleToUtf8(const seal::secure_triplet16_t& t);

    /**
     * @brief Parse one or more `service:username:password` items from plain text.
     *
     * Splits on `,` or newline boundaries; trims per-item whitespace;
     * enforces exactly two colons per item.
     *
     * @tparam A Locked allocator for `wchar_t`.
     * @param plain Narrow plain text input (UTF-8; converted to UTF-16
     *              via `MultiByteToWideChar`).
     * @param out   Destination vector of secure UTF-16 triplets.
     * @return `true` on success (non-empty result with only well-formed items).
     */
    template <class A>
    static bool parseTriples(std::string_view plain, std::vector<seal::secure_triplet16<A>>& out);

    /**
     * @brief Encrypt/decrypt all files in a directory tree.
     *
     * Walks the directory with `FindFirstFileA`, skipping `.exe` and the
     * `seal` binary itself. Each file is encrypted or decrypted based on
     * its `.seal` extension and renamed in place after successful I/O.
     * Subdirectories are processed in parallel via `std::async`
     * (concurrency is bounded by the thread pool to `std::thread::hardware_concurrency()`).
     *
     * @tparam SecurePwd Secure password container.
     * @param dir      Root directory path.
     * @param password Master password for key derivation.
     * @param recurse  Recurse into subdirectories when `true`.
     * @return `true` if all processed files succeeded.
     */
    template <class SecurePwd>
    static bool processDirectory(const std::string& dir,
                                 const SecurePwd& password,
                                 bool recurse = true);

    /**
     * @brief Process a single file path or convenience token.
     *
     * - `.` expands to the current directory (recursive).
     * - Directories delegate to processDirectory().
     * - Regular files: encrypt to `<name>.seal` or decrypt based on extension.
     * - Skips `.exe` and `seal`.
     *
     * @tparam SecurePwd Secure password container.
     * @param raw      Raw path string (may be quoted).
     * @param password Master password for key derivation.
     * @return `true` if the path was recognized and processed successfully.
     */
    template <class SecurePwd>
    static bool processFilePath(const std::string& raw, const SecurePwd& password);

    /**
     * @brief Batch dispatcher for mixed CLI input.
     *
     * For each input line:
     * - File paths are encrypted/decrypted/renamed via processFilePath().
     * - Hex tokens are decrypted; if they contain triples, they are
     *   aggregated for the masked interactive view; otherwise the plaintext
     *   is copied to the clipboard with a TTL scrub.
     * - Other text is encrypted and the hex is printed to stdout.
     *
     * In censored mode (`uncensored == false`), decrypted plaintext is
     * never printed: triples go to MaskedCredentialView and non-triples
     * are echoed as `*` characters.
     *
     * @tparam SecurePwd Secure password container.
     * @param lines      Input lines to process.
     * @param uncensored Print plaintext when `true`, mask when `false`.
     * @param password   Master password for key derivation.
     */
    template <class SecurePwd>
    static void processBatch(const std::vector<std::string>& lines,
                             bool uncensored,
                             const SecurePwd& password);

    /**
     * @brief Stream encryption: read from stdin, encrypt, write binary to stdout.
     *
     * Reads all data from `std::cin`, encrypts via AES-256-GCM, and writes
     * the binary packet to `std::cout`. Use with shell redirection:
     * `seal -e < input.txt > output.seal`
     *
     * @tparam SecurePwd Secure password container.
     * @param password Master password for key derivation.
     * @return `true` on success, `false` on error (errors go to stderr).
     */
    template <class SecurePwd>
    static bool streamEncrypt(const SecurePwd& password);

    /**
     * @brief Stream decryption: read binary from stdin, decrypt, write to stdout.
     *
     * Reads a binary encrypted packet from `std::cin`, decrypts via
     * AES-256-GCM, and writes the plaintext to `std::cout`. Use with
     * shell redirection: `seal -d < input.seal > output.txt`
     *
     * @tparam SecurePwd Secure password container.
     * @param password Master password for key derivation.
     * @return `true` on success, `false` on error (errors go to stderr).
     */
    template <class SecurePwd>
    static bool streamDecrypt(const SecurePwd& password);

    /**
     * @brief Securely delete a file by overwriting with random data then removing.
     *
     * Performs three overwrite passes (random, zeros, random) to prevent
     * data recovery, then deletes the file.
     *
     * @param path Filesystem path to the file to shred.
     * @return `true` on success, `false` on error.
     */
    static bool shredFile(const std::string& path);

    /**
     * @brief Compute the SHA-256 hash of a file.
     *
     * Reads the file in 64KB chunks and produces a hex-encoded hash string.
     *
     * @param path Filesystem path to the file.
     * @return Hex-encoded SHA-256 hash, or empty string on error.
     */
    [[nodiscard]] static std::string hashFile(const std::string& path);
};

}  // namespace seal
