#pragma once

#include "Cryptography.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace seal
{

/**
 * @class FileOperations
 * @brief Static entry points for file, directory, batch and stream crypto.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup IO_FileOperations
 *
 * Groups every high-level path that moves data between disk (or stdin/stdout)
 * and the AES-256-GCM core. The class holds no instance state and cannot be
 * constructed. processDirectory() is the one exception: its leaf-file tasks run
 * on a worker pool shared by every caller in the process.
 *
 * ## :material-file-lock: Single-file operations
 *
 * encryptFileTo() / decryptFileTo() transform a file into a new destination
 * through `Cryptography::encryptPacket` / `Cryptography::decryptPacket`, and
 * re-dispatch to encryptFileStreaming() / decryptFileStreaming() above
 * `cfg::FILE_CHUNK` (1 MiB). encryptLine() / decryptLine() do the same for
 * hex-encoded text and return the result instead of writing to disk.
 *
 * @par Atomic write sequence
 * Every disk-writing path commits through temp-then-rename, so a crash cannot
 * leave a half-written destination:
 * @verbatim
 *   src  (read-only; never modified by encrypt/decrypt)
 *     |
 *     v  transform (AES-256-GCM)
 *   <dst>.tmp  --- flush, close, reopen, FlushFileBuffers ---> bytes durable
 *     |
 *     v  MoveFileEx(<dst>.tmp -> <dst>, MOVEFILE_REPLACE_EXISTING)
 *   <dst>  (replaced atomically; on crash <dst> is fully old or fully new)
 * @endverbatim
 * The FlushFileBuffers step is best-effort: its result is not checked, so the
 * rename proceeds and the call still returns `true` when the durable flush
 * failed. Only the stream-level write and flush failures are reported as
 * `false`.
 *
 * The staging name is always `<dstPath>.tmp` and is never randomised, so a
 * caller must treat that name as reserved. It is deleted on every `false` path
 * that created it; an escaping exception leaves it behind.
 *
 * ## :material-folder-lock: Directory and batch processing
 *
 * processDirectory() walks a tree with `FindFirstFileA` and transforms each
 * file by its `.seal` extension. Once the destination is committed the source
 * is removed with `DeleteFileA`, not shredded. processBatch() dispatches mixed
 * CLI input (paths, hex tokens, raw plaintext) and, in censored mode, presents
 * the result through MaskedCredentialView.
 *
 * ## :material-pipe: Stream mode
 *
 * streamEncrypt() / streamDecrypt() pipe binary data between `std::cin` and
 * `std::cout` for shell integration. No CLI mode routes here: `-e` /
 * `--text-encrypt` and `-d` / `--text-decrypt` select the hex/Base64 text mode,
 * which is a separate path.
 *
 * ## :material-format-list-group: Triple helpers
 *
 * parseTriples() splits `service:username:password` text into secure UTF-16
 * triplets and serves both processBatch() display modes. tripleToUtf8()
 * serialises a triplet back into one UTF-8 line and is reached only from the
 * uncensored stdout echo, never from the masked view. tripleLen() measures the
 * same line in `wchar_t` units and has no in-tree caller.
 *
 * @par Failure reporting
 * Progress and errors print to `std::cout` / `std::cerr`.
 * - encryptFileTo(), encryptFileStreaming(): a `std::runtime_error` from the
 *   OpenSSL layer propagates, and `false` means an I/O failure only.
 * - decryptFileTo(), decryptFileStreaming(), streamEncrypt(), streamDecrypt():
 *   every `std::exception` becomes `false`.
 * - encryptLine() and decryptLine() return a value, so they throw instead of
 *   reporting `false`.
 */
class FileOperations
{
public:
    FileOperations() = delete;
    FileOperations(const FileOperations&) = delete;
    FileOperations& operator=(const FileOperations&) = delete;

    /**
     * @brief Encrypt a file to a new destination without modifying the source.
     *
     * Writes the packet atomically to @p dstPath through a `<dstPath>.tmp`
     * staging file. @p srcPath is never modified; delete it only after this
     * returns `true`. An existing @p dstPath is replaced without warning.
     *
     * A source larger than `cfg::FILE_CHUNK` (1 MiB) is forwarded to
     * @ref encryptFileStreaming, so only smaller files are read whole into
     * memory. A size that cannot be queried counts as small and stays on the
     * single-shot path.
     *
     * @tparam SecurePwd Secure password container.
     * @param srcPath Source file; left unmodified.
     * @param dstPath Destination for the encrypted output.
     * @param pwd     Master password for key derivation.
     * @return `true` on success, `false` when the source cannot be opened or a
     *         write, flush or rename fails.
     *
     * @throw std::runtime_error propagated from the OpenSSL layer; an
     *        encryption failure is not reported as `false`. On the in-memory
     *        path it is thrown before the staging file exists, so nothing is
     *        left behind. A source above `cfg::FILE_CHUNK` runs
     *        @ref encryptFileStreaming, which opens `<dstPath>.tmp` before it
     *        encrypts the payload, so an exception can leave that file on disk
     *        for the caller to remove.
     */
    template <secure_password SecurePwd>
    static bool encryptFileTo(const std::string& srcPath,
                              const std::string& dstPath,
                              const SecurePwd& pwd);

    /**
     * @brief Decrypt a file to a new destination without modifying the source.
     *
     * Writes the plaintext atomically to @p dstPath through a `<dstPath>.tmp`
     * staging file. @p srcPath is never modified. Authentication completes
     * before the staging file is created, so a wrong password or a tampered
     * packet leaves no output file at all.
     *
     * A source larger than `cfg::FILE_CHUNK` (1 MiB) plus the 52-byte framing
     * overhead is forwarded to @ref decryptFileStreaming. A size that cannot be
     * queried counts as small.
     *
     * @tparam SecurePwd Secure password container.
     * @param srcPath Encrypted source file; left unmodified.
     * @param dstPath Destination for the decrypted output.
     * @param pwd     Master password for key derivation.
     * @return `true` on success, `false` on I/O failure, a malformed packet, or
     *         authentication failure. Every `std::exception` from the crypto
     *         layer is caught, logged to `std::cerr` and reported as `false`.
     */
    template <secure_password SecurePwd>
    static bool decryptFileTo(const std::string& srcPath,
                              const std::string& dstPath,
                              const SecurePwd& pwd);

    /**
     * @brief Encrypt a UTF-8 string and return the result as a hex string.
     *
     * The bytes of @p s are encrypted verbatim: no terminator is added and the
     * content need not be valid UTF-8. Both the argument and the returned hex
     * live in ordinary heap memory, so the caller must wipe them.
     *
     * @tparam SecurePwd Secure password container.
     * @param s   Plaintext to encrypt.
     * @param pwd Master password for key derivation.
     * @return Lowercase hex encoding of the framed packet. Framing adds 52
     *         bytes, so the result is `2 * s.size() + 104` characters long.
     *
     * @throw std::runtime_error propagated from the OpenSSL layer.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static std::string encryptLine(const std::string& s, const SecurePwd& pwd);

    /**
     * @brief Decrypt a hex-encoded packet back to a secure plaintext string.
     *
     * Strips every whitespace character, decodes the hex, then decrypts. Hex
     * case is not significant. The result holds raw bytes and may contain
     * embedded NUL characters, so read it with `.size()`, never as a C string.
     *
     * @tparam SecurePwd Secure password container.
     * @param rawHex Hex-encoded packet. Spaces, tabs and line breaks anywhere
     *               in the token are ignored.
     * @param pwd    Master password for key derivation.
     * @return Decrypted plaintext in a locked-page string. The intermediate
     *         plaintext buffer is wiped before returning.
     *
     * @throw std::runtime_error on odd-length or non-hex input, a malformed
     *        packet, out-of-cap KDF parameters, or authentication failure.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static seal::secure_string<seal::locked_allocator<char>> decryptLine(
        const std::string& rawHex, const SecurePwd& pwd);

    /**
     * @brief Encrypt a file to a new destination using chunked streaming I/O.
     *
     * Reads the source in `cfg::FILE_CHUNK` (1 MiB) blocks and feeds them to
     * `EVP_EncryptUpdate`, so peak memory is two chunks instead of the whole
     * file. The wire format matches `encryptPacket`
     * (`AAD | salt | IV | ciphertext | tag`), so every decrypt path reads the
     * output. This function has no size gate of its own: @ref encryptFileTo
     * decides when to come here, and a direct call always streams.
     *
     * Salt and IV are freshly random per call, so encrypting the same source
     * twice yields different ciphertext. Every plaintext chunk is wiped once
     * consumed, and the derived key is wiped before returning.
     *
     * @tparam SecurePwd Secure password container.
     * @param srcPath Source file; left unmodified.
     * @param dstPath Destination for the encrypted output.
     * @param pwd     Master password for key derivation.
     * @return `true` on success, `false` when the source cannot be opened or a
     *         write, flush or rename fails. The `<dstPath>.tmp` staging file is
     *         deleted on every `false` path that created it.
     *
     * @throw std::runtime_error propagated from the OpenSSL layer. A throw
     *        after the staging file opens leaves that file behind.
     */
    template <secure_password SecurePwd>
    static bool encryptFileStreaming(const std::string& srcPath,
                                     const std::string& dstPath,
                                     const SecurePwd& pwd);

    /**
     * @brief Decrypt a file to a new destination using chunked streaming I/O.
     *
     * Reads the ciphertext in `cfg::FILE_CHUNK` (1 MiB) blocks and feeds them
     * to `EVP_DecryptUpdate`. The 8-byte packet header is parsed and
     * cap-validated first, then salt and IV are read, then the GCM tag is read
     * from the last `cfg::TAG_LEN` bytes of the file. This function has no size
     * gate of its own: @ref decryptFileTo decides when to come here, and a
     * direct call always streams.
     *
     * @par Two-pass authentication
     * The source is read twice, so unauthenticated plaintext never reaches the
     * filesystem, at the cost of decrypting the payload twice. The key is
     * derived once and shared by both passes.
     * @verbatim
     *   pass 1  read CT -> EVP_DecryptUpdate -> scratch buffer, wiped at once
     *              |                            (nothing is written to disk)
     *              v  EVP_DecryptFinal_ex against the stored GCM tag
     *           tag bad --------------------> return false, no output file
     *              |
     *              v  re-stat src: last-write time and size unchanged?
     *           changed --------------------> return false, no output file
     *              |
     *   pass 2  re-read CT -> decrypt -> <dst>.tmp -> flush -> rename
     * @endverbatim
     *
     * @tparam SecurePwd Secure password container.
     * @param srcPath Encrypted source file; left unmodified.
     * @param dstPath Destination for the decrypted output.
     * @param pwd     Master password for key derivation.
     * @return `true` on success. `false` when the source cannot be opened or
     *         stated, the header is malformed, the file is shorter than its own
     *         framing, the tag does not verify, the source changed between the
     *         two passes, or a write, flush or rename fails. Every
     *         `std::exception` from the crypto layer is caught and reported as
     *         `false`.
     */
    template <secure_password SecurePwd>
    static bool decryptFileStreaming(const std::string& srcPath,
                                     const std::string& dstPath,
                                     const SecurePwd& pwd);

    /**
     * @brief Compute the serialized wide-character length of a triple as `s:u:p`.
     * @tparam A Locked allocator type for `wchar_t`.
     * @return Wide-character count including the two `:` separators.
     *
     * @note The unit is `wchar_t`, not bytes. @ref tripleToUtf8 can return a
     *       longer string because non-ASCII characters expand to several UTF-8
     *       bytes.
     */
    template <class A>
    static size_t tripleLen(const seal::secure_triplet16<A>& t)
    {
        return t.primary.size() + 1 + t.secondary.size() + 1 + t.tertiary.size();
    }

    /**
     * @brief Convert a UTF-16 triple to a single UTF-8 line `service:username:password`.
     *
     * Empty fields become empty segments, so the result always holds two `:`
     * characters.
     *
     * @param t Secure triple to serialize.
     * @return UTF-8 string in ordinary heap memory.
     *
     * @warning The returned string is not in locked memory. Pass it to
     *          `Cryptography::cleanseString` once it is no longer needed.
     * @note The round trip through @ref parseTriples is not lossless: a field
     *       that itself contains `:` produces a line with more than two
     *       separators, which parseTriples() rejects.
     */
    static std::string tripleToUtf8(const seal::secure_triplet16_t& t);

    /**
     * @brief Parse one or more `service:username:password` items from plain text.
     *
     * `,`, `\n` and `\r` all end an item, so one decrypted blob can carry many
     * credentials. Each item is trimmed at both ends and must hold two `:`
     * characters: fewer is an incomplete triple, more is ambiguous. An item
     * that is empty after trimming is ignored rather than rejected. All three
     * fields must be non-empty.
     *
     * @par Whitespace handling
     * The service and username fields are trimmed a second time, individually.
     * The password field is not: it keeps everything between the second `:` and
     * the end of the trimmed item, so leading and interior spaces stay part of
     * the password.
     *
     * @tparam A Locked allocator for `wchar_t`.
     * @param plain UTF-8 input, converted to UTF-16 with `MultiByteToWideChar`.
     *              Items are sub-views of the caller's buffer, so no extra
     *              narrow copy of the secret is made.
     * @param out   Destination vector of secure UTF-16 triplets. Cleared on
     *              entry and cleared again if any item is rejected, so a
     *              `false` return always leaves it empty.
     * @return `true` when at least one item parsed and every item was
     *         well-formed; `false` when any item is malformed or the input
     *         holds no items at all.
     */
    template <class A>
    static bool parseTriples(std::string_view plain, std::vector<seal::secure_triplet16<A>>& out);

    /**
     * @brief Encrypt/decrypt all files in a directory tree (CLI path).
     *
     * Walks the directory with `FindFirstFileA` and hands every leaf file to
     * @ref processFilePath, which transforms it by `.seal` extension, writes a
     * sibling output, then removes the source.
     *
     * @par Entries that never reach processFilePath
     * - `.` and `..`.
     * - Any entry carrying `FILE_ATTRIBUTE_REPARSE_POINT` (symlink, junction or
     *   mount point), skipped silently so the walk cannot escape the tree or
     *   loop.
     * - `.exe` files and the `seal` binary, reported as `(skipped)`. The name
     *   test runs before the directory test, so a directory named `*.exe` is
     *   skipped whole and never descended into.
     *
     * @par Concurrency
     * Leaf files run on a fixed-size worker pool in a function-local static, so
     * every caller in the process shares the same
     * `max(1, min(hardware_concurrency, 8))` threads and one 32-slot queue.
     * Submitting to a full queue blocks. Subdirectory recursion runs inline on
     * the calling thread, which keeps a pool worker from ever waiting on
     * another pool task.
     *
     * @par Lifetime and errors
     * Pool tasks capture @p password by reference and are joined on every exit
     * path, including an exception, so @p password must outlive the call. A
     * task never propagates an exception; it reports `false` instead.
     *
     * @tparam SecurePwd Secure password container.
     * @param dir      Root directory to walk.
     * @param password Master password for key derivation.
     * @param recurse  Recurse into subdirectories when `true`. When `false`,
     *                 subdirectories are ignored and do not count as failures.
     * @return `true` when nothing failed: the directory listed, every leaf file
     *         succeeded, and every recursive call returned `true`.
     *
     * @note This is the CLI-mode directory processor. The GUI-mode
     *       seal::encryptDirectory() / seal::decryptDirectory() in Vault.hpp
     *       scan with `std::filesystem::recursive_directory_iterator` on one
     *       thread, decide with ProtectedFolderPolicy.hpp, and refuse an entry
     *       whose destination or `.tmp` staging path already exists. This path
     *       replaces both without warning.
     * @note The `[dir]` summary line counts leaf files in `total` but counts
     *       both leaf files and subdirectory results in `ok` / `fail`, so
     *       `ok + fail` can exceed `total`.
     */
    template <secure_password SecurePwd>
    static bool processDirectory(const std::string& dir,
                                 const SecurePwd& password,
                                 bool recurse = true);

    /**
     * @brief Process a single file path or convenience token.
     *
     * @par Normalisation
     * Outer whitespace and quotes are removed, every control character (below
     * 0x20, plus 0x7F) is deleted as clipboard paste residue, and trailing `\`
     * and `/` are dropped one by one, stopping at a drive root such as `C:\`.
     * A string left empty by the control-character pass returns `false`.
     *
     * @par Classification order
     * - Basename `.exe` or `seal`: skipped and reported as success.
     * - `.`: expanded to the current working directory.
     * - Directory: delegated to processDirectory() with recursion enabled. The
     *   test runs twice, first through `GetFileAttributesA` and then through
     *   `std::filesystem`, so long paths and forward-slash forms still resolve.
     * - Missing path: rejected, which is how processBatch() decides a line is
     *   not a path and moves on to the hex and plaintext tiers.
     * - `.seal` file: decrypted to the same name with the extension removed.
     * - Any other file: encrypted to `<name>.seal`.
     *
     * @tparam SecurePwd Secure password container.
     * @param raw      Path string; may be quoted.
     * @param password Master password for key derivation.
     * @return `true` when the path was recognized and processed. Skipped names
     *         and directories also return `true`; a directory returns `true`
     *         even when files inside it failed.
     *
     * @post After a successful file transform the source is removed with
     *       `DeleteFileA`. It is not shredded, and an existing destination is
     *       replaced without warning.
     * @throw std::runtime_error propagated from the encrypt path (see
     *        @ref encryptFileTo). The decrypt path reports failures as `false`.
     */
    template <secure_password SecurePwd>
    static bool processFilePath(const std::string& raw, const SecurePwd& password);

    /**
     * @brief Batch dispatcher for mixed CLI input.
     *
     * Each line is classified by the first tier that accepts it:
     * - Tier 1, file or directory path, handled by processFilePath(). A path
     *   always wins, even when the same text would also scan as hex.
     * - Tier 2, hex tokens, decrypted with decryptLine(). Tokens that parse as
     *   triples contribute their service names to the masked view; any other
     *   plaintext is copied to the clipboard with a TTL scrub and kept for the
     *   echo step below.
     * - Tier 3, anything else, encrypted with encryptLine().
     *
     * Output is emitted in three groups once every line is classified: the
     * credential view first, then the non-triple plaintext echo, then the newly
     * produced hex.
     *
     * @par Credential exposure
     * The scan keeps only service names plus an index back to the source hex
     * token; usernames and passwords are wiped as soon as the names are copied.
     * In censored mode (`uncensored == false`) a credential is re-decrypted one
     * at a time when its row is clicked, and the call blocks in
     * interactiveMaskedWin() until the user exits. In uncensored mode every
     * triple is re-decrypted and printed to `std::cout` on one line.
     *
     * @par Non-triple plaintext
     * Uncensored mode prints it as-is; censored mode prints `*` runs. Both
     * modes copy it to the clipboard during the scan, and censored mode copies
     * it once more at the echo step. Each copy replaces the previous one and
     * restarts the single TTL scrub timer, so only the last non-triple
     * plaintext of the batch survives there.
     *
     * @tparam SecurePwd Secure password container.
     * @param lines      Input lines to process. Returns immediately when empty.
     * @param uncensored Print plaintext when `true`, mask when `false`.
     * @param password   Master password for key derivation.
     *
     * @note A token that fails to decrypt is reported on `std::cerr` and the
     *       remaining lines are still processed. An exception from the encrypt
     *       side of processFilePath() is not caught here and aborts the batch.
     */
    template <secure_password SecurePwd>
    static void processBatch(const std::vector<std::string>& lines,
                             bool uncensored,
                             const SecurePwd& password);

    /**
     * @brief Stream encryption: read from stdin, encrypt, write binary to stdout.
     *
     * Reads `std::cin` to end of stream, encrypts the bytes as one AES-256-GCM
     * packet, and writes that raw packet to `std::cout`. Despite the name the
     * read is not incremental: the whole input is buffered in heap memory and
     * the packet is built beside it, so peak memory is the input plus its
     * packet (input + 52 bytes).
     *
     * @tparam SecurePwd Secure password container.
     * @param password Master password for key derivation.
     * @return `true` on success. `false` when stdin is empty, the write to
     *         stdout fails, or the crypto layer throws; the reason goes to
     *         `std::cerr`.
     *
     * @pre `stdin` and `stdout` are in binary mode. seal never calls `_setmode`,
     *      so the caller must switch them. In text mode Windows translates `\n`
     *      to `\r\n` on output and stops reading at 0x1A, which corrupts the
     *      packet.
     * @note No CLI mode reaches this function; `-e` / `--text-encrypt` selects
     *       the hex/Base64 text mode instead.
     */
    template <secure_password SecurePwd>
    static bool streamEncrypt(const SecurePwd& password);

    /**
     * @brief Stream decryption: read binary from stdin, decrypt, write to stdout.
     *
     * Reads one raw AES-256-GCM packet from `std::cin`, decrypts it, and writes
     * the plaintext to `std::cout`. The whole packet is buffered first, so peak
     * memory is the size of the input plus its plaintext. GCM authenticates
     * only at the end, so nothing is emitted until the tag verifies.
     *
     * @tparam SecurePwd Secure password container.
     * @param password Master password for key derivation.
     * @return `true` on success. `false` when stdin is empty, the packet is
     *         malformed, authentication fails, or the write to stdout fails;
     *         the reason goes to `std::cerr`.
     *
     * @pre `stdin` and `stdout` are in binary mode; see @ref streamEncrypt.
     * @note No CLI mode reaches this function; `-d` / `--text-decrypt` selects
     *       the hex/Base64 text mode instead.
     */
    template <secure_password SecurePwd>
    static bool streamDecrypt(const SecurePwd& password);

    /**
     * @brief Securely delete a file by overwriting with random data then removing.
     *
     * Opens the file exclusively with `FILE_FLAG_WRITE_THROUGH`, makes three
     * full-length passes over it - random, zeros, random - flushing after each,
     * then deletes it. A file whose size is zero or cannot be queried skips the
     * passes and is deleted directly.
     *
     * @param path File to shred.
     * @return `true` when the file is gone. `false` when it cannot be opened
     *         exclusively, a seek or write fails, `RAND_bytes` fails, or the
     *         final delete fails.
     *
     * @warning Overwriting reaches the original sectors only on media that
     *          write in place. On SSDs, copy-on-write or journalling
     *          filesystems, shadow copies and network shares the old contents
     *          can survive.
     * @warning A `false` return from a failed pass leaves the file on disk,
     *          partly overwritten and therefore unusable. Do not treat the data
     *          as either intact or destroyed.
     */
    static bool shredFile(const std::string& path);

    /**
     * @brief Compute the SHA-256 hash of a file.
     *
     * Reads the file in 64 KiB chunks, so memory use does not depend on the
     * file size. The file is opened in binary mode and hashed byte for byte.
     *
     * @param path File to hash.
     * @return 64 lowercase hex characters, or an empty string when the file
     *         cannot be opened or an OpenSSL digest call fails. An empty file
     *         hashes to the SHA-256 of zero bytes, not to an empty string.
     *
     * @warning A read error after the first chunk is not reported. The call
     *          returns the SHA-256 of the bytes read so far, so a returned
     *          digest is not proof that the whole file was read. A caller that
     *          needs that proof must check the byte count itself.
     */
    [[nodiscard]] static std::string hashFile(const std::string& path);
};

}  // namespace seal
