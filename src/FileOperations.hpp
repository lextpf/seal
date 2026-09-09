#pragma once

#include "Cryptography.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace seal
{

/**
 * @class FileOperations
 * @brief file and CLI boundaries for AES-256-GCM operations.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup IO_FileOperations
 *
 * disk writes reserve the deterministic `<dstPath>.tmp` name and replace existing destinations.
 * reported failures remove staging files; escaping exceptions can leave them behind.
 * FlushFileBuffers is best-effort: its failure does not prevent rename or a true return.
 * progress and errors use stdout and stderr.
 *
 * | operation                           | failure result               |
 * |-------------------------------------|------------------------------|
 * | encryptFileTo, encryptFileStreaming | false for I/O; crypto throws |
 * | decryptFileTo, decryptFileStreaming | std::exception becomes false |
 * | streamEncrypt, streamDecrypt        | std::exception becomes false |
 * | encryptLine, decryptLine            | exceptions propagate         |
 *
 * @verbatim
 *   src  (read-only; never modified by encrypt/decrypt)
 *     |
 *     v  transform (AES-256-GCM)
 *   <dst>.tmp  --- flush, close, reopen, FlushFileBuffers ---> bytes durable
 *     |
 *     v  MoveFileEx(<dst>.tmp -> <dst>, MOVEFILE_REPLACE_EXISTING)
 *   <dst>  (replaced atomically; on crash <dst> is fully old or fully new)
 * @endverbatim
 */
class FileOperations
{
public:
    FileOperations() = delete;
    FileOperations(const FileOperations&) = delete;
    FileOperations& operator=(const FileOperations&) = delete;

    /**
     * @brief encrypt to a replacement destination, preserving the source.
     *
     * streams above cfg::FILE_CHUNK (1 MiB); failed size queries use the whole-file path.
     *
     * @return false for source-open, write, flush or rename failure.
     * @throw std::runtime_error on crypto failure. streaming can leave a staging file;
     *        whole-file encryption fails before staging starts.
     */
    template <secure_password SecurePwd>
    static bool encryptFileTo(const std::string& srcPath,
                              const std::string& dstPath,
                              const SecurePwd& pwd);

    /**
     * @brief authenticate before creating plaintext output, preserving the source.
     *
     * streams above 1 MiB plus 52 framing bytes; failed size queries use the whole-file path.
     *
     * @return false for I/O, format or authentication failure; std::exception is logged to stderr.
     */
    template <secure_password SecurePwd>
    static bool decryptFileTo(const std::string& srcPath,
                              const std::string& dstPath,
                              const SecurePwd& pwd);

    /**
     * @brief encrypt raw bytes without adding a terminator.
     *
     * UTF-8 validity is not required. the caller wipes the pageable input and output strings.
     *
     * @return lowercase hex, `2 * s.size() + 104` characters including framing.
     * @throw std::runtime_error on crypto failure.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static std::string encryptLine(const std::string& s, const SecurePwd& pwd);

    /**
     * @brief decode whitespace-tolerant hex into locked plaintext.
     *
     * hex is case-insensitive. use size() because plaintext can contain NULs.
     * intermediate plaintext is wiped before return.
     *
     * @throw std::runtime_error on odd-length or non-hex input, invalid framing, excessive KDF
     *        parameters or authentication failure.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static seal::secure_string<seal::locked_allocator<char>> decryptLine(
        const std::string& rawHex, const SecurePwd& pwd);

    /**
     * @brief encrypt with two 1 MiB buffers, preserving the source.
     *
     * uses the encryptPacket wire format with fresh salt and IV. plaintext chunks and the derived
     * key are wiped after use. direct calls stream at any file size.
     *
     * @return false for I/O failure; staging files are removed on reported failure.
     * @throw std::runtime_error on crypto failure; an opened staging file can remain.
     */
    template <secure_password SecurePwd>
    static bool encryptFileStreaming(const std::string& srcPath,
                                     const std::string& dstPath,
                                     const SecurePwd& pwd);

    /**
     * @brief authenticate in a first pass, then stream plaintext to disk.
     *
     * uses 1 MiB chunks and one derived key for both passes. validates header/KDF limits and reads
     * the stored tag before decryption. direct calls stream at any file size.
     *
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
     * @return false on I/O, format or authentication failure, source size/time change between
     *         passes, or std::exception.
     */
    template <secure_password SecurePwd>
    static bool decryptFileStreaming(const std::string& srcPath,
                                     const std::string& dstPath,
                                     const SecurePwd& pwd);

    /**
     * @brief count wchar_t units including the two separators.
     *
     * UTF-8 serialization can require more bytes.
     */
    template <class A>
    static size_t tripleLen(const seal::secure_triplet16<A>& t)
    {
        return t.primary.size() + 1 + t.secondary.size() + 1 + t.tertiary.size();
    }

    /**
     * @brief serialize service, username and password with two colon separators.
     *
     * empty fields produce empty segments. colons inside fields prevent parseTriples round trips.
     *
     * @return pageable UTF-8 string; cleanse it immediately after use.
     */
    static std::string tripleToUtf8(const seal::secure_triplet16_t& t);

    /**
     * @brief parse non-empty service, username and password fields into locked UTF-16 storage.
     *
     * comma, CR and LF end items. trim each item, ignore empty items and require exactly two
     * colons.
     * trim service and username again; password retains leading/interior spaces after item
     * trimming.
     * no intermediate narrow secret copy is made.
     *
     * @param out cleared on entry and on failure.
     * @return true only when at least one item exists and every item is valid.
     */
    template <class A>
    static bool parseTriples(std::string_view plain, std::vector<seal::secure_triplet16<A>>& out);

    /**
     * @brief transform a CLI directory tree by file extension, then remove each source.
     *
     * skips dot entries, reparse points, `.exe` names and the seal binary. name checks precede
     * directory checks, so a directory ending in .exe is skipped entirely.
     *
     * all callers share max(1, min(hardware_concurrency, 8)) workers and a 32-slot queue; a full
     * queue blocks submission. recursion runs on the caller to avoid pool deadlock. tasks borrow
     * password and join on every exit, including exceptions; task exceptions become false.
     *
     * @param recurse false ignores subdirectories without failure.
     * @return true only if enumeration, leaf transforms and recursive calls all succeed.
     * @note summary total counts files; ok/fail also count subdirectories and can exceed total.
     * @warning destinations and staging files are replaced; the GUI protected-folder path refuses
     *          these collisions. removed sources are not shredded.
     */
    template <secure_password SecurePwd>
    static bool processDirectory(const std::string& dir,
                                 const SecurePwd& password,
                                 bool recurse = true);

    /**
     * @brief normalize a CLI path, transform it and remove a successfully transformed source.
     *
     * strips outer whitespace/quotes, control bytes below 0x20 plus 0x7F, and trailing separators
     * without shortening drive roots.
     *
     * | first matching case | action                                     |
     * |---------------------|--------------------------------------------|
     * | .exe or seal name   | skip successfully                          |
     * | dot                 | expand to current directory                |
     * | directory           | recurse; return true even if children fail |
     * | missing/empty path  | return false                               |
     * | .seal file          | decrypt; remove final extension            |
     * | other file          | encrypt to name.seal                       |
     *
     * @throw std::runtime_error from encryption; decryption reports false.
     * @post replaces destinations; source removal uses DeleteFileA, not shredding.
     */
    template <secure_password SecurePwd>
    static bool processFilePath(const std::string& raw, const SecurePwd& password);

    /**
     * @brief classify CLI lines as paths, hex tokens or plaintext, in that order.
     *
     * hex credentials retain only service names and source-token indices after the scan; other
     * credential fields are wiped. censored mode re-decrypts one clicked row and blocks until the
     * masked view exits. uncensored mode re-decrypts and prints every triple.
     *
     * non-triple plaintext is copied to the clipboard with TTL during the scan. censored echo
     * copies it again; only the final copy survives. output order is credentials, non-triple
     * plaintext (masked unless uncensored), then newly encrypted hex.
     *
     * @note failed token decryption is logged and processing continues. file-encryption exceptions
     *       propagate and abort the batch.
     */
    template <secure_password SecurePwd>
    static void processBatch(const std::vector<std::string>& lines,
                             bool uncensored,
                             const SecurePwd& password);

    /**
     * @brief encrypt all of stdin as one binary packet on stdout.
     *
     * buffers the entire input and packet; peak storage is twice input size plus 52 bytes.
     *
     * @return false for empty stdin, output failure or crypto exception; logs to stderr.
     * @pre caller sets stdin and stdout to binary mode; text translation corrupts packets.
     * @note no CLI mode routes here; text-encrypt uses hex/Base64 instead.
     */
    template <secure_password SecurePwd>
    static bool streamEncrypt(const SecurePwd& password);

    /**
     * @brief authenticate a complete stdin packet before writing plaintext to stdout.
     *
     * buffers the packet and plaintext in full.
     *
     * @return false for empty input, malformed packet, authentication or output failure.
     * @pre caller sets stdin and stdout to binary mode.
     * @note no CLI mode routes here; text-decrypt uses hex/Base64 instead.
     */
    template <secure_password SecurePwd>
    static bool streamDecrypt(const SecurePwd& password);

    /**
     * @brief overwrite random/zero/random passes, flush each and remove the file.
     *
     * opens exclusively with FILE_FLAG_WRITE_THROUGH. zero or unknown size skips overwriting.
     *
     * @return false on open, seek, write, random-generation or delete failure.
     * @warning overwrite cannot erase copies on SSDs, copy-on-write/journaled filesystems, shadow
     *          copies or network shares. a failed pass can leave partly overwritten, unusable data.
     */
    static bool shredFile(const std::string& path);

    /**
     * @brief hash binary file bytes with a 64 KiB buffer.
     *
     * @return 64 lowercase hex characters; empty on open or OpenSSL failure. empty files have a
     *         digest.
     * @warning read errors return a digest of the bytes read so far; this does not prove a full
     *          read.
     */
    [[nodiscard]] static std::string hashFile(const std::string& path);
};

}  // namespace seal
