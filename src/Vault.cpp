#ifdef USE_QT_UI

#include "Vault.hpp"

#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "FileOperations.hpp"
#include "Logging.hpp"
#include "Utils.hpp"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QString>

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

// Securely wipe a std::string including its SSO inline buffer, then release.
// Unlike cleanseString + SecureZeroMemory(&obj), this does NOT zero the
// object's metadata - only the character data - so the destructor operates
// on a valid (empty) object rather than corrupted internal state.
void wipeStdString(std::string& s)
{
    if (!s.empty())
    {
        // capacity() covers the full SSO inline buffer on MSVC (15 chars),
        // not just size(), so stale characters beyond the logical length
        // are wiped too.
        SecureZeroMemory(s.data(), s.capacity());
    }
    s.clear();
    s.shrink_to_fit();
}
// Vault binary format (V2):
//   magic(4 bytes "SVH2") + version(1 byte) + count(4 bytes BE) + N records
// Each record: platformLen(4 BE) + platformBlob + credLen(4 BE) + credBlob
// The entire binary frame is hex-encoded into a single text string on disk.
constexpr unsigned char kVaultMagic[4] = {'S', 'V', 'H', '2'};
constexpr unsigned char kVaultFormatVersion = 1;

// All multi-byte integers use big-endian (network byte order) so the vault
// file is portable across machines regardless of native endianness.
void appendU32BE(std::vector<unsigned char>& out, uint32_t v)
{
    out.push_back(static_cast<unsigned char>((v >> 24) & 0xFFu));
    out.push_back(static_cast<unsigned char>((v >> 16) & 0xFFu));
    out.push_back(static_cast<unsigned char>((v >> 8) & 0xFFu));
    out.push_back(static_cast<unsigned char>(v & 0xFFu));
}

bool readU32BE(const std::vector<unsigned char>& in, size_t& pos, uint32_t& out)
{
    if (pos + 4 > in.size())
        return false;
    out = (static_cast<uint32_t>(in[pos]) << 24) | (static_cast<uint32_t>(in[pos + 1]) << 16) |
          (static_cast<uint32_t>(in[pos + 2]) << 8) | static_cast<uint32_t>(in[pos + 3]);
    pos += 4;
    return true;
}

bool readSizedBlob(const std::vector<unsigned char>& in,
                   size_t& pos,
                   uint32_t len,
                   std::vector<unsigned char>& out)
{
    const size_t n = static_cast<size_t>(len);
    if (pos > in.size() || n > (in.size() - pos))
        return false;
    out.assign(in.begin() + pos, in.begin() + pos + n);
    pos += n;
    return true;
}
}  // namespace

namespace seal
{

void DecryptedCredential::cleanse()
{
    seal::Cryptography::cleanseString(username, password);
}

static std::vector<unsigned char> encryptString(
    const std::string& plaintext,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword)
{
    return seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(plaintext.data()),
                                       plaintext.size()),
        masterPassword);
}

// Decrypt a packet and return the plaintext as a regular std::string.
// Used only for platform names, which are explicitly non-secret (displayed
// in the vault list view). Secret fields (username, password) go through
// decryptCredentialOnDemand() which returns secure_string in locked memory.
static std::string decryptToString(
    const std::vector<unsigned char>& packet,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    auto plainBytes =
        seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);
    std::string result(reinterpret_cast<const char*>(plainBytes.data()), plainBytes.size());
    seal::Cryptography::cleanseString(plainBytes);
    return result;
}

std::vector<VaultRecord> loadVaultIndex(
    const QString& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    const std::string opId = seal::diag::nextOpId("vault_index_load");
    const auto started = std::chrono::steady_clock::now();
    const std::string pathMeta = seal::diag::pathSummary(vaultPath.toUtf8().toStdString());
    auto logInfo = [](std::initializer_list<std::string> fields)
    { qCInfo(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(fields)); };
    auto logWarn = [](std::initializer_list<std::string> fields)
    { qCWarning(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(fields)); };

    logInfo({"event=vault.index.load.begin", "result=start", seal::diag::kv("op", opId), pathMeta});
    std::ifstream in(vaultPath.toStdString(), std::ios::in | std::ios::binary);
    if (!in)
    {
        logWarn({"event=vault.index.load.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=open_failed",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Cannot open vault file");
    }

    // Step 1: Read the entire file as a hex-encoded text string.
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    // Strip any whitespace that may have been inserted (e.g. line breaks).
    std::string compact = seal::utils::stripSpaces(raw);
    if (compact.empty())
    {
        logInfo({"event=vault.index.load.finish",
                 "result=ok",
                 seal::diag::kv("op", opId),
                 seal::diag::kv("record_count", 0),
                 "reason=empty_input",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        return {};
    }

    // Step 2: Hex-decode the text back into the raw binary frame.
    // The vault file is stored as one long hex string so it stays a safe
    // single-line text blob (no embedded NULs, no encoding ambiguity).
    std::vector<unsigned char> framed;
    if (!seal::utils::from_hex(std::string_view{compact}, framed))
    {
        logWarn({"event=vault.index.load.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=invalid_hex",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Invalid vault format");
    }

    // Step 3: Parse the binary frame header: magic(4) + version(1) + count(4) = 9 bytes min.
    size_t pos = 0;
    if (framed.size() < 9)
    {
        logWarn({"event=vault.index.load.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=payload_too_short",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Corrupted vault file");
    }
    for (unsigned char b : kVaultMagic)
    {
        if (framed[pos++] != b)
        {
            logWarn({"event=vault.index.load.finish",
                     "result=fail",
                     seal::diag::kv("op", opId),
                     "reason=bad_magic",
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            throw std::runtime_error("Invalid vault format");
        }
    }
    const unsigned char version = framed[pos++];
    if (version != kVaultFormatVersion)
    {
        logWarn({"event=vault.index.load.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=unsupported_version",
                 seal::diag::kv("version", version),
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Unsupported vault format version");
    }

    uint32_t entryCount = 0;
    if (!readU32BE(framed, pos, entryCount))
    {
        logWarn({"event=vault.index.load.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=missing_entry_count",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Corrupted vault file");
    }
    // Sanity check: each record needs at least 8 bytes (two u32 length fields),
    // so reject counts that would be impossible given the remaining data.
    if (entryCount > (framed.size() - pos) / 8)
    {
        logWarn({"event=vault.index.load.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=impossible_entry_count",
                 seal::diag::kv("entry_count", entryCount),
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Corrupted vault file");
    }

    // Step 4: Read each length-prefixed record: [platformLen][platformBlob][credLen][credBlob].
    // We decrypt *only* the platform name here (for display in the list view);
    // the credential blob stays encrypted until the user explicitly requests it.
    std::vector<VaultRecord> records;
    records.reserve(entryCount);

    for (uint32_t i = 0; i < entryCount; ++i)
    {
        std::vector<unsigned char> platformBlob, credBlob;
        uint32_t platformLen = 0;
        uint32_t credLen = 0;
        if (!readU32BE(framed, pos, platformLen) ||
            !readSizedBlob(framed, pos, platformLen, platformBlob) ||
            !readU32BE(framed, pos, credLen) || !readSizedBlob(framed, pos, credLen, credBlob))
        {
            logWarn({"event=vault.index.load.finish",
                     "result=fail",
                     seal::diag::kv("op", opId),
                     "reason=truncated_payload",
                     seal::diag::kv("entry_index", i),
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            throw std::runtime_error("Corrupted vault file");
        }

        try
        {
            std::string platformName = decryptToString(platformBlob, password);

            VaultRecord rec;
            rec.platform = std::move(platformName);
            rec.encryptedPlatform = std::move(platformBlob);
            rec.encryptedBlob = std::move(credBlob);
            rec.dirty = false;
            rec.deleted = false;
            records.push_back(std::move(rec));
        }
        catch (...)
        {
            // Fail on the very first decryption failure so a wrong password
            // never reveals how many records the vault holds.  If we kept
            // going, an attacker could measure how far parsing progressed
            // and infer the record count even without the correct password.
            logWarn({"event=vault.index.load.finish",
                     "result=fail",
                     seal::diag::kv("op", opId),
                     "reason=wrong_password",
                     seal::diag::kv("entry_index", i),
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            throw std::runtime_error("Wrong password");
        }
    }
    // Step 5: Verify we consumed every byte.  Trailing bytes would indicate
    // file corruption, accidental concatenation, or a tampered payload.
    if (pos != framed.size())
    {
        logWarn({"event=vault.index.load.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=trailing_bytes",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Corrupted vault file");
    }

    logInfo({"event=vault.index.load.finish",
             "result=ok",
             seal::diag::kv("op", opId),
             seal::diag::kv("record_count", records.size()),
             seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
    return records;
}

bool saveVaultV2(
    const QString& vaultPath,
    const std::vector<VaultRecord>& records,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    const std::string opId = seal::diag::nextOpId("vault_index_save");
    const auto started = std::chrono::steady_clock::now();
    const std::string pathMeta = seal::diag::pathSummary(vaultPath.toUtf8().toStdString());
    auto logInfo = [](std::initializer_list<std::string> fields)
    { qCInfo(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(fields)); };
    auto logWarn = [](std::initializer_list<std::string> fields)
    { qCWarning(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(fields)); };

    logInfo({"event=vault.index.save.begin",
             "result=start",
             seal::diag::kv("op", opId),
             seal::diag::kv("record_count", records.size()),
             pathMeta});

    // Atomic save: write to a temporary file, flush, then rename over the target.
    // This prevents data loss if the process crashes mid-write.
    std::string finalPath = vaultPath.toStdString();
    std::string tmpPath = finalPath + ".tmp";

    std::ofstream out(tmpPath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!out)
    {
        logWarn({"event=vault.index.save.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=open_temp_failed",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        return false;
    }

    struct SerializedRecord
    {
        std::vector<unsigned char> platform;
        std::vector<unsigned char> credential;
    };

    std::vector<SerializedRecord> serialized;
    serialized.reserve(records.size());
    for (const auto& rec : records)
    {
        if (rec.deleted)
            continue;

        // Use existing encrypted platform if available, otherwise encrypt it
        std::vector<unsigned char> platformBlob;
        if (!rec.encryptedPlatform.empty() && !rec.dirty)
        {
            platformBlob = rec.encryptedPlatform;
        }
        else
        {
            platformBlob = encryptString(rec.platform, password);
        }

        if (platformBlob.size() > std::numeric_limits<uint32_t>::max() ||
            rec.encryptedBlob.size() > std::numeric_limits<uint32_t>::max())
        {
            logWarn({"event=vault.index.save.finish",
                     "result=fail",
                     seal::diag::kv("op", opId),
                     "reason=field_too_large",
                     seal::diag::kv("platform_blob_len", platformBlob.size()),
                     seal::diag::kv("credential_blob_len", rec.encryptedBlob.size()),
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            out.close();
            DeleteFileA(tmpPath.c_str());
            return false;
        }

        serialized.push_back({std::move(platformBlob), rec.encryptedBlob});
    }

    if (serialized.size() > std::numeric_limits<uint32_t>::max())
    {
        logWarn({"event=vault.index.save.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=too_many_records",
                 seal::diag::kv("serialized_count", serialized.size()),
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        out.close();
        DeleteFileA(tmpPath.c_str());
        return false;
    }

    // Build the binary frame: magic + version + count + records (same layout
    // that loadVaultIndex expects to parse back).
    size_t framedSize = 4 + 1 + 4;  // magic(4) + version(1) + entryCount(4)
    for (const auto& rec : serialized)
    {
        framedSize += 4 + rec.platform.size();    // platformLen + platformBlob
        framedSize += 4 + rec.credential.size();  // credLen + credBlob
    }

    std::vector<unsigned char> framed;
    framed.reserve(framedSize);
    framed.insert(framed.end(), kVaultMagic, kVaultMagic + sizeof(kVaultMagic));
    framed.push_back(kVaultFormatVersion);
    appendU32BE(framed, static_cast<uint32_t>(serialized.size()));
    for (const auto& rec : serialized)
    {
        appendU32BE(framed, static_cast<uint32_t>(rec.platform.size()));
        framed.insert(framed.end(), rec.platform.begin(), rec.platform.end());
        appendU32BE(framed, static_cast<uint32_t>(rec.credential.size()));
        framed.insert(framed.end(), rec.credential.begin(), rec.credential.end());
    }

    // Hex-encode the entire binary frame so the file is plain text on disk.
    const std::string hexBlob = seal::utils::to_hex(framed);
    out.write(hexBlob.data(), static_cast<std::streamsize>(hexBlob.size()));
    out.flush();
    bool ok = out.good();
    out.close();

    if (ok)
    {
        // Atomically replace the target file with the completed temp file.
        // MoveFileExA with MOVEFILE_REPLACE_EXISTING performs an atomic rename
        // on NTFS, so readers never see a half-written vault.  MOVEFILE_COPY_ALLOWED
        // is a fallback that lets the OS copy+delete if src/dst are on different volumes.
        if (!MoveFileExA(tmpPath.c_str(),
                         finalPath.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
        {
            logWarn({"event=vault.index.save.finish",
                     "result=fail",
                     seal::diag::kv("op", opId),
                     "reason=rename_failed",
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            DeleteFileA(tmpPath.c_str());
            return false;
        }
        logInfo({"event=vault.index.save.finish",
                 "result=ok",
                 seal::diag::kv("op", opId),
                 seal::diag::kv("record_count", serialized.size()),
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
    }
    else
    {
        logWarn({"event=vault.index.save.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 "reason=write_failed",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        DeleteFileA(tmpPath.c_str());
    }
    return ok;
}

DecryptedCredential decryptCredentialOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    qCDebug(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.decrypt.begin",
         seal::diag::kv("platform_len", record.platform.size()),
         seal::diag::kv("encrypted_blob_len", record.encryptedBlob.size())}));
    // The encrypted credential blob contains "username\0password" -- a single
    // null byte separates the two fields inside the decrypted plaintext.
    auto plainBytes = seal::Cryptography::decryptPacket(
        std::span<const unsigned char>(record.encryptedBlob), password);

    const char* data = reinterpret_cast<const char*>(plainBytes.data());
    size_t len = plainBytes.size();

    // Find the first '\0' which splits username from password.
    size_t sep = len;
    for (size_t i = 0; i < len; ++i)
    {
        if (data[i] == '\0')
        {
            sep = i;
            break;
        }
    }

    if (sep == len)
    {
        qCWarning(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=credential.decrypt.finish",
             "result=fail",
             "reason=malformed_blob",
             seal::diag::kv("encrypted_blob_len", record.encryptedBlob.size())}));
        seal::Cryptography::cleanseString(plainBytes);
        throw std::runtime_error("Malformed credential blob");
    }

    // Everything before the separator is the username; everything after is the password.
    std::string userUtf8(data, sep);
    std::string passUtf8;
    if (sep + 1 < len)
    {
        passUtf8.assign(data + sep + 1, len - sep - 1);
    }
    seal::Cryptography::cleanseString(plainBytes);

    DecryptedCredential cred;
    cred.username = seal::utils::utf8ToSecureWide(userUtf8);
    cred.password = seal::utils::utf8ToSecureWide(passUtf8);

    // Wipe the intermediate UTF-8 strings including their SSO inline buffers.
    // wipeStdString zeroes s.data() for the full capacity() (covering SSO
    // slack) then clear+shrink, keeping the object in a valid state for its
    // destructor - unlike the previous SecureZeroMemory(&obj) which was UB.
    wipeStdString(userUtf8);
    wipeStdString(passUtf8);

    qCDebug(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.decrypt.finish",
         "result=ok",
         seal::diag::kv("username_chars", cred.username.size()),
         seal::diag::kv("credential_chars", cred.username.size() + cred.password.size())}));
    return cred;
}

VaultRecord encryptCredential(
    const std::string& platform,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword)
{
    qCDebug(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.encrypt.begin", seal::diag::kv("platform_len", platform.size())}));
    // Convert wide-char credentials to UTF-8 for the on-disk format.
    std::string userUtf8 = seal::utils::secureWideToUtf8(username);
    std::string passUtf8 = seal::utils::secureWideToUtf8(password);

    // Build the credential plaintext as "username\0password" -- a single null
    // byte separates the two fields.  This mirrors what decryptCredentialOnDemand
    // expects when splitting the blob back apart.
    std::string credPlain;
    credPlain.reserve(userUtf8.size() + 1 + passUtf8.size());
    credPlain.append(userUtf8);
    credPlain.push_back('\0');
    credPlain.append(passUtf8);
    wipeStdString(userUtf8);
    wipeStdString(passUtf8);

    // Encrypt the combined credential blob with the master password.
    auto credBlob = seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(credPlain.data()),
                                       credPlain.size()),
        masterPassword);
    wipeStdString(credPlain);

    auto platformBlob = encryptString(platform, masterPassword);

    VaultRecord rec;
    rec.platform = platform;
    rec.encryptedPlatform = std::move(platformBlob);
    rec.encryptedBlob = std::move(credBlob);
    rec.dirty = true;
    rec.deleted = false;
    qCDebug(logVault).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=credential.encrypt.finish",
                                "result=ok",
                                seal::diag::kv("platform_blob_len", rec.encryptedPlatform.size()),
                                seal::diag::kv("credential_blob_len", rec.encryptedBlob.size())}));
    return rec;
}

int encryptDirectory(
    const QString& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    std::string path = dirPath.toStdString();
    int count = 0;
    const std::string opId = seal::diag::nextOpId("vault_dir_encrypt");
    const auto started = std::chrono::steady_clock::now();

    qCInfo(logVault).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=directory.encrypt.begin",
                                "result=start",
                                seal::diag::kv("op", opId),
                                seal::diag::pathSummary(path)}));
    try
    {
        // Collect all eligible file paths first, then process them in a
        // second pass. Renaming files during recursive_directory_iterator
        // traversal can cause skipped or double-visited entries on some
        // filesystems.
        namespace fs = std::filesystem;
        std::vector<std::string> filePaths;
        for (const auto& entry :
             fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied))
        {
            if (entry.is_symlink() || !entry.is_regular_file())
            {
                continue;
            }

            const std::string ext = entry.path().extension().string();
            if (seal::utils::endsWithCi(ext, ".seal") || seal::utils::endsWithCi(ext, ".exe") ||
                seal::utils::endsWithCi(ext, ".dll") || seal::utils::endsWithCi(ext, ".pdb"))
            {
                continue;
            }

            filePaths.push_back(entry.path().string());
        }

        for (const auto& filePath : filePaths)
        {
            std::string newPath = filePath + ".seal";
            if (FileOperations::encryptFileTo(filePath, newPath, password))
            {
                DeleteFileA(filePath.c_str());
                count++;
            }
        }
    }
    catch (const std::exception& e)
    {
        qCWarning(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=directory.encrypt.finish",
             "result=partial",
             seal::diag::kv("op", opId),
             seal::diag::kv("count", count),
             seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what())),
             seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
             seal::diag::pathSummary(path)}));
        return count;
    }

    qCInfo(logVault).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=directory.encrypt.finish",
                                "result=ok",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("count", count),
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                                seal::diag::pathSummary(path)}));
    return count;
}

int decryptDirectory(
    const QString& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    std::string path = dirPath.toStdString();
    int count = 0;
    const std::string opId = seal::diag::nextOpId("vault_dir_decrypt");
    const auto started = std::chrono::steady_clock::now();

    qCInfo(logVault).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=directory.decrypt.begin",
                                "result=start",
                                seal::diag::kv("op", opId),
                                seal::diag::pathSummary(path)}));
    try
    {
        // Collect all eligible file paths first, then process them in a
        // second pass. Renaming files during recursive_directory_iterator
        // traversal can cause skipped or double-visited entries on some
        // filesystems.
        namespace fs = std::filesystem;
        std::vector<std::string> filePaths;
        for (const auto& entry :
             fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied))
        {
            if (entry.is_symlink() || !entry.is_regular_file())
            {
                continue;
            }

            const std::string ext = entry.path().extension().string();
            if (!seal::utils::endsWithCi(ext, ".seal"))
            {
                continue;
            }

            filePaths.push_back(entry.path().string());
        }

        for (const auto& filePath : filePaths)
        {
            std::string newPath = seal::utils::strip_ext_ci(filePath, ".seal");
            if (FileOperations::decryptFileTo(filePath, newPath, password))
            {
                DeleteFileA(filePath.c_str());
                count++;
            }
        }
    }
    catch (const std::exception& e)
    {
        qCWarning(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=directory.decrypt.finish",
             "result=partial",
             seal::diag::kv("op", opId),
             seal::diag::kv("count", count),
             seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what())),
             seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
             seal::diag::pathSummary(path)}));
        return count;
    }

    qCInfo(logVault).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=directory.decrypt.finish",
                                "result=ok",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("count", count),
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                                seal::diag::pathSummary(path)}));
    return count;
}

}  // namespace seal

#endif  // USE_QT_UI
