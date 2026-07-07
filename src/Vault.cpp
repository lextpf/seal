#include "Vault.hpp"

#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "FileOperations.hpp"
#include "Utils.hpp"

#ifdef USE_QT_UI
#include "Logging.hpp"

#include <QtCore/QString>
#endif

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
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
// Unlike SecureZeroMemory(&obj), this zeroes only the character data, not
// the metadata, so the destructor sees a valid (empty) object.
void wipeStdString(std::string& s)
{
    if (!s.empty())
    {
        // capacity() covers the full SSO buffer (15 chars on MSVC), not
        // just size(), so stale slack bytes are wiped too.
        SecureZeroMemory(s.data(), s.capacity());
    }
    s.clear();
    s.shrink_to_fit();
}

// FlushFileBuffers a path so the temp file's data blocks reach stable storage
// before the rename commits: rename persists directory metadata, not file data,
// so a power loss after it could leave a renamed-but-empty vault (total loss).
// Mirrors flushFileToDisk in FileOperations.cpp (wide variant for vault paths).
bool flushPathToDisk(const std::filesystem::path& path)
{
    HANDLE h = CreateFileW(path.c_str(),
                           GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    const BOOL ok = FlushFileBuffers(h);
    CloseHandle(h);
    return ok != 0;
}

// Vault binary format: magic(4 "SVH2") + version(1) + count(4 BE) +
// N records. Each record: platformLen(4 BE) + blob + credLen(4 BE) + blob.
// The binary frame is hex-encoded into a single text string on disk.
constexpr unsigned char kVaultMagic[4] = {'S', 'V', 'H', '2'};
constexpr unsigned char kVaultFormatVersion = 1;

// All multi-byte ints use big-endian for cross-machine portability.
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

// pathSummary wants a narrow string; lossy conversion is fine (metadata only).
std::string pathMetaString(const std::filesystem::path& p)
{
    return seal::diag::pathSummary(reinterpret_cast<const char*>(p.generic_u8string().c_str()));
}

// ASCII-lowercase copy for case-insensitive comparisons (platform names are
// compared, not collated; ASCII folding matches the search-filter behavior).
std::string asciiLowerCopy(std::string_view s)
{
    std::string out(s);
    for (char& c : out)
    {
        if (c >= 'A' && c <= 'Z')
        {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

// Alphabetically-first *.seal file in a directory; empty when none.
std::filesystem::path firstSealFileIn(const std::filesystem::path& dir)
{
    std::error_code ec;
    if (dir.empty() || !std::filesystem::is_directory(dir, ec))
    {
        return {};
    }
    std::filesystem::path best;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec))
    {
        if (!entry.is_regular_file(ec))
        {
            continue;
        }
        if (seal::utils::endsWithCi(entry.path().extension().string(), ".seal"))
        {
            if (best.empty() || entry.path().filename() < best.filename())
            {
                best = entry.path();
            }
        }
    }
    return best;
}

// Vault diagnostics sink: one logfmt line to the `vault` Qt category, compiled
// out to a no-op in non-Qt (CLI/test) builds. Shared by the vault load / save /
// rekey / directory operations. (The initializer_list is still built at the
// call site in non-Qt builds, matching the previous no-op-lambda behaviour.)
void logVaultInfo([[maybe_unused]] std::initializer_list<std::string> fields)
{
#ifdef USE_QT_UI
    qCInfo(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(fields));
#endif
}

void logVaultWarn([[maybe_unused]] std::initializer_list<std::string> fields)
{
#ifdef USE_QT_UI
    qCWarning(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(fields));
#endif
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
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword,
    const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF)
{
    return seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(plaintext.data()),
                                       plaintext.size()),
        masterPassword,
        kdf);
}

// Decrypt to a regular std::string. Used only for platform names (non-
// secret, displayed in the list). Secret fields go through
// decryptCredentialOnDemand() into locked-memory secure_string.
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
    const std::filesystem::path& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    const std::string opId = seal::diag::nextOpId("vault_index_load");
    const auto started = std::chrono::steady_clock::now();
    const std::string pathMeta = pathMetaString(vaultPath);

    logVaultInfo(
        {"event=vault.index.load.begin", "result=start", seal::diag::kv("op", opId), pathMeta});
    std::ifstream in(vaultPath, std::ios::in | std::ios::binary);
    if (!in)
    {
        logVaultWarn({"event=vault.index.load.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=open_failed",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Cannot open vault file");
    }

    // Step 1: read the file as a hex-encoded text string and strip stray
    // whitespace (e.g. line breaks).
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::string compact = seal::utils::stripSpaces(raw);
    if (compact.empty())
    {
        logVaultInfo({"event=vault.index.load.finish",
                      "result=ok",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("record_count", 0),
                      "reason=empty_input",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        return {};
    }

    // Step 2: hex-decode to the raw binary frame. The on-disk hex form
    // keeps the file a safe single-line text blob (no NULs, no encoding
    // ambiguity).
    std::vector<unsigned char> framed;
    if (!seal::utils::from_hex(std::string_view{compact}, framed))
    {
        logVaultWarn({"event=vault.index.load.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=invalid_hex",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Invalid vault format");
    }

    // Step 3: parse header: magic(4) + version(1) + count(4) = 9 bytes min.
    size_t pos = 0;
    if (framed.size() < 9)
    {
        logVaultWarn({"event=vault.index.load.finish",
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
            logVaultWarn({"event=vault.index.load.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=bad_magic",
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            throw std::runtime_error("Invalid vault format");
        }
    }
    const unsigned char version = framed[pos++];
    switch (version)
    {
        case kVaultFormatVersion:
            break;
        default:
        {
            const bool newer = version > kVaultFormatVersion;
            logVaultWarn({"event=vault.index.load.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=unsupported_version",
                          seal::diag::kv("version", version),
                          seal::diag::kv("direction", std::string_view(newer ? "newer" : "older")),
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            throw std::runtime_error(
                newer ? "Vault was written by a newer version of seal; update the app to open it."
                      : "Unsupported (older) vault format version.");
        }
    }

    uint32_t entryCount = 0;
    if (!readU32BE(framed, pos, entryCount))
    {
        logVaultWarn({"event=vault.index.load.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=missing_entry_count",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Corrupted vault file");
    }
    // Sanity: each record needs >= 8 bytes (two u32 lengths); reject
    // counts that don't fit in the remaining payload.
    if (entryCount > (framed.size() - pos) / 8)
    {
        logVaultWarn({"event=vault.index.load.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=impossible_entry_count",
                      seal::diag::kv("entry_count", entryCount),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Corrupted vault file");
    }

    // Step 4: read each [platformLen|platformBlob|credLen|credBlob]. Only
    // the platform name decrypts here; the credential stays encrypted
    // until decryptCredentialOnDemand().
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
            logVaultWarn({"event=vault.index.load.finish",
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
            // Fail-fast on first decrypt failure: keeps the record count
            // from leaking via timing on wrong-password attempts.
            logVaultWarn({"event=vault.index.load.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=wrong_password",
                          seal::diag::kv("entry_index", i),
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            throw std::runtime_error("Wrong password");
        }
    }
    // Step 5: every byte must have been consumed; trailing bytes mean
    // corruption, concatenation, or tampering.
    if (pos != framed.size())
    {
        logVaultWarn({"event=vault.index.load.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=trailing_bytes",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw std::runtime_error("Corrupted vault file");
    }

    logVaultInfo({"event=vault.index.load.finish",
                  "result=ok",
                  seal::diag::kv("op", opId),
                  seal::diag::kv("record_count", records.size()),
                  seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
    return records;
}

bool saveVault(const std::filesystem::path& vaultPath,
               const std::vector<VaultRecord>& records,
               const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
               const seal::cfg::KdfParams& kdf)
{
    const std::string opId = seal::diag::nextOpId("vault_index_save");
    const auto started = std::chrono::steady_clock::now();
    const std::string pathMeta = pathMetaString(vaultPath);

    logVaultInfo({"event=vault.index.save.begin",
                  "result=start",
                  seal::diag::kv("op", opId),
                  seal::diag::kv("record_count", records.size()),
                  pathMeta});

    // Atomic save: write tmp, flush, rename. Mid-write crash never
    // corrupts the existing vault.
    const std::filesystem::path& finalPath = vaultPath;
    std::filesystem::path tmpPath = vaultPath;
    tmpPath += ".tmp";

    std::ofstream out(tmpPath, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!out)
    {
        logVaultWarn({"event=vault.index.save.finish",
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
            platformBlob = encryptString(rec.platform, password, kdf);
        }

        if (platformBlob.size() > std::numeric_limits<uint32_t>::max() ||
            rec.encryptedBlob.size() > std::numeric_limits<uint32_t>::max())
        {
            logVaultWarn({"event=vault.index.save.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=field_too_large",
                          seal::diag::kv("platform_blob_len", platformBlob.size()),
                          seal::diag::kv("credential_blob_len", rec.encryptedBlob.size()),
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            out.close();
            DeleteFileW(tmpPath.c_str());
            return false;
        }

        serialized.push_back({std::move(platformBlob), rec.encryptedBlob});
    }

    if (serialized.size() > std::numeric_limits<uint32_t>::max())
    {
        logVaultWarn({"event=vault.index.save.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=too_many_records",
                      seal::diag::kv("serialized_count", serialized.size()),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        out.close();
        DeleteFileW(tmpPath.c_str());
        return false;
    }

    // Build the binary frame in the layout loadVaultIndex parses back.
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
        // Durable flush before the rename so a crash/power-loss can't lose the
        // freshly-written vault (the rename persists metadata, not file data).
        flushPathToDisk(tmpPath);

        // Atomic rename: MOVEFILE_REPLACE_EXISTING is atomic on NTFS so
        // readers never see a half-written vault. MOVEFILE_COPY_ALLOWED
        // is the cross-volume fallback (copy + delete).
        if (!MoveFileExW(tmpPath.c_str(),
                         finalPath.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
        {
            logVaultWarn({"event=vault.index.save.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=rename_failed",
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            DeleteFileW(tmpPath.c_str());
            return false;
        }
        logVaultInfo({"event=vault.index.save.finish",
                      "result=ok",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("record_count", serialized.size()),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
    }
    else
    {
        logVaultWarn({"event=vault.index.save.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=write_failed",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        DeleteFileW(tmpPath.c_str());
    }
    return ok;
}

PlatformMatch matchPlatform(const std::vector<std::string>& names, std::string_view query)
{
    PlatformMatch result;
    const std::string q = asciiLowerCopy(query);
    if (q.empty())
    {
        return result;
    }

    std::vector<int> prefixHits;
    for (int i = 0; i < static_cast<int>(names.size()); ++i)
    {
        const std::string lower = asciiLowerCopy(names[static_cast<size_t>(i)]);
        if (lower == q)
        {
            result.outcome = MatchOutcome::Found;
            result.index = i;
            result.candidates.clear();
            return result;
        }
        if (lower.size() > q.size() && lower.compare(0, q.size(), q) == 0)
        {
            prefixHits.push_back(i);
        }
    }

    if (prefixHits.size() == 1)
    {
        result.outcome = MatchOutcome::Found;
        result.index = prefixHits.front();
        return result;
    }
    if (prefixHits.size() > 1)
    {
        result.outcome = MatchOutcome::Ambiguous;
        for (int idx : prefixHits)
        {
            result.candidates.push_back(names[static_cast<size_t>(idx)]);
        }
    }
    return result;
}

std::filesystem::path findDefaultVault()
{
    // 1. Environment override (used verbatim when the file exists).
    if (const char* env = std::getenv("SEAL_VAULT"); env != nullptr && env[0] != '\0')
    {
        std::filesystem::path p{env};
        std::error_code ec;
        if (std::filesystem::exists(p, ec))
        {
            return p;
        }
    }

    // 2. Executable directory.
    wchar_t exeBuf[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, exeBuf, MAX_PATH) > 0)
    {
        if (auto hit = firstSealFileIn(std::filesystem::path{exeBuf}.parent_path()); !hit.empty())
        {
            return hit;
        }
    }

    // 3. Current working directory.
    std::error_code ec;
    if (auto hit = firstSealFileIn(std::filesystem::current_path(ec)); !hit.empty())
    {
        return hit;
    }

    // 4. User home.
    if (const char* home = std::getenv("USERPROFILE"); home != nullptr && home[0] != '\0')
    {
        if (auto hit = firstSealFileIn(std::filesystem::path{home}); !hit.empty())
        {
            return hit;
        }
    }
    return {};
}

size_t rekeyVault(
    const std::filesystem::path& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& currentPassword,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& newPassword)
{
    [[maybe_unused]] const std::string opId = seal::diag::nextOpId("vault_rekey");
    [[maybe_unused]] const auto started = std::chrono::steady_clock::now();
    logVaultInfo({"event=vault.rekey.begin", "result=start", seal::diag::kv("op", opId)});

    // Throws "Wrong password" fast on a bad current password.
    std::vector<VaultRecord> records = loadVaultIndex(vaultPath, currentPassword);

    std::filesystem::path tmpPath = vaultPath;
    tmpPath += ".rekey.tmp";

    try
    {
        // Re-encrypt one record at a time: peak plaintext = one credential.
        std::vector<VaultRecord> rekeyed;
        rekeyed.reserve(records.size());
        for (const VaultRecord& rec : records)
        {
            if (rec.deleted)
            {
                continue;
            }
            DecryptedCredential cred = decryptCredentialOnDemand(rec, currentPassword);
            VaultRecord fresh =
                encryptCredential(rec.platform, cred.username, cred.password, newPassword);
            cred.cleanse();
            rekeyed.push_back(std::move(fresh));
        }

        if (!saveVault(tmpPath, rekeyed, newPassword))
        {
            throw std::runtime_error("Rekey failed: could not write temp vault");
        }

        // Verify the temp vault is loadable with the new password and
        // structurally equivalent before touching the original.
        std::vector<VaultRecord> verify = loadVaultIndex(tmpPath, newPassword);
        if (verify.size() != rekeyed.size())
        {
            throw std::runtime_error("Rekey failed: verification record count mismatch");
        }
        for (size_t i = 0; i < verify.size(); ++i)
        {
            if (verify[i].platform != rekeyed[i].platform)
            {
                throw std::runtime_error("Rekey failed: verification platform mismatch");
            }
        }

        // Durable flush so the rekeyed temp is on stable storage before we
        // atomically swap it over the live vault (rename persists metadata,
        // not file data); otherwise a power-loss here could lose every record.
        flushPathToDisk(tmpPath);

        if (!ReplaceFileW(vaultPath.c_str(),
                          tmpPath.c_str(),
                          nullptr,
                          REPLACEFILE_IGNORE_MERGE_ERRORS,
                          nullptr,
                          nullptr))
        {
            // ReplaceFileW requires an existing target; fall back for the
            // cross-volume / exotic-FS cases.
            if (!MoveFileExW(tmpPath.c_str(),
                             vaultPath.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
            {
                throw std::runtime_error("Rekey failed: could not replace vault file");
            }
        }

        logVaultInfo({"event=vault.rekey.finish",
                      "result=ok",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("record_count", rekeyed.size()),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        return rekeyed.size();
    }
    catch (...)
    {
        std::error_code ec;
        std::filesystem::remove(tmpPath, ec);
        logVaultInfo({"event=vault.rekey.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
        throw;
    }
}

DecryptedCredential decryptCredentialOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
#ifdef USE_QT_UI
    qCDebug(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.decrypt.begin",
         seal::diag::kv("platform_len", record.platform.size()),
         seal::diag::kv("encrypted_blob_len", record.encryptedBlob.size())}));
#endif
    // Credential blob plaintext is "username\0password" - one NUL separator.
    auto plainBytes = seal::Cryptography::decryptPacket(
        std::span<const unsigned char>(record.encryptedBlob), password);

    const char* data = reinterpret_cast<const char*>(plainBytes.data());
    size_t len = plainBytes.size();

    // Locate the '\0' separator.
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
#ifdef USE_QT_UI
        qCWarning(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=credential.decrypt.finish",
             "result=fail",
             "reason=malformed_blob",
             seal::diag::kv("encrypted_blob_len", record.encryptedBlob.size())}));
#endif
        seal::Cryptography::cleanseString(plainBytes);
        throw std::runtime_error("Malformed credential blob");
    }

    // Before separator = username, after = password.
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

    // Wipe the intermediate UTF-8 strings including SSO buffers; the prior
    // SecureZeroMemory(&obj) approach was UB (corrupted metadata).
    wipeStdString(userUtf8);
    wipeStdString(passUtf8);

#ifdef USE_QT_UI
    qCDebug(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.decrypt.finish",
         "result=ok",
         seal::diag::kv("username_chars", cred.username.size()),
         seal::diag::kv("credential_chars", cred.username.size() + cred.password.size())}));
#endif
    return cred;
}

seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> decryptUsernameOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
#ifdef USE_QT_UI
    qCDebug(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.decrypt_username.begin",
         seal::diag::kv("platform_len", record.platform.size()),
         seal::diag::kv("encrypted_blob_len", record.encryptedBlob.size())}));
#endif
    auto plainBytes = seal::Cryptography::decryptPacket(
        std::span<const unsigned char>(record.encryptedBlob), password);

    const char* data = reinterpret_cast<const char*>(plainBytes.data());
    const size_t len = plainBytes.size();

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
#ifdef USE_QT_UI
        qCWarning(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=credential.decrypt_username.finish",
             "result=fail",
             "reason=malformed_blob",
             seal::diag::kv("encrypted_blob_len", record.encryptedBlob.size())}));
#endif
        seal::Cryptography::cleanseString(plainBytes);
        throw std::runtime_error("Malformed credential blob");
    }

    std::string userUtf8(data, sep);
    seal::Cryptography::cleanseString(plainBytes);

    auto username = seal::utils::utf8ToSecureWide(userUtf8);
    wipeStdString(userUtf8);

#ifdef USE_QT_UI
    qCDebug(logVault).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=credential.decrypt_username.finish",
                                "result=ok",
                                seal::diag::kv("username_chars", username.size())}));
#endif
    return username;
}

VaultRecord encryptCredential(
    const std::string& platform,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword,
    const seal::cfg::KdfParams& kdf)
{
#ifdef USE_QT_UI
    qCDebug(logVault).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.encrypt.begin", seal::diag::kv("platform_len", platform.size())}));
#endif
    // Wide chars -> UTF-8 for the on-disk format.
    std::string userUtf8 = seal::utils::secureWideToUtf8(username);
    std::string passUtf8 = seal::utils::secureWideToUtf8(password);

    // Plaintext format: "username\0password" - mirrors what
    // decryptCredentialOnDemand splits on.
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
        masterPassword,
        kdf);
    wipeStdString(credPlain);

    auto platformBlob = encryptString(platform, masterPassword, kdf);

    VaultRecord rec;
    rec.platform = platform;
    rec.encryptedPlatform = std::move(platformBlob);
    rec.encryptedBlob = std::move(credBlob);
    rec.dirty = true;
    rec.deleted = false;
#ifdef USE_QT_UI
    qCDebug(logVault).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=credential.encrypt.finish",
                                "result=ok",
                                seal::diag::kv("platform_blob_len", rec.encryptedPlatform.size()),
                                seal::diag::kv("credential_blob_len", rec.encryptedBlob.size())}));
#endif
    return rec;
}

// Shared body for encryptDirectory()/decryptDirectory(): recursively collect
// eligible files (skipping symlinks/dirs), then op each one and delete the
// source on success. `encrypt` selects the extension filter, the destination
// name, and the crypto op; behaviour is otherwise identical.
static int processDirectoryFiles(
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    bool encrypt)
{
    int count = 0;
    const std::string opId =
        seal::diag::nextOpId(encrypt ? "vault_dir_encrypt" : "vault_dir_decrypt");
    const auto started = std::chrono::steady_clock::now();
    const std::string pathMeta = pathMetaString(dirPath);
    const char* eventBase = encrypt ? "directory.encrypt" : "directory.decrypt";

    logVaultInfo({std::string("event=") + eventBase + ".begin",
                  "result=start",
                  seal::diag::kv("op", opId),
                  pathMeta});
    try
    {
        // Collect paths first, rename in a second pass. Renaming during
        // recursive_directory_iterator can skip or double-visit entries.
        namespace fs = std::filesystem;
        std::vector<std::string> filePaths;
        for (const auto& entry : fs::recursive_directory_iterator(
                 dirPath, fs::directory_options::skip_permission_denied))
        {
            if (entry.is_symlink() || !entry.is_regular_file())
            {
                continue;
            }

            const std::string ext = entry.path().extension().string();
            const bool isSeal = seal::utils::endsWithCi(ext, ".seal");
            if (encrypt)
            {
                // Skip already-encrypted files and non-payload binaries.
                if (isSeal || seal::utils::endsWithCi(ext, ".exe") ||
                    seal::utils::endsWithCi(ext, ".dll") || seal::utils::endsWithCi(ext, ".pdb"))
                {
                    continue;
                }
            }
            else if (!isSeal)
            {
                continue;
            }

            filePaths.push_back(entry.path().string());
        }

        for (const auto& filePath : filePaths)
        {
            const std::string newPath =
                encrypt ? filePath + ".seal" : seal::utils::strip_ext_ci(filePath, ".seal");
            const bool ok = encrypt ? FileOperations::encryptFileTo(filePath, newPath, password)
                                    : FileOperations::decryptFileTo(filePath, newPath, password);
            if (ok)
            {
                DeleteFileA(filePath.c_str());
                count++;
            }
        }
    }
    catch (const std::exception& e)
    {
        logVaultWarn({std::string("event=") + eventBase + ".finish",
                      "result=partial",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("count", count),
                      seal::diag::errorFields(e.what()),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      pathMeta});
        return count;
    }

    logVaultInfo({std::string("event=") + eventBase + ".finish",
                  "result=ok",
                  seal::diag::kv("op", opId),
                  seal::diag::kv("count", count),
                  seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                  pathMeta});
    return count;
}

int encryptDirectory(
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    return processDirectoryFiles(dirPath, password, /*encrypt=*/true);
}

int decryptDirectory(
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
{
    return processDirectoryFiles(dirPath, password, /*encrypt=*/false);
}

}  // namespace seal
