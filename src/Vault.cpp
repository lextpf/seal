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
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

// wipe character storage, including SSO slack, without corrupting string metadata.
void wipeStdString(std::string& s)
{
    if (!s.empty())
    {
        // capacity includes stale SSO bytes beyond size().
        SecureZeroMemory(s.data(), s.capacity());
    }
    s.clear();
    s.shrink_to_fit();
}

// attempt a durable data flush before rename; directory metadata does not flush file bytes.
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

// vault binary format: magic(4 "SVH2") + version(1) + count(4 BE) +
// N records. each record: platformLen(4 BE) + blob + credLen(4 BE) + blob.
// the binary frame is hex-encoded into a single text string on disk.
constexpr unsigned char kVaultMagic[4] = {'S', 'V', 'H', '2'};
constexpr unsigned char kVaultFormatVersion = 1;

// all multi-byte ints use big-endian for cross-machine portability.
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

// ASCII-only lookup deliberately differs from the Qt list filter.
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

// choose the first regular .seal extension by ordinal filename; hidden .seal is excluded.
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

// non-Qt builds omit emission but still construct diagnostic fields.
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

bool looksLikeVault(const std::filesystem::path& path) noexcept
{
    try
    {
        // require the full nine-byte frame header to reject magic-only truncation.
        constexpr std::size_t kHeaderHexCharacters = 18;
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in)
        {
            return false;
        }

        std::string compactHeader;
        compactHeader.reserve(kHeaderHexCharacters);
        char ch = '\0';
        // cap physical reads so whitespace cannot make a sniff scan an entire file.
        constexpr std::size_t kMaximumBytesToRead = 4096;
        std::size_t bytesRead = 0;
        while (compactHeader.size() < kHeaderHexCharacters && bytesRead < kMaximumBytesToRead &&
               in.get(ch))
        {
            ++bytesRead;
            const unsigned char byte = static_cast<unsigned char>(ch);
            if (std::isspace(byte) != 0)
            {
                continue;
            }
            if (std::isxdigit(byte) == 0)
            {
                return false;
            }
            compactHeader.push_back(ch);
        }
        if (compactHeader.size() != kHeaderHexCharacters)
        {
            return false;
        }

        std::vector<unsigned char> decoded;
        if (!seal::utils::from_hex(std::string_view{compactHeader}, decoded) || decoded.size() < 4)
        {
            return false;
        }
        return std::equal(std::begin(kVaultMagic), std::end(kVaultMagic), decoded.begin());
    }
    catch (...)
    {
        return false;
    }
}

bool isVaultCandidateName(const std::filesystem::path& path) noexcept
{
    try
    {
        const std::wstring fileName = path.filename().wstring();
        const std::wstring extension = path.extension().wstring();
        const auto equalsSeal = [](const std::wstring& value)
        {
            return CompareStringOrdinal(
                       value.data(), static_cast<int>(value.size()), L".seal", 5, TRUE) ==
                   CSTR_EQUAL;
        };
        return equalsSeal(fileName) || equalsSeal(extension);
    }
    catch (...)
    {
        return false;
    }
}

std::filesystem::path selectVaultCandidate(std::span<const VaultCandidate> candidates)
{
    const auto found = std::find_if(candidates.begin(),
                                    candidates.end(),
                                    [](const VaultCandidate& item) { return item.vault; });
    return found != candidates.end() ? found->path : std::filesystem::path{};
}

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

// platform names use pageable storage because the list displays them; secrets use locked memory.
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
    // each record requires at least two u32 lengths.
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
            // Stop after the first rejected platform packet; do not derive keys for later records.
            logVaultWarn({"event=vault.index.load.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=wrong_password",
                          seal::diag::kv("entry_index", i),
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))});
            throw std::runtime_error("Wrong password");
        }
    }
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

        // reuse clean platform packets to avoid another scrypt derivation.
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

    const std::string hexBlob = seal::utils::to_hex(framed);
    out.write(hexBlob.data(), static_cast<std::streamsize>(hexBlob.size()));
    out.flush();
    bool ok = out.good();
    out.close();

    if (ok)
    {
        flushPathToDisk(tmpPath);

        // NTFS replacement is atomic; cross-volume fallback copies and deletes.
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
    if (const char* env = std::getenv("SEAL_VAULT"); env != nullptr && env[0] != '\0')
    {
        std::filesystem::path p{env};
        std::error_code ec;
        if (std::filesystem::exists(p, ec))
        {
            return p;
        }
    }

    wchar_t exeBuf[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, exeBuf, MAX_PATH) > 0)
    {
        if (auto hit = firstSealFileIn(std::filesystem::path{exeBuf}.parent_path()); !hit.empty())
        {
            return hit;
        }
    }

    std::error_code ec;
    if (auto hit = firstSealFileIn(std::filesystem::current_path(ec)); !hit.empty())
    {
        return hit;
    }

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

    std::vector<VaultRecord> records = loadVaultIndex(vaultPath, currentPassword);

    std::filesystem::path tmpPath = vaultPath;
    tmpPath += ".rekey.tmp";

    try
    {
        // keep at most one credential plaintext during rekey.
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

        // verify the new key and structure before replacing the original.
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

        flushPathToDisk(tmpPath);

        if (!ReplaceFileW(vaultPath.c_str(),
                          tmpPath.c_str(),
                          nullptr,
                          REPLACEFILE_IGNORE_MERGE_ERRORS,
                          nullptr,
                          nullptr))
        {
            // ReplaceFileW needs an existing target; other filesystems can require fallback.
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
    auto plainBytes = seal::Cryptography::decryptPacket(
        std::span<const unsigned char>(record.encryptedBlob), password);

    const char* data = reinterpret_cast<const char*>(plainBytes.data());
    size_t len = plainBytes.size();

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
    std::string userUtf8 = seal::utils::secureWideToUtf8(username);
    std::string passUtf8 = seal::utils::secureWideToUtf8(password);

    // credential format: "username\0password".
    std::string credPlain;
    credPlain.reserve(userUtf8.size() + 1 + passUtf8.size());
    credPlain.append(userUtf8);
    credPlain.push_back('\0');
    credPlain.append(passUtf8);
    wipeStdString(userUtf8);
    wipeStdString(passUtf8);

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

ProtectedFolderScan scanProtectedFolder(const std::filesystem::path& root)
{
    namespace fs = std::filesystem;

    ProtectedFolderScan scan;
    std::error_code ec;
    if (root.empty() || !fs::is_directory(root, ec))
    {
        scan.failures = 1;
        return scan;
    }

    fs::recursive_directory_iterator iterator(root, fs::directory_options::none, ec);
    const fs::recursive_directory_iterator end;
    if (ec)
    {
        scan.failures = 1;
        return scan;
    }

    while (iterator != end)
    {
        const fs::directory_entry item = *iterator;
        const DWORD attributes = GetFileAttributesW(item.path().c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            iterator.disable_recursion_pending();
            ++scan.failures;
        }
        else if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        {
            // retain reparse points for policy diagnostics without following them.
            iterator.disable_recursion_pending();
            const fs::path relative = item.path().lexically_relative(root);
            if (!relative.empty())
            {
                scan.entries.push_back({relative, 0, true, false});
            }
            else
            {
                ++scan.failures;
            }
        }
        else
        {
            std::error_code statusError;
            if (item.is_regular_file(statusError))
            {
                const fs::path relative = item.path().lexically_relative(root);
                if (relative.empty())
                {
                    ++scan.failures;
                }
                else
                {
                    std::error_code sizeError;
                    const std::uintmax_t size = item.file_size(sizeError);
                    if (sizeError)
                    {
                        ++scan.failures;
                    }
                    scan.entries.push_back(
                        {relative, sizeError ? 0 : size, false, looksLikeVault(item.path())});
                }
            }
            else if (statusError)
            {
                ++scan.failures;
            }
        }

        iterator.increment(ec);
        if (ec)
        {
            ++scan.failures;
            // stop on iterator errors; a partial inventory must fail preflight/exit protection.
            break;
        }
    }

    std::sort(scan.entries.begin(),
              scan.entries.end(),
              [](const protected_folder::Entry& lhs, const protected_folder::Entry& rhs)
              { return lhs.relativePath.generic_wstring() < rhs.relativePath.generic_wstring(); });
    return scan;
}

namespace
{

bool isSafeRelativeEntry(const std::filesystem::path& relative)
{
    if (relative.empty() || relative.is_absolute() || relative.has_root_path())
    {
        return false;
    }
    for (const auto& component : relative.lexically_normal())
    {
        if (component == L"..")
        {
            return false;
        }
    }
    return true;
}

enum class PathProbe
{
    Missing,
    Present,
    Error,
};

PathProbe probePathWithoutFollowing(const std::filesystem::path& path)
{
    std::error_code error;
    const std::filesystem::file_status status = std::filesystem::symlink_status(path, error);
    if (!error)
    {
        return status.type() == std::filesystem::file_type::not_found ? PathProbe::Missing
                                                                      : PathProbe::Present;
    }
    if (error == std::errc::no_such_file_or_directory)
    {
        return PathProbe::Missing;
    }
    return PathProbe::Error;
}

struct WindowsPathLess
{
    bool operator()(const std::wstring& lhs, const std::wstring& rhs) const noexcept
    {
        const int result = CompareStringOrdinal(lhs.data(),
                                                static_cast<int>(lhs.size()),
                                                rhs.data(),
                                                static_cast<int>(rhs.size()),
                                                TRUE);
        // API failure uses lexical fallback to keep the comparator ordered.
        return result == CSTR_LESS_THAN || (result == 0 && lhs < rhs);
    }
};

std::filesystem::path transformDestination(const std::filesystem::path& source, bool encrypt)
{
    std::filesystem::path destination = source;
    if (encrypt)
    {
        destination += L".seal";
    }
    else
    {
        destination.replace_extension();
    }
    return destination;
}

}  // namespace

DirectoryProcessResult processFolderPlan(
    const std::filesystem::path& root,
    const protected_folder::FolderPlan& plan,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    bool encrypt)
{
    namespace fs = std::filesystem;

    DirectoryProcessResult result;
    const std::string opId =
        seal::diag::nextOpId(encrypt ? "vault_dir_encrypt" : "vault_dir_decrypt");
    const auto started = std::chrono::steady_clock::now();
    const std::string pathMeta = pathMetaString(root);
    const char* eventBase = encrypt ? "directory.encrypt" : "directory.decrypt";

    logVaultInfo({std::string("event=") + eventBase + ".begin",
                  "result=start",
                  seal::diag::kv("op", opId),
                  seal::diag::kv("planned", plan.act.size()),
                  seal::diag::kv("skipped", plan.skipped.size()),
                  pathMeta});

    // reserve all staging names before execution so they cannot become later source entries.
    std::set<std::wstring, WindowsPathLess> reservedTemporaryPaths;
    for (const protected_folder::Entry& entry : plan.act)
    {
        if (!isSafeRelativeEntry(entry.relativePath))
        {
            continue;
        }
        fs::path temporary = transformDestination(entry.relativePath, encrypt);
        temporary += L".tmp";
        reservedTemporaryPaths.insert(temporary.lexically_normal().generic_wstring());
    }

    for (const auto& [entry, reason] : plan.skipped)
    {
        logVaultInfo({"event=directory.plan.skip",
                      "result=skip",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("reason", protected_folder::skipReasonToken(reason)),
                      pathMetaString(entry.relativePath)});
    }

    for (const protected_folder::Entry& entry : plan.act)
    {
        try
        {
            if (!isSafeRelativeEntry(entry.relativePath))
            {
                ++result.failed;
                continue;
            }

            if (reservedTemporaryPaths.contains(
                    entry.relativePath.lexically_normal().generic_wstring()))
            {
                ++result.failed;
                logVaultWarn({"event=directory.transform.blocked",
                              "result=fail",
                              seal::diag::kv("op", opId),
                              "reason=reserved_temporary",
                              pathMetaString(entry.relativePath)});
                continue;
            }

            const fs::path source = root / entry.relativePath;
            const DWORD sourceAttributes = GetFileAttributesW(source.c_str());
            std::error_code statusError;
            const fs::file_status status = fs::symlink_status(source, statusError);
            if (sourceAttributes == INVALID_FILE_ATTRIBUTES ||
                (sourceAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || statusError ||
                fs::is_symlink(status) || !fs::is_regular_file(status))
            {
                ++result.failed;
                continue;
            }

            // recheck vault magic because source identity may have changed since planning.
            if (looksLikeVault(source))
            {
                logVaultInfo({"event=directory.plan.skip",
                              "result=skip",
                              seal::diag::kv("op", opId),
                              "reason=credential_vault",
                              pathMetaString(entry.relativePath)});
                continue;
            }

            const fs::path destination = transformDestination(source, encrypt);

            // refuse occupied output/staging names; symlink_status rejects dangling links.
            fs::path temporary = destination;
            temporary += L".tmp";
            const PathProbe destinationProbe = probePathWithoutFollowing(destination);
            const PathProbe temporaryProbe = probePathWithoutFollowing(temporary);
            if (destinationProbe != PathProbe::Missing || temporaryProbe != PathProbe::Missing)
            {
                ++result.failed;
                logVaultWarn({"event=directory.transform.blocked",
                              "result=fail",
                              seal::diag::kv("op", opId),
                              destinationProbe == PathProbe::Present ? "reason=destination_exists"
                              : temporaryProbe == PathProbe::Present
                                  ? "reason=temporary_exists"
                                  : "reason=destination_probe_failed",
                              pathMetaString(entry.relativePath)});
                continue;
            }

            const bool transformed = encrypt ? FileOperations::encryptFileTo(
                                                   source.string(), destination.string(), password)
                                             : FileOperations::decryptFileTo(
                                                   source.string(), destination.string(), password);
            if (!transformed)
            {
                ++result.failed;
                continue;
            }

            std::error_code removeError;
            const bool removed = fs::remove(source, removeError);
            if (!removed || removeError)
            {
                ++result.failed;
                continue;
            }
            ++result.succeeded;
        }
        catch (const std::exception&)
        {
            ++result.failed;
        }
    }

    const auto fields = {
        std::string("event=") + eventBase + ".finish",
        result.failed == 0 ? std::string("result=ok") : std::string("result=partial"),
        seal::diag::kv("op", opId),
        seal::diag::kv("count", result.succeeded),
        seal::diag::kv("failed", result.failed),
        seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
        pathMeta};
    if (result.failed == 0)
    {
        logVaultInfo(fields);
    }
    else
    {
        logVaultWarn(fields);
    }
    return result;
}

// manual GUI operations return successes only; scan failures are not logged here.
static int processDirectoryFiles(
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    bool encrypt)
{
    ProtectedFolderScan scan = scanProtectedFolder(dirPath);
    const protected_folder::PolicyContext context;
    const protected_folder::FolderPlan plan =
        encrypt ? protected_folder::planEncrypt(scan.entries, context)
                : protected_folder::planDecrypt(scan.entries, context);
    DirectoryProcessResult result = processFolderPlan(dirPath, plan, password, encrypt);
    result.failed += scan.failures;
    return static_cast<int>(result.succeeded);
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
