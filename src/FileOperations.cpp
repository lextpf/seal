#include "FileOperations.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <bit>

namespace seal
{

// Serialize a (service, user, password) triple into the colon-delimited
// wire format "service:user:pass".  Each field is stored internally as
// UTF-16 (wchar_t on Windows), so we must convert to UTF-8 first.
std::string FileOperations::tripleToUtf8(const seal::secure_triplet16_t& t)
{
    auto to_utf8 = [](auto& w)
    {
        if (w.size() == 0)
            return std::string{};
        // First call: pass nullptr dest to query how many UTF-8 bytes we need.
        int need =
            WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string out(need, '\0');
        // Second call: actually write the converted bytes into the buffer.
        WideCharToMultiByte(
            CP_UTF8, 0, w.data(), (int)w.size(), out.data(), need, nullptr, nullptr);
        return out;
    };
    std::string s = to_utf8(t.primary), u = to_utf8(t.secondary), p = to_utf8(t.tertiary);
    std::string out;
    // +2 accounts for the two ':' delimiters between the three fields.
    out.reserve(s.size() + u.size() + p.size() + 2);
    out.append(s).push_back(':');
    out.append(u).push_back(':');
    out.append(p);
    return out;
}

template <secure_password SecurePwd>
bool FileOperations::encryptFileInPlace(const std::string& path, const SecurePwd& pwd)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        std::cerr << "(encrypt) cannot open: " << path << "\n";
        return false;
    }
    std::vector<unsigned char> plain((std::istreambuf_iterator<char>(in)), {});
    in.close();
    auto packet = seal::Cryptography::encryptPacket(std::span<const unsigned char>(plain), pwd);
    // Wipe plaintext from memory as soon as encryption is done.
    seal::Cryptography::cleanseString(plain);

    // Atomic write pattern: write ciphertext to a .tmp file first, then
    // atomically rename it over the original. This ensures the original
    // file is never left in a half-written state (e.g. on disk-full or
    // crash), because MoveFileExA is an atomic replace on NTFS.
    std::string tmpPath = path + ".tmp";
    std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cerr << "(encrypt) cannot write temp file: " << tmpPath << "\n";
        return false;
    }
    out.write(reinterpret_cast<const char*>(packet.data()), (std::streamsize)packet.size());
    out.flush();
    if (!out)
    {
        std::cerr << "(encrypt) write failed: " << tmpPath << "\n";
        out.close();
        DeleteFileA(tmpPath.c_str());
        return false;
    }
    out.close();

    if (!MoveFileExA(tmpPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING))
    {
        std::cerr << "(encrypt) cannot replace original: " << path << "\n";
        DeleteFileA(tmpPath.c_str());
        return false;
    }
    return true;
}

template <secure_password SecurePwd>
bool FileOperations::decryptFileInPlace(const std::string& path, const SecurePwd& pwd)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        std::cerr << "(decrypt) cannot open: " << path << "\n";
        return false;
    }
    std::vector<unsigned char> blob((std::istreambuf_iterator<char>(in)), {});
    in.close();
    try
    {
        auto plain = seal::Cryptography::decryptPacket(std::span<const unsigned char>(blob), pwd);

        // Atomic write pattern (same as encryptFileInPlace): write to .tmp,
        // then rename over the original so we never corrupt the source file.
        std::string tmpPath = path + ".tmp";
        std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            std::cerr << "(decrypt) cannot write temp file: " << tmpPath << "\n";
            seal::Cryptography::cleanseString(plain);
            return false;
        }
        out.write(reinterpret_cast<const char*>(plain.data()), (std::streamsize)plain.size());
        out.flush();
        // Wipe plaintext from memory immediately after flushing to disk,
        // BEFORE checking the stream state. This minimizes the window during
        // which decrypted data sits in process memory, even on write failure.
        seal::Cryptography::cleanseString(plain);
        if (!out)
        {
            std::cerr << "(decrypt) write failed: " << tmpPath << "\n";
            out.close();
            DeleteFileA(tmpPath.c_str());
            return false;
        }
        out.close();

        if (!MoveFileExA(tmpPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            std::cerr << "(decrypt) cannot replace original: " << path << "\n";
            DeleteFileA(tmpPath.c_str());
            return false;
        }
        return true;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(decrypt) " << e.what() << "\n";
        return false;
    }
}

// Encrypt a single plaintext string and return it as a hex-encoded string.
// The round-trip is: plaintext bytes -> encrypt -> raw ciphertext -> hex.
// Hex encoding makes the ciphertext safe to paste into terminals, logs, etc.
template <secure_password SecurePwd>
std::string FileOperations::encryptLine(const std::string& s, const SecurePwd& pwd)
{
    auto packet = seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()), s.size()),
        pwd);
    return seal::utils::to_hex(packet);
}

// Reverse of encryptLine: hex string -> raw ciphertext bytes -> decrypt -> plaintext.
// Spaces are stripped first so the user can paste hex with whitespace formatting.
template <secure_password SecurePwd>
seal::secure_string<seal::locked_allocator<char>> FileOperations::decryptLine(
    const std::string& rawHex, const SecurePwd& pwd)
{
    std::string compact = seal::utils::stripSpaces(rawHex);
    std::vector<unsigned char> blob;
    // Decode hex back to the raw ciphertext bytes that encryptLine produced.
    if (!seal::utils::from_hex(std::string_view{compact}, blob))
        throw std::runtime_error("Invalid hex input");
    auto bytes = seal::Cryptography::decryptPacket(std::span<const unsigned char>(blob), pwd);
    // Move decrypted bytes into a locked-allocator string (non-pageable memory).
    seal::secure_string<seal::locked_allocator<char>> out;
    out.s.assign(reinterpret_cast<const char*>(bytes.data()),
                 reinterpret_cast<const char*>(bytes.data()) + bytes.size());
    seal::Cryptography::cleanseString(bytes);
    return out;
}

// Parse a flat string of colon-delimited triples separated by commas or
// newlines.  Expected format: "svc1:user1:pass1,svc2:user2:pass2\n...".
// Each token must contain EXACTLY 2 colons (3 fields). Fewer means the
// data is incomplete; more means ambiguous field boundaries. Any violation
// fails the entire parse so callers get all-or-nothing semantics.
template <class A>
bool FileOperations::parseTriples(std::string_view plain,
                                  std::vector<seal::secure_triplet16<A>>& out)
{
    out.clear();
    std::string tok;

    // flush: validate and consume one accumulated token.
    auto flush = [&](std::string& t) -> bool
    {
        std::string s = seal::utils::trim(t);
        t.clear();
        if (s.empty())
            return true;

        // Locate the first and second colons. Reject if there are fewer
        // than 2 (incomplete triple) or more than 2 (ambiguous fields).
        size_t c1 = s.find(':'),
               c2 = (c1 == std::string::npos ? std::string::npos : s.find(':', c1 + 1));
        if (c1 == std::string::npos || c2 == std::string::npos ||
            s.find(':', c2 + 1) != std::string::npos)
            return false;

        auto mk = [&](size_t off, size_t len)
        {
            seal::basic_secure_string<wchar_t, A> r;
            if (len == 0)
                return r;
            const char* src = s.data() + off;
            int need = MultiByteToWideChar(CP_UTF8, 0, src, (int)len, nullptr, 0);
            if (need > 0)
            {
                r.s.resize(need);
                MultiByteToWideChar(CP_UTF8, 0, src, (int)len, r.s.data(), need);
            }
            return r;
        };

        // Split into (service, username, password) around the two colons.
        out.emplace_back(mk(0, c1), mk(c1 + 1, c2 - (c1 + 1)), mk(c2 + 1, s.size() - (c2 + 1)));
        return true;
    };

    // Commas and newlines both act as triple separators, so a single
    // encrypted blob can carry multiple credentials in one payload.
    for (char ch : plain)
    {
        if (ch == ',' || ch == '\n' || ch == '\r')
        {
            if (!flush(tok))
            {
                out.clear();
                return false;
            }
        }
        else
        {
            tok.push_back(ch);
        }
    }
    // Don't forget the last token (no trailing delimiter required).
    if (!flush(tok))
    {
        out.clear();
        return false;
    }
    return !out.empty();
}

// Walk a directory with FindFirstFileA/FindNextFileA, encrypting or
// decrypting every file based on its .seal extension (see processFilePath).
// Subdirectories are processed recursively via std::async.
template <secure_password SecurePwd>
bool FileOperations::processDirectory(const std::string& dir,
                                      const SecurePwd& password,
                                      bool recurse)
{
    WIN32_FIND_DATAA fd{};
    // "*" wildcard matches all entries in the directory.
    std::string pattern = seal::utils::joinPath(dir, "*");
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        std::cerr << "(dir) cannot list: " << dir << "\n";
        return false;
    }

    static constexpr size_t MAX_CONCURRENT = 8;

    uint64_t total = 0, ok = 0, fail = 0;
    std::vector<std::future<bool>> futures;

    // Drain completed futures when the batch reaches the concurrency cap.
    auto drainFutures = [&]()
    {
        for (auto& f : futures)
        {
            if (f.get())
                ++ok;
            else
                ++fail;
        }
        futures.clear();
    };

    do
    {
        const char* name = fd.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;
        // Skip reparse points (symlinks, junctions, mount points). Following
        // them could escape the intended directory tree or cause infinite
        // loops if a junction points back up the hierarchy.
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        std::string full = seal::utils::joinPath(dir, name);

        if (seal::utils::endsWithCi(name, ".exe") || _stricmp(name, "seal") == 0)
        {
            std::cout << "(skipped) " << full << "\n";
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            // Recurse into subdirectories asynchronously so sibling
            // directories can be processed in parallel.
            if (recurse)
            {
                futures.push_back(std::async(std::launch::async,
                                             FileOperations::processDirectory<SecurePwd>,
                                             full,
                                             std::ref(password),
                                             true));
            }
            continue;
        }

        // Launch each file encrypt/decrypt on the thread pool.
        futures.push_back(std::async(std::launch::async,
                                     FileOperations::processFilePath<SecurePwd>,
                                     full,
                                     std::ref(password)));
        ++total;

        if (futures.size() >= MAX_CONCURRENT)
        {
            drainFutures();
        }

    } while (FindNextFileA(h, &fd));

    FindClose(h);

    drainFutures();

    std::cout << "[dir] " << dir << ": " << ok << " ok, " << fail << " failed, " << total
              << " total\n";
    return fail == 0;
}

// Decide whether to encrypt or decrypt a single path based on its extension.
// Files ending in ".seal" are decrypted (extension removed); all others are
// encrypted (extension appended). This toggle means running the same command
// twice round-trips a file back to its original state.
template <secure_password SecurePwd>
bool FileOperations::processFilePath(const std::string& raw, const SecurePwd& password)
{
    std::string t = seal::utils::stripQuotes(seal::utils::trim(raw));
    if (t.empty())
        return false;

    std::string base = seal::utils::basenameA(t);
    if (seal::utils::endsWithCi(base, ".exe") || _stricmp(base.c_str(), "seal") == 0)
    {
        std::cout << "(skipped) " << t << "\n";
        return true;
    }

    // "." is a shorthand for the current working directory, letting the
    // user encrypt/decrypt everything in cwd without typing the full path.
    if (_stricmp(t.c_str(), ".") == 0)
    {
        t = std::filesystem::current_path().string();
    }

    if (seal::utils::isDirectoryA(t))
    {
        return processDirectory(t, password, true);
    }

    if (!seal::utils::fileExistsA(t))
        return false;

    // Extension toggle: .seal present -> decrypt and strip it;
    // .seal absent -> encrypt and append it.
    const bool isPmg = seal::utils::endsWithCi(t, ".seal");

    if (isPmg)
    {
        // Decrypt: strip the .seal extension to restore the original filename.
        std::string newName = seal::utils::strip_ext_ci(t, std::string_view{".seal"});
        bool success = FileOperations::decryptFileInPlace(t, password);

        if (success)
        {
            if (MoveFileExA(t.c_str(), newName.c_str(), MOVEFILE_REPLACE_EXISTING))
            {
                std::cout << "(decrypted) " << t << " -> " << newName << "\n";
            }
            else
            {
                std::cerr << "(decrypt) failed to rename: " << t << " -> " << newName << "\n";
                return false;
            }
        }
        return success;
    }
    else
    {
        // Encrypt: append .seal so the file is recognized as encrypted later.
        std::string newName = seal::utils::add_ext(t, std::string_view{".seal"});
        bool success = FileOperations::encryptFileInPlace(t, password);

        if (success)
        {
            if (MoveFileExA(t.c_str(), newName.c_str(), MOVEFILE_REPLACE_EXISTING))
            {
                std::cout << "(encrypted) " << t << " -> " << newName << "\n";
            }
            else
            {
                std::cerr << "(encrypt) failed to rename: " << t << " -> " << newName << "\n";
                return false;
            }
        }
        return success;
    }
}

// Decrypt a batch of hex-encoded ciphertext tokens. Each decrypted result is
// tested against the colon-delimited triple format. If it parses as triples,
// they are aggregated into aggTriples for structured display. Otherwise the
// plaintext is treated as opaque data: copied to the clipboard (with a TTL)
// and collected in otherPlain for raw output.
template <secure_password SecurePwd>
static void decryptHexTokens(const std::vector<std::string>& hexTokens,
                             const SecurePwd& password,
                             std::vector<seal::secure_triplet16_t>& aggTriples,
                             std::vector<std::string>& otherPlain)
{
    for (const auto& tok : hexTokens)
    {
        try
        {
            auto plain = FileOperations::decryptLine(tok, password);

            std::vector<seal::secure_triplet16<seal::locked_allocator<wchar_t>>> ts;
            if (FileOperations::parseTriples(plain.view(), ts))
            {
                // Structured credential data -- collect for batch display.
                aggTriples.insert(aggTriples.end(),
                                  std::make_move_iterator(ts.begin()),
                                  std::make_move_iterator(ts.end()));
            }
            else
            {
                // Not a triple -- fallback: copy raw plaintext to clipboard.
                (void)seal::Clipboard::copyWithTTL(plain.view());
                otherPlain.emplace_back(plain.data(), plain.size());
            }
            seal::Cryptography::cleanseString(plain);
        }
        catch (const std::exception& ex)
        {
            std::cerr << "(decrypt failed: " << ex.what() << ")\n";
        }
    }
}

// Print decrypted triples to the console.  In uncensored mode the full
// "service:user:pass" text is printed.  In censored (default) mode, the
// password fields are masked with asterisks and the user clicks to copy
// individual values via the interactive masked-output UI.
static void displayTriples(std::vector<seal::secure_triplet16_t>& aggTriples, bool uncensored)
{
    if (uncensored)
    {
        // Uncensored: dump all triples comma-separated in plaintext.
        std::ostringstream oss;
        for (size_t i = 0; i < aggTriples.size(); ++i)
        {
            if (i)
                oss << ", ";
            std::string sv = FileOperations::tripleToUtf8(aggTriples[i]);
            oss << sv;
            seal::Cryptography::cleanseString(sv);
        }
        std::string printed = oss.str();
        std::cout << printed << "\n";
        seal::Cryptography::cleanseString(printed);
        // Wipe the ostringstream's internal buffer so plaintext does not
        // linger on the heap after display.
        std::string ossBuf = std::move(oss).str();
        seal::Cryptography::cleanseString(ossBuf);
    }
    else
    {
        // Censored: show masked fields with click-to-copy behavior.
        interactiveMaskedWin(aggTriples);
        std::cout << "(Masked; Click **** to copy)\n";
    }
    // Wipe all sensitive fields from memory after display.
    for (auto& t : aggTriples)
    {
        seal::Cryptography::cleanseString(t.primary, t.secondary, t.tertiary);
    }
}

// Process a batch of user-supplied input lines with a three-tier dispatch:
//   1. File paths -- encrypt or decrypt files on disk (highest priority).
//   2. Hex tokens -- treat as ciphertext, decrypt and display/copy.
//   3. Plain text -- anything else is encrypted and printed as hex.
// This priority order means a line that happens to look like valid hex but
// also resolves to a real file path will be treated as a file path.
template <secure_password SecurePwd>
void FileOperations::processBatch(const std::vector<std::string>& lines,
                                  bool uncensored,
                                  const SecurePwd& password)
{
    if (lines.empty())
        return;

    std::vector<seal::secure_triplet16_t> aggTriples;
    std::vector<std::string> otherPlain;
    std::vector<std::string> encHex;

    for (const auto& L : lines)
    {
        // Priority 1: try to handle as a file/directory path.
        if (processFilePath(L, password))
            continue;

        // Priority 2: if the line contains hex-encoded ciphertext, decrypt it.
        auto hexTokens = seal::utils::extractHexTokens(L);
        if (!hexTokens.empty())
        {
            decryptHexTokens(hexTokens, password, aggTriples, otherPlain);
            continue;
        }

        // Priority 3: treat as plaintext and encrypt to hex for output.
        try
        {
            encHex.emplace_back(encryptLine(L, password));
        }
        catch (const std::exception& ex)
        {
            std::cerr << "(encrypt failed: " << ex.what() << ")\n";
        }
    }

    if (!aggTriples.empty())
        displayTriples(aggTriples, uncensored);

    for (auto& p : otherPlain)
    {
        if (uncensored)
            std::cout << p << "\n";
        else
        {
            (void)seal::Clipboard::copyWithTTL(p);
            std::cout << std::string(p.size(), '*') << "  [copied]\n";
        }
        seal::Cryptography::cleanseString(p);
    }

    for (const auto& hex : encHex)
        std::cout << hex << "\n";
}

// Read all of stdin as binary, encrypt, and write raw ciphertext to stdout.
// Designed for shell pipe integration, e.g.: cat secret | seal --encrypt | ...
// stdin/stdout must be in binary mode (set by the caller) so that Windows
// CRLF translation does not corrupt the ciphertext byte stream.
template <secure_password SecurePwd>
bool FileOperations::streamEncrypt(const SecurePwd& password)
{
    try
    {
        // Slurp all of stdin into memory (binary pipe, no line buffering).
        std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(std::cin)),
                                             std::istreambuf_iterator<char>());

        if (plaintext.empty())
        {
            std::cerr << "(encrypt) No data read from stdin\n";
            return false;
        }

        auto packet =
            seal::Cryptography::encryptPacket(std::span<const unsigned char>(plaintext), password);

        std::cout.write(reinterpret_cast<const char*>(packet.data()),
                        static_cast<std::streamsize>(packet.size()));

        if (!std::cout.good())
        {
            std::cerr << "(encrypt) Failed to write to stdout\n";
            seal::Cryptography::cleanseString(plaintext);
            return false;
        }

        seal::Cryptography::cleanseString(plaintext);
        return true;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(encrypt) " << e.what() << "\n";
        return false;
    }
}

// Inverse of streamEncrypt: read raw ciphertext from stdin, decrypt, and
// write plaintext to stdout. Used for shell pipe decryption, e.g.:
//   cat secret.seal | seal --decrypt > secret.txt
// Same binary-mode requirement as streamEncrypt.
template <secure_password SecurePwd>
bool FileOperations::streamDecrypt(const SecurePwd& password)
{
    try
    {
        // Slurp all of stdin (raw ciphertext bytes).
        std::vector<unsigned char> packet((std::istreambuf_iterator<char>(std::cin)),
                                          std::istreambuf_iterator<char>());

        if (packet.empty())
        {
            std::cerr << "(decrypt) No data read from stdin\n";
            return false;
        }

        auto plaintext =
            seal::Cryptography::decryptPacket(std::span<const unsigned char>(packet), password);

        std::cout.write(reinterpret_cast<const char*>(plaintext.data()),
                        static_cast<std::streamsize>(plaintext.size()));

        if (!std::cout.good())
        {
            std::cerr << "(decrypt) Failed to write to stdout\n";
            seal::Cryptography::cleanseString(plaintext);
            return false;
        }

        seal::Cryptography::cleanseString(plaintext);
        return true;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(decrypt) " << e.what() << "\n";
        return false;
    }
}

bool FileOperations::shredFile(const std::string& path)
{
    // Open with FILE_FLAG_WRITE_THROUGH to bypass the filesystem write cache
    // and push data directly to the storage controller. This gives a stronger
    // (though still not absolute) guarantee that overwrite passes hit the same
    // physical sectors as the original data. On SSDs with wear-leveling or
    // copy-on-write filesystems (e.g. ReFS), the controller may remap sectors
    // regardless -- full disk encryption is the only complete mitigation there.
    HANDLE hFile = CreateFileA(path.c_str(),
                               GENERIC_READ | GENERIC_WRITE,
                               0,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_FLAG_WRITE_THROUGH,
                               nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "(shred) cannot open: " << path << "\n";
        return false;
    }

    LARGE_INTEGER liSize{};
    if (!GetFileSizeEx(hFile, &liSize) || std::bit_cast<long long>(liSize) <= 0)
    {
        CloseHandle(hFile);
        // Empty or unreadable file - just delete it.
        return DeleteFileA(path.c_str()) != 0;
    }

    auto fileSize = static_cast<size_t>(std::bit_cast<long long>(liSize));
    constexpr size_t CHUNK = 65536;
    std::vector<unsigned char> buf(std::min(fileSize, CHUNK));

    // Three overwrite passes: random, zeros, random.
    for (int pass = 0; pass < 3; ++pass)
    {
        // Rewind to the start for each pass.
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN))
        {
            std::cerr << "(shred) seek failed pass " << (pass + 1) << ": " << path << "\n";
            CloseHandle(hFile);
            return false;
        }

        size_t remaining = fileSize;
        while (remaining > 0)
        {
            size_t chunk = std::min(remaining, buf.size());
            if (pass == 1)
            {
                std::fill_n(buf.data(), chunk, static_cast<unsigned char>(0));
            }
            else
            {
                RAND_bytes(buf.data(), static_cast<int>(chunk));
            }

            DWORD written = 0;
            if (!WriteFile(hFile, buf.data(), static_cast<DWORD>(chunk), &written, nullptr) ||
                written != static_cast<DWORD>(chunk))
            {
                std::cerr << "(shred) write failed pass " << (pass + 1) << ": " << path << "\n";
                CloseHandle(hFile);
                return false;
            }
            remaining -= chunk;
        }
        FlushFileBuffers(hFile);
    }

    CloseHandle(hFile);
    SecureZeroMemory(buf.data(), buf.size());

    if (!DeleteFileA(path.c_str()))
    {
        std::cerr << "(shred) failed to delete: " << path << "\n";
        return false;
    }
    return true;
}

std::string FileOperations::hashFile(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        std::cerr << "(hash) cannot open: " << path << "\n";
        return {};
    }

    seal::EvpMdCtx ctx;
    if (EVP_DigestInit_ex(ctx.p, EVP_sha256(), nullptr) != 1)
        return {};

    constexpr size_t CHUNK = 65536;
    char buf[CHUNK];
    while (in.read(buf, CHUNK) || in.gcount() > 0)
    {
        if (EVP_DigestUpdate(ctx.p, buf, static_cast<size_t>(in.gcount())) != 1)
            return {};
        if (in.eof())
            break;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx.p, hash, &hashLen) != 1)
        return {};

    return seal::utils::to_hex(std::span<const unsigned char>(hash, hashLen));
}

using SecNarrow = seal::secure_string<>;
using SecWide = seal::basic_secure_string<wchar_t>;

// Explicit template instantiations for the two password types (narrow and
// wide secure strings).  These are required because the template definitions
// live in this .cpp file rather than the header, so the compiler cannot
// generate them on demand when other translation units call these functions.
// Without these lines the linker would report unresolved-symbol errors.
template bool FileOperations::encryptFileInPlace(const std::string&, const SecNarrow&);
template bool FileOperations::encryptFileInPlace(const std::string&, const SecWide&);

template bool FileOperations::decryptFileInPlace(const std::string&, const SecNarrow&);
template bool FileOperations::decryptFileInPlace(const std::string&, const SecWide&);

template std::string FileOperations::encryptLine(const std::string&, const SecNarrow&);
template std::string FileOperations::encryptLine(const std::string&, const SecWide&);

template seal::secure_string<seal::locked_allocator<char>> FileOperations::decryptLine(
    const std::string&, const SecNarrow&);
template seal::secure_string<seal::locked_allocator<char>> FileOperations::decryptLine(
    const std::string&, const SecWide&);

template bool FileOperations::parseTriples(
    std::string_view, std::vector<seal::secure_triplet16<seal::locked_allocator<wchar_t>>>&);

template bool FileOperations::processDirectory(const std::string&, const SecWide&, bool);
template bool FileOperations::processFilePath(const std::string&, const SecWide&);

template void FileOperations::processBatch(const std::vector<std::string>&, bool, const SecWide&);

template bool FileOperations::streamEncrypt(const SecWide&);
template bool FileOperations::streamDecrypt(const SecWide&);

}  // namespace seal
