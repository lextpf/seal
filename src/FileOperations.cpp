#include "FileOperations.h"

#include "Clipboard.h"
#include "Console.h"
#include "Utils.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <bit>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <iterator>
#include <mutex>
#include <queue>
#include <thread>

namespace
{

// Flush a file's data to durable storage so a subsequent rename + source-delete
// cannot lose the destination on a crash. Opens the file by path, calls
// FlushFileBuffers, then closes the handle. Returns false on any failure.
bool flushFileToDisk(const std::string& path)
{
    HANDLE h = CreateFileA(path.c_str(),
                           GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    BOOL ok = FlushFileBuffers(h);
    CloseHandle(h);
    return ok != 0;
}

}  // namespace

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
bool FileOperations::encryptFileTo(const std::string& srcPath,
                                   const std::string& dstPath,
                                   const SecurePwd& pwd)
{
    // Use streaming path for files larger than FILE_CHUNK to avoid
    // loading the entire file into memory.
    {
        std::error_code ec;
        auto fileSize = std::filesystem::file_size(srcPath, ec);
        if (!ec && fileSize > seal::cfg::FILE_CHUNK)
        {
            return encryptFileStreaming(srcPath, dstPath, pwd);
        }
    }

    std::ifstream in(srcPath, std::ios::binary);
    if (!in)
    {
        std::cerr << "(encrypt) cannot open: " << srcPath << "\n";
        return false;
    }
    std::vector<unsigned char> plain((std::istreambuf_iterator<char>(in)), {});
    in.close();
    auto packet = seal::Cryptography::encryptPacket(std::span<const unsigned char>(plain), pwd);
    seal::Cryptography::cleanseString(plain);

    // Atomic write: ciphertext -> dstPath.tmp -> rename to dstPath.
    // The source file is never modified.
    std::string tmpPath = dstPath + ".tmp";
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

    // Flush data to durable storage before the rename so a crash between
    // the rename and the caller's DeleteFileA cannot lose the destination.
    flushFileToDisk(tmpPath);

    if (!MoveFileExA(tmpPath.c_str(), dstPath.c_str(), MOVEFILE_REPLACE_EXISTING))
    {
        std::cerr << "(encrypt) cannot rename to destination: " << dstPath << "\n";
        DeleteFileA(tmpPath.c_str());
        return false;
    }
    return true;
}

template <secure_password SecurePwd>
bool FileOperations::decryptFileTo(const std::string& srcPath,
                                   const std::string& dstPath,
                                   const SecurePwd& pwd)
{
    // Use streaming path for files larger than FILE_CHUNK + framing overhead
    // to avoid loading the entire file into memory.
    {
        constexpr size_t kFramingOverhead =
            seal::cfg::AAD_LEN + seal::cfg::SALT_LEN + seal::cfg::IV_LEN + seal::cfg::TAG_LEN;
        std::error_code ec;
        auto fileSize = std::filesystem::file_size(srcPath, ec);
        if (!ec && fileSize > seal::cfg::FILE_CHUNK + kFramingOverhead)
        {
            return decryptFileStreaming(srcPath, dstPath, pwd);
        }
    }

    std::ifstream in(srcPath, std::ios::binary);
    if (!in)
    {
        std::cerr << "(decrypt) cannot open: " << srcPath << "\n";
        return false;
    }
    std::vector<unsigned char> blob((std::istreambuf_iterator<char>(in)), {});
    in.close();
    try
    {
        auto plain = seal::Cryptography::decryptPacket(std::span<const unsigned char>(blob), pwd);

        // Atomic write: plaintext -> dstPath.tmp -> rename to dstPath.
        // The source file is never modified.
        std::string tmpPath = dstPath + ".tmp";
        std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            std::cerr << "(decrypt) cannot write temp file: " << tmpPath << "\n";
            seal::Cryptography::cleanseString(plain);
            return false;
        }
        out.write(reinterpret_cast<const char*>(plain.data()), (std::streamsize)plain.size());
        out.flush();
        seal::Cryptography::cleanseString(plain);
        if (!out)
        {
            std::cerr << "(decrypt) write failed: " << tmpPath << "\n";
            out.close();
            DeleteFileA(tmpPath.c_str());
            return false;
        }
        out.close();

        flushFileToDisk(tmpPath);

        if (!MoveFileExA(tmpPath.c_str(), dstPath.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            std::cerr << "(decrypt) cannot rename to destination: " << dstPath << "\n";
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
// Each token must contain EXACTLY 2 colons (3 fields).
template <class A>
bool FileOperations::parseTriples(std::string_view plain,
                                  std::vector<seal::secure_triplet16<A>>& out)
{
    out.clear();
    std::string tok;

    // Flush: Validate and consume one accumulated token.
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

namespace
{

// Fixed-size worker pool for processDirectory.  Replaces the previous
// semaphore + std::async pattern which created an unbounded number of
// OS threads (one per std::async call) even though only 16 could run
// concurrently.  Deep directory trees could exhaust the thread quota.
// This pool creates exactly N workers and uses a bounded queue so
// Submit() blocks when there is too much outstanding work.
class WorkPool
{
public:
    explicit WorkPool(unsigned nWorkers)
    {
        for (unsigned i = 0; i < nWorkers; ++i)
        {
            m_Workers.emplace_back([this](std::stop_token stop) { WorkerLoop(stop); });
        }
    }

    std::future<bool> Submit(std::function<bool()> fn)
    {
        std::packaged_task<bool()> task(std::move(fn));
        auto fut = task.get_future();
        {
            std::unique_lock lk(m_Mutex);
            m_SpaceAvailable.wait(lk, [this] { return m_Tasks.size() < MAX_QUEUED || m_Stopped; });
            if (m_Stopped)
            {
                return fut;
            }
            m_Tasks.push(std::move(task));
        }
        m_TaskAvailable.notify_one();
        return fut;
    }

    ~WorkPool()
    {
        {
            std::lock_guard lk(m_Mutex);
            m_Stopped = true;
        }
        m_TaskAvailable.notify_all();
        m_SpaceAvailable.notify_all();
        // jthread destructors request stop and join automatically.
    }

    WorkPool(const WorkPool&) = delete;
    WorkPool& operator=(const WorkPool&) = delete;

private:
    void WorkerLoop(std::stop_token stop)
    {
        while (!stop.stop_requested())
        {
            std::packaged_task<bool()> task;
            {
                std::unique_lock lk(m_Mutex);
                m_TaskAvailable.wait(lk, [this] { return m_Stopped || !m_Tasks.empty(); });
                if (m_Stopped && m_Tasks.empty())
                {
                    return;
                }
                task = std::move(m_Tasks.front());
                m_Tasks.pop();
            }
            m_SpaceAvailable.notify_one();
            task();
        }
    }

    std::vector<std::jthread> m_Workers;
    std::queue<std::packaged_task<bool()>> m_Tasks;
    std::mutex m_Mutex;
    std::condition_variable m_TaskAvailable;
    std::condition_variable m_SpaceAvailable;
    static constexpr size_t MAX_QUEUED = 32;
    bool m_Stopped = false;
};

WorkPool& GetPool()
{
    static WorkPool pool(std::min(std::thread::hardware_concurrency(), 8u));
    return pool;
}

}  // namespace

// Walk a directory with FindFirstFileA/FindNextFileA, encrypting or
// decrypting every file based on its .seal extension (see processFilePath).
// Subdirectories are processed recursively via a fixed-size work pool.
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

    // SAFETY: pool lambdas below capture `password` by reference. This is
    // safe because drainFutures() joins ALL futures before this function
    // returns, guaranteeing password outlives every lambda. If you add an
    // early-return path, you MUST drain futures first.
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
            // Recurse into subdirectories via the work pool so sibling
            // directories can be processed in parallel without creating
            // an unbounded number of OS threads.
            if (recurse)
            {
                futures.push_back(GetPool().Submit(
                    [full, &password]() -> bool
                    { return FileOperations::processDirectory(full, password, true); }));
            }
            continue;
        }

        // Submit each file encrypt/decrypt to the work pool.
        futures.push_back(
            GetPool().Submit([full, &password]() -> bool
                             { return FileOperations::processFilePath(full, password); }));
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
// encrypted (extension appended).
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
        bool success = FileOperations::decryptFileTo(t, newName, password);

        if (success)
        {
            DeleteFileA(t.c_str());
            std::cout << "(decrypted) " << t << " -> " << newName << "\n";
        }
        return success;
    }
    else
    {
        // Encrypt: append .seal so the file is recognized as encrypted later.
        std::string newName = seal::utils::add_ext(t, std::string_view{".seal"});
        bool success = FileOperations::encryptFileTo(t, newName, password);

        if (success)
        {
            DeleteFileA(t.c_str());
            std::cout << "(encrypted) " << t << " -> " << newName << "\n";
        }
        return success;
    }
}

// Index mapping for on-demand re-decryption: maps an aggregate entry
// index (as shown in the masked view) back to the hex token and the
// specific triple within that token's decrypted output.
struct TokenMapping
{
    size_t hexTokenIndex;     // index into the allHexTokens vector
    size_t intraTripleIndex;  // which triple within that token's decrypted output
};

// Decrypt a batch of hex-encoded ciphertext tokens. Extracts service names
// (non-secret) for display and builds an index map for on-demand re-decryption.
// Credentials are wiped immediately; only service names are retained.
template <secure_password SecurePwd>
static void scanHexTokens(const std::vector<std::string>& hexTokens,
                          const SecurePwd& password,
                          std::vector<std::string>& allHexTokens,
                          std::vector<std::wstring>& serviceNames,
                          std::vector<TokenMapping>& indexMap,
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
                size_t tokIdx = allHexTokens.size();
                allHexTokens.push_back(tok);
                for (size_t j = 0; j < ts.size(); ++j)
                {
                    // Extract non-secret service name for display.
                    serviceNames.emplace_back(ts[j].primary.data(), ts[j].primary.size());
                    indexMap.push_back({tokIdx, j});
                }
                // Wipe credentials immediately; only service names are kept.
                for (auto& t : ts)
                    seal::Cryptography::cleanseString(t.primary, t.secondary, t.tertiary);
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

// Print decrypted triples to the console in uncensored mode.
// All triples are re-decrypted for stdout output (unavoidable since the
// user explicitly chose uncensored) and wiped after printing.
template <secure_password SecurePwd>
static void displayTriplesUncensored(const std::vector<std::string>& allHexTokens,
                                     const std::vector<TokenMapping>& indexMap,
                                     const SecurePwd& password)
{
    std::ostringstream oss;
    bool first = true;
    for (const auto& m : indexMap)
    {
        try
        {
            auto plain = FileOperations::decryptLine(allHexTokens[m.hexTokenIndex], password);
            std::vector<seal::secure_triplet16_t> ts;
            if (FileOperations::parseTriples(plain.view(), ts) && m.intraTripleIndex < ts.size())
            {
                if (!first)
                    oss << ", ";
                std::string sv = FileOperations::tripleToUtf8(ts[m.intraTripleIndex]);
                oss << sv;
                seal::Cryptography::cleanseString(sv);
                first = false;
            }
            seal::Cryptography::cleanseString(plain);
            for (auto& t : ts)
                seal::Cryptography::cleanseString(t.primary, t.secondary, t.tertiary);
        }
        catch (const std::exception& ex)
        {
            std::cerr << "(decrypt failed: " << ex.what() << ")\n";
        }
    }
    std::string printed = oss.str();
    if (!printed.empty())
        std::cout << printed << "\n";
    seal::Cryptography::cleanseString(printed);
    std::string ossBuf = std::move(oss).str();
    seal::Cryptography::cleanseString(ossBuf);
}

// Process a batch of user-supplied input lines with a three-tier dispatch:
//   1. File paths -- encrypt or decrypt files on disk (highest priority).
//   2. Hex tokens -- treat as ciphertext, decrypt and display/copy.
//   3. Plain text -- anything else is encrypted and printed as hex.
// This priority order means a line that happens to look like valid hex but
// also resolves to a real file path will be treated as a file path.
//
// In censored mode, credentials are decrypted on-demand at click time
// (not accumulated in memory) to minimize the plaintext exposure window.
template <secure_password SecurePwd>
void FileOperations::processBatch(const std::vector<std::string>& lines,
                                  bool uncensored,
                                  const SecurePwd& password)
{
    if (lines.empty())
        return;

    // Service names (non-secret, displayed in cleartext) and an index map
    // for on-demand re-decryption. Credentials are never held simultaneously.
    std::vector<std::string> allHexTokens;
    std::vector<std::wstring> serviceNames;
    std::vector<TokenMapping> indexMap;
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
            scanHexTokens(hexTokens, password, allHexTokens, serviceNames, indexMap, otherPlain);
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

    if (!serviceNames.empty())
    {
        if (uncensored)
        {
            // Uncensored: re-decrypt all for stdout (user explicitly chose this).
            displayTriplesUncensored(allHexTokens, indexMap, password);
        }
        else
        {
            // Censored: on-demand decrypt. Only service names are in memory;
            // credentials are decrypted one at a time when the user clicks.
            auto decryptCb =
                [&allHexTokens, &indexMap, &password](size_t idx) -> seal::secure_triplet16_t
            {
                const auto& m = indexMap[idx];
                auto plain = FileOperations::decryptLine(allHexTokens[m.hexTokenIndex], password);
                std::vector<seal::secure_triplet16_t> ts;
                FileOperations::parseTriples(plain.view(), ts);
                seal::Cryptography::cleanseString(plain);
                if (m.intraTripleIndex < ts.size())
                    return std::move(ts[m.intraTripleIndex]);
                throw std::runtime_error("triple index out of range on re-decrypt");
            };

            interactiveMaskedWin(std::move(serviceNames), std::move(decryptCb));
            std::cout << "(Masked; Click **** to copy)\n";
        }
    }

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
    // guarantee that overwrite passes hit the same physical sectors as
    // the original data.
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

// Streaming encryption: reads the source file in cfg::FILE_CHUNK increments,
// feeds each chunk to EVP_EncryptUpdate, and writes ciphertext incrementally.
// The wire format is identical to encryptPacket (AAD | salt | IV | ct | tag)
// so the output is interoperable with all existing decrypt paths.
template <secure_password SecurePwd>
bool FileOperations::encryptFileStreaming(const std::string& srcPath,
                                          const std::string& dstPath,
                                          const SecurePwd& pwd)
{
    std::ifstream in(srcPath, std::ios::binary);
    if (!in)
    {
        std::cerr << "(encrypt-stream) cannot open: " << srcPath << "\n";
        return false;
    }

    // Generate salt and IV
    std::vector<unsigned char> salt(seal::cfg::SALT_LEN);
    seal::Cryptography::opensslCheck(RAND_bytes(salt.data(), (int)salt.size()),
                                     "RAND_bytes(salt) failed");
    std::vector<unsigned char> iv(seal::cfg::IV_LEN);
    seal::Cryptography::opensslCheck(RAND_bytes(iv.data(), (int)iv.size()),
                                     "RAND_bytes(iv) failed");

    auto key = seal::Cryptography::deriveKey(pwd, std::span<const unsigned char>(salt));

    seal::EvpCipherCtx ctx;
    seal::Cryptography::opensslCheck(
        EVP_EncryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
        "EncryptInit(cipher) failed");
    seal::Cryptography::opensslCheck(
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr),
        "SET_IVLEN failed");
    seal::Cryptography::opensslCheck(
        EVP_EncryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv.data()),
        "EncryptInit(key/iv) failed");

    // Feed AAD
    std::span<const unsigned char> aad = seal::Cryptography::aadSpan();
    if (!aad.empty())
    {
        int tmp = 0;
        seal::Cryptography::opensslCheck(
            EVP_EncryptUpdate(ctx.p, nullptr, &tmp, aad.data(), (int)aad.size()),
            "EncryptUpdate(AAD) failed");
    }

    // Open output via atomic tmp file
    std::string tmpPath = dstPath + ".tmp";
    std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cerr << "(encrypt-stream) cannot write temp file: " << tmpPath << "\n";
        seal::Cryptography::cleanseString(key);
        return false;
    }

    // Write header: AAD | salt | IV
    if (!aad.empty())
    {
        out.write(reinterpret_cast<const char*>(aad.data()), (std::streamsize)aad.size());
    }
    out.write(reinterpret_cast<const char*>(salt.data()), (std::streamsize)salt.size());
    out.write(reinterpret_cast<const char*>(iv.data()), (std::streamsize)iv.size());

    // Encrypt in chunks
    std::vector<unsigned char> plainBuf(seal::cfg::FILE_CHUNK);
    std::vector<unsigned char> ctBuf(seal::cfg::FILE_CHUNK + 16);  // block slop
    bool ioOk = true;

    while (in)
    {
        in.read(reinterpret_cast<char*>(plainBuf.data()), (std::streamsize)plainBuf.size());
        auto bytesRead = static_cast<size_t>(in.gcount());
        if (bytesRead == 0)
            break;

        int outlen = 0;
        seal::Cryptography::opensslCheck(
            EVP_EncryptUpdate(
                ctx.p, ctBuf.data(), &outlen, plainBuf.data(), static_cast<int>(bytesRead)),
            "EncryptUpdate(PT) failed");

        SecureZeroMemory(plainBuf.data(), bytesRead);
        out.write(reinterpret_cast<const char*>(ctBuf.data()), outlen);
        if (!out)
        {
            ioOk = false;
            break;
        }
    }
    in.close();

    if (ioOk)
    {
        // Finalize
        int fin = 0;
        seal::Cryptography::opensslCheck(EVP_EncryptFinal_ex(ctx.p, ctBuf.data(), &fin),
                                         "EncryptFinal failed");
        if (fin > 0)
        {
            out.write(reinterpret_cast<const char*>(ctBuf.data()), fin);
        }

        // Write GCM tag
        std::vector<unsigned char> tag(seal::cfg::TAG_LEN);
        seal::Cryptography::opensslCheck(
            EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data()),
            "GET_TAG failed");
        out.write(reinterpret_cast<const char*>(tag.data()), (std::streamsize)tag.size());
        out.flush();
        ioOk = out.good();
    }

    seal::Cryptography::cleanseString(key);
    SecureZeroMemory(plainBuf.data(), plainBuf.size());
    SecureZeroMemory(ctBuf.data(), ctBuf.size());
    out.close();

    if (ioOk)
    {
        flushFileToDisk(tmpPath);

        if (!MoveFileExA(tmpPath.c_str(), dstPath.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            std::cerr << "(encrypt-stream) cannot rename to destination: " << dstPath << "\n";
            DeleteFileA(tmpPath.c_str());
            return false;
        }
        return true;
    }

    std::cerr << "(encrypt-stream) write error: " << tmpPath << "\n";
    DeleteFileA(tmpPath.c_str());
    return false;
}

// Streaming decryption with two-pass authentication.
//
// Pass 1 (verify): streams the entire ciphertext through GCM decryption into
// a scratch buffer (immediately wiped) and checks the authentication tag via
// EVP_DecryptFinal_ex. No plaintext is written to disk during this pass.
// If the tag fails, the function returns false without ever creating a file.
//
// Pass 2 (write): re-reads the ciphertext and decrypts again, this time
// writing plaintext to a temp file. Since authentication passed in pass 1,
// the data is known-authentic. The temp file is flushed, renamed to the
// destination, and the key is wiped.
//
// The two-pass approach costs one extra file read and one extra decrypt, but
// guarantees that unauthenticated plaintext never reaches disk -- critical for
// a credential manager where tampered ciphertext must not produce recoverable
// plaintext.
template <secure_password SecurePwd>
bool FileOperations::decryptFileStreaming(const std::string& srcPath,
                                          const std::string& dstPath,
                                          const SecurePwd& pwd)
{
    // Snapshot the file's last-write time before reading so we can detect
    // modifications between the verification pass and the write pass (TOCTOU).
    WIN32_FILE_ATTRIBUTE_DATA fileAttrBefore{};
    if (!GetFileAttributesExA(srcPath.c_str(), GetFileExInfoStandard, &fileAttrBefore))
    {
        std::cerr << "(decrypt-stream) cannot stat: " << srcPath << "\n";
        return false;
    }

    std::ifstream in(srcPath, std::ios::binary);
    if (!in)
    {
        std::cerr << "(decrypt-stream) cannot open: " << srcPath << "\n";
        return false;
    }

    // Determine file size
    in.seekg(0, std::ios::end);
    auto fileSize = static_cast<size_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    std::span<const unsigned char> aadExpected = seal::Cryptography::aadSpan();
    size_t headerSize = aadExpected.size() + seal::cfg::SALT_LEN + seal::cfg::IV_LEN;

    if (fileSize < headerSize + seal::cfg::TAG_LEN)
    {
        std::cerr << "(decrypt-stream) file too short: " << srcPath << "\n";
        return false;
    }

    // Read and verify AAD header
    if (!aadExpected.empty())
    {
        std::vector<unsigned char> aadBuf(aadExpected.size());
        in.read(reinterpret_cast<char*>(aadBuf.data()), (std::streamsize)aadBuf.size());
        if (std::memcmp(aadBuf.data(), aadExpected.data(), aadExpected.size()) != 0)
        {
            std::cerr << "(decrypt-stream) bad AAD header: " << srcPath << "\n";
            return false;
        }
    }

    // Read salt and IV
    std::vector<unsigned char> salt(seal::cfg::SALT_LEN);
    in.read(reinterpret_cast<char*>(salt.data()), (std::streamsize)salt.size());
    std::vector<unsigned char> iv(seal::cfg::IV_LEN);
    in.read(reinterpret_cast<char*>(iv.data()), (std::streamsize)iv.size());

    size_t ctLen = fileSize - headerSize - seal::cfg::TAG_LEN;

    // Read the GCM tag from the end of the file, then seek back to ciphertext start
    auto ctStartPos = in.tellg();
    in.seekg(-(std::streamoff)seal::cfg::TAG_LEN, std::ios::end);
    std::vector<unsigned char> tag(seal::cfg::TAG_LEN);
    in.read(reinterpret_cast<char*>(tag.data()), (std::streamsize)tag.size());
    in.seekg(ctStartPos);

    try
    {
        auto key = seal::Cryptography::deriveKey(pwd, std::span<const unsigned char>(salt));

        // Helper: initialise a GCM decrypt context with the shared key/IV/AAD.
        auto initCtx = [&](seal::EvpCipherCtx& ctx)
        {
            seal::Cryptography::opensslCheck(
                EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                "DecryptInit(cipher) failed");
            seal::Cryptography::opensslCheck(
                EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)seal::cfg::IV_LEN, nullptr),
                "SET_IVLEN failed");
            seal::Cryptography::opensslCheck(
                EVP_DecryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv.data()),
                "DecryptInit(key/iv) failed");
            if (!aadExpected.empty())
            {
                int tmp = 0;
                seal::Cryptography::opensslCheck(
                    EVP_DecryptUpdate(
                        ctx.p, nullptr, &tmp, aadExpected.data(), (int)aadExpected.size()),
                    "DecryptUpdate(AAD) failed");
            }
        };

        // Reusable buffers for both passes.
        std::vector<unsigned char> ctBuf(seal::cfg::FILE_CHUNK);
        std::vector<unsigned char> plainBuf(seal::cfg::FILE_CHUNK + 16);

        // --- Pass 1: verify GCM tag without writing plaintext to disk ---
        {
            seal::EvpCipherCtx verifyCtx;
            initCtx(verifyCtx);

            size_t remaining = ctLen;
            while (remaining > 0)
            {
                size_t toRead = std::min(remaining, seal::cfg::FILE_CHUNK);
                in.read(reinterpret_cast<char*>(ctBuf.data()), (std::streamsize)toRead);
                auto bytesRead = static_cast<size_t>(in.gcount());
                if (bytesRead == 0)
                    break;

                int outlen = 0;
                seal::Cryptography::opensslCheck(EVP_DecryptUpdate(verifyCtx.p,
                                                                   plainBuf.data(),
                                                                   &outlen,
                                                                   ctBuf.data(),
                                                                   static_cast<int>(bytesRead)),
                                                 "DecryptUpdate(CT/verify) failed");
                SecureZeroMemory(plainBuf.data(), static_cast<size_t>(outlen));
                remaining -= bytesRead;
            }

            seal::Cryptography::opensslCheck(
                EVP_CIPHER_CTX_ctrl(
                    verifyCtx.p, EVP_CTRL_GCM_SET_TAG, (int)seal::cfg::TAG_LEN, tag.data()),
                "SET_TAG failed");

            unsigned char finBuf[16]{};
            int fin = 0;
            int ok = EVP_DecryptFinal_ex(verifyCtx.p, finBuf, &fin);
            SecureZeroMemory(finBuf, sizeof(finBuf));

            if (ok != 1)
            {
                seal::Cryptography::cleanseString(key);
                SecureZeroMemory(ctBuf.data(), ctBuf.size());
                SecureZeroMemory(plainBuf.data(), plainBuf.size());
                std::cerr << "(decrypt-stream) authentication failed: " << srcPath << "\n";
                return false;
            }
        }

        // --- TOCTOU guard: verify the file wasn't modified during pass 1 ---
        // If another process wrote to the file between our verification and
        // the write pass, the authentication guarantee from pass 1 is void.
        WIN32_FILE_ATTRIBUTE_DATA fileAttrAfter{};
        if (!GetFileAttributesExA(srcPath.c_str(), GetFileExInfoStandard, &fileAttrAfter) ||
            fileAttrBefore.ftLastWriteTime.dwLowDateTime !=
                fileAttrAfter.ftLastWriteTime.dwLowDateTime ||
            fileAttrBefore.ftLastWriteTime.dwHighDateTime !=
                fileAttrAfter.ftLastWriteTime.dwHighDateTime ||
            fileAttrBefore.nFileSizeLow != fileAttrAfter.nFileSizeLow ||
            fileAttrBefore.nFileSizeHigh != fileAttrAfter.nFileSizeHigh)
        {
            seal::Cryptography::cleanseString(key);
            SecureZeroMemory(ctBuf.data(), ctBuf.size());
            SecureZeroMemory(plainBuf.data(), plainBuf.size());
            std::cerr << "(decrypt-stream) file modified during verification: " << srcPath << "\n";
            return false;
        }

        // --- Pass 2: re-read and decrypt to disk (data is now authenticated) ---
        in.clear();
        in.seekg(ctStartPos);

        seal::EvpCipherCtx writeCtx;
        initCtx(writeCtx);

        std::string tmpPath = dstPath + ".tmp";
        std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            std::cerr << "(decrypt-stream) cannot write temp file: " << tmpPath << "\n";
            seal::Cryptography::cleanseString(key);
            return false;
        }

        size_t remaining = ctLen;
        bool ioOk = true;

        while (remaining > 0)
        {
            size_t toRead = std::min(remaining, seal::cfg::FILE_CHUNK);
            in.read(reinterpret_cast<char*>(ctBuf.data()), (std::streamsize)toRead);
            auto bytesRead = static_cast<size_t>(in.gcount());
            if (bytesRead == 0)
                break;

            int outlen = 0;
            seal::Cryptography::opensslCheck(EVP_DecryptUpdate(writeCtx.p,
                                                               plainBuf.data(),
                                                               &outlen,
                                                               ctBuf.data(),
                                                               static_cast<int>(bytesRead)),
                                             "DecryptUpdate(CT/write) failed");

            out.write(reinterpret_cast<const char*>(plainBuf.data()), outlen);
            SecureZeroMemory(plainBuf.data(), static_cast<size_t>(outlen));
            if (!out)
            {
                ioOk = false;
                break;
            }
            remaining -= bytesRead;
        }
        in.close();

        if (!ioOk)
        {
            seal::Cryptography::cleanseString(key);
            SecureZeroMemory(ctBuf.data(), ctBuf.size());
            SecureZeroMemory(plainBuf.data(), plainBuf.size());
            out.close();
            DeleteFileA(tmpPath.c_str());
            return false;
        }

        // Finalize the write-pass context (tag is already verified; this
        // call flushes any remaining block padding).
        seal::Cryptography::opensslCheck(
            EVP_CIPHER_CTX_ctrl(
                writeCtx.p, EVP_CTRL_GCM_SET_TAG, (int)seal::cfg::TAG_LEN, tag.data()),
            "SET_TAG(write) failed");

        unsigned char finBuf[16]{};
        int fin = 0;
        (void)EVP_DecryptFinal_ex(writeCtx.p, finBuf, &fin);
        if (fin > 0)
        {
            out.write(reinterpret_cast<const char*>(finBuf), fin);
        }
        SecureZeroMemory(finBuf, sizeof(finBuf));

        seal::Cryptography::cleanseString(key);
        SecureZeroMemory(ctBuf.data(), ctBuf.size());
        SecureZeroMemory(plainBuf.data(), plainBuf.size());

        out.flush();
        ioOk = out.good();
        out.close();

        if (ioOk)
        {
            flushFileToDisk(tmpPath);

            if (!MoveFileExA(tmpPath.c_str(), dstPath.c_str(), MOVEFILE_REPLACE_EXISTING))
            {
                std::cerr << "(decrypt-stream) cannot rename to destination: " << dstPath << "\n";
                DeleteFileA(tmpPath.c_str());
                return false;
            }
            return true;
        }

        std::cerr << "(decrypt-stream) write error: " << tmpPath << "\n";
        DeleteFileA(tmpPath.c_str());
        return false;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(decrypt-stream) " << e.what() << "\n";
        return false;
    }
}

using SecNarrow = seal::secure_string<>;
using SecWide = seal::basic_secure_string<wchar_t>;

// Explicit template instantiations for the two password types (narrow and
// wide secure strings). Without these lines the linker would report
// unresolved-symbol errors.
template bool FileOperations::encryptFileTo(const std::string&,
                                            const std::string&,
                                            const SecNarrow&);
template bool FileOperations::encryptFileTo(const std::string&, const std::string&, const SecWide&);

template bool FileOperations::decryptFileTo(const std::string&,
                                            const std::string&,
                                            const SecNarrow&);
template bool FileOperations::decryptFileTo(const std::string&, const std::string&, const SecWide&);

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

template bool FileOperations::encryptFileStreaming(const std::string&,
                                                   const std::string&,
                                                   const SecNarrow&);
template bool FileOperations::encryptFileStreaming(const std::string&,
                                                   const std::string&,
                                                   const SecWide&);

template bool FileOperations::decryptFileStreaming(const std::string&,
                                                   const std::string&,
                                                   const SecNarrow&);
template bool FileOperations::decryptFileStreaming(const std::string&,
                                                   const std::string&,
                                                   const SecWide&);

template bool FileOperations::streamEncrypt(const SecWide&);
template bool FileOperations::streamDecrypt(const SecWide&);

}  // namespace seal
