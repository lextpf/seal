#include "FileOperations.hpp"

#include "Clipboard.hpp"
#include "Console.hpp"
#include "Utils.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
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

// attempt a durable data flush before renaming and deleting the source.
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

std::string FileOperations::tripleToUtf8(const seal::secure_triplet16_t& t)
{
    auto to_utf8 = [](auto& w)
    {
        if (w.size() == 0)
            return std::string{};
        int need =
            WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string out(need, '\0');
        WideCharToMultiByte(
            CP_UTF8, 0, w.data(), (int)w.size(), out.data(), need, nullptr, nullptr);
        return out;
    };
    std::string s = to_utf8(t.primary), u = to_utf8(t.secondary), p = to_utf8(t.tertiary);
    std::string out;
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
    {
        constexpr size_t kFramingOverhead =
            seal::cfg::HDR_LEN + seal::cfg::SALT_LEN + seal::cfg::IV_LEN + seal::cfg::TAG_LEN;
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

template <secure_password SecurePwd>
std::string FileOperations::encryptLine(const std::string& s, const SecurePwd& pwd)
{
    auto packet = seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()), s.size()),
        pwd);
    return seal::utils::to_hex(packet);
}

template <secure_password SecurePwd>
seal::secure_string<seal::locked_allocator<char>> FileOperations::decryptLine(
    const std::string& rawHex, const SecurePwd& pwd)
{
    std::string compact = seal::utils::stripSpaces(rawHex);
    std::vector<unsigned char> blob;
    if (!seal::utils::from_hex(std::string_view{compact}, blob))
        throw std::runtime_error("Invalid hex input");
    auto bytes = seal::Cryptography::decryptPacket(std::span<const unsigned char>(blob), pwd);
    seal::secure_string<seal::locked_allocator<char>> out;
    out.assign(reinterpret_cast<const char*>(bytes.data()),
               reinterpret_cast<const char*>(bytes.data()) + bytes.size());
    seal::Cryptography::cleanseString(bytes);
    return out;
}

// format: "svc1:user1:pass1,svc2:user2:pass2\n...".
template <class A>
bool FileOperations::parseTriples(std::string_view plain,
                                  std::vector<seal::secure_triplet16<A>>& out)
{
    out.clear();

    auto trimView = [](std::string_view sv) -> std::string_view
    {
        size_t a = 0, b = sv.size();
        while (a < b && std::isspace(static_cast<unsigned char>(sv[a])))
            ++a;
        while (b > a && std::isspace(static_cast<unsigned char>(sv[b - 1])))
            --b;
        return sv.substr(a, b - a);
    };

    auto flush = [&](std::string_view tok) -> bool
    {
        const std::string_view s = trimView(tok);
        if (s.empty())
            return true;

        const size_t c1 = s.find(':');
        const size_t c2 =
            (c1 == std::string_view::npos ? std::string_view::npos : s.find(':', c1 + 1));
        if (c1 == std::string_view::npos || c2 == std::string_view::npos ||
            s.find(':', c2 + 1) != std::string_view::npos)
            return false;

        auto mk = [&](std::string_view field)
        {
            seal::basic_secure_string<wchar_t, A> r;
            if (field.empty())
                return r;
            int need = MultiByteToWideChar(CP_UTF8, 0, field.data(), (int)field.size(), nullptr, 0);
            if (need > 0)
            {
                r.resize(need);
                MultiByteToWideChar(CP_UTF8, 0, field.data(), (int)field.size(), r.data(), need);
            }
            return r;
        };

        const std::string_view service = trimView(s.substr(0, c1));
        const std::string_view user = trimView(s.substr(c1 + 1, c2 - c1 - 1));
        const std::string_view pass = s.substr(c2 + 1);
        if (service.empty() || user.empty() || pass.empty())
            return false;

        out.emplace_back(mk(service), mk(user), mk(pass));
        return true;
    };

    // offset views avoid another narrow secret copy.
    size_t start = 0;
    for (size_t i = 0; i < plain.size(); ++i)
    {
        const char ch = plain[i];
        if (ch == ',' || ch == '\n' || ch == '\r')
        {
            if (!flush(plain.substr(start, i - start)))
            {
                out.clear();
                return false;
            }
            start = i + 1;
        }
    }

    if (!flush(plain.substr(start)))
    {
        out.clear();
        return false;
    }
    return !out.empty();
}

namespace
{

// bound workers and queued tasks; a full queue blocks submission.
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
    // hardware_concurrency can return zero; keep one worker to drain submissions.
    static WorkPool pool(std::max(1u, std::min(std::thread::hardware_concurrency(), 8u)));
    return pool;
}

}  // namespace

template <secure_password SecurePwd>
bool FileOperations::processDirectory(const std::string& dir,
                                      const SecurePwd& password,
                                      bool recurse)
{
    WIN32_FIND_DATAA fd{};
    std::string pattern = seal::utils::joinPath(dir, "*");
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        std::cerr << "(dir) cannot list: " << dir << "\n";
        return false;
    }

    // bound held futures independently of the 32-slot task queue.
    static constexpr size_t MAX_CONCURRENT = 8;

    uint64_t total = 0, ok = 0, fail = 0;
    std::vector<std::future<bool>> futures;

    // tasks borrow password; join on every exit. task exceptions are caught before get().
    auto drainAll = [&]()
    {
        for (auto& f : futures)
        {
            if (f.get())
            {
                ++ok;
            }
            else
            {
                ++fail;
            }
        }
        futures.clear();
    };

    // drain tasks and close enumeration even if allocation throws.
    struct ScopeExit
    {
        std::function<void()> fn;
        ~ScopeExit() { fn(); }
    } scopeExit{[&]
                {
                    drainAll();
                    FindClose(h);
                }};

    do
    {
        const char* name = fd.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        {
            continue;
        }
        // reparse points can escape the tree or loop upward.
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        {
            continue;
        }

        std::string full = seal::utils::joinPath(dir, name);

        if (seal::utils::endsWithCi(name, ".exe") || _stricmp(name, "seal") == 0)
        {
            std::cout << "(skipped) " << full << "\n";
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            // recurse on the caller so no worker waits for another pool task.
            if (recurse)
            {
                if (processDirectory(full, password, true))
                {
                    ++ok;
                }
                else
                {
                    ++fail;
                }
            }
            continue;
        }

        futures.push_back(GetPool().Submit(
            [full, &password]() -> bool
            {
                // report false so drainAll/get cannot rethrow.
                try
                {
                    return FileOperations::processFilePath(full, password);
                }
                catch (...)
                {
                    return false;
                }
            }));
        ++total;

        if (futures.size() >= MAX_CONCURRENT)
        {
            drainAll();
        }

    } while (FindNextFileA(h, &fd));

    drainAll();

    std::cout << "[dir] " << dir << ": " << ok << " ok, " << fail << " failed, " << total
              << " total\n";
    return fail == 0;
}

template <secure_password SecurePwd>
bool FileOperations::processFilePath(const std::string& raw, const SecurePwd& password)
{
    std::string t = seal::utils::stripQuotes(seal::utils::trim(raw));

    std::erase_if(t, [](unsigned char c) { return c < 32 || c == 127; });

    if (t.empty())
        return false;

    // GetFileAttributesA rejects trailing separators except on drive roots.
    while (t.size() > 1 && (t.back() == '\\' || t.back() == '/') && !(t.size() == 3 && t[1] == ':'))
    {
        t.pop_back();
    }

    std::string base = seal::utils::basenameA(t);
    if (seal::utils::endsWithCi(base, ".exe") || _stricmp(base.c_str(), "seal") == 0)
    {
        std::cout << "(skipped) " << t << "\n";
        return true;
    }

    if (_stricmp(t.c_str(), ".") == 0)
    {
        t = std::filesystem::current_path().string();
    }

    if (seal::utils::isDirectoryA(t))
    {
        (void)processDirectory(t, password, true);
        return true;  // recognized as a directory; never fall through to text encryption
    }

    // filesystem handles path forms the ANSI attribute query can reject.
    {
        std::error_code ec;
        if (std::filesystem::is_directory(t, ec))
        {
            (void)processDirectory(t, password, true);
            return true;
        }
    }

    if (!seal::utils::fileExistsA(t))
        return false;

    const bool isPmg = seal::utils::endsWithCi(t, ".seal");

    if (isPmg)
    {
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

// map each visible service to its token and intra-token index for deferred decryption.
struct TokenMapping
{
    size_t hexTokenIndex;     // index into the allHexTokens vector
    size_t intraTripleIndex;  // which triple within that token's decrypted output
};

// retain only service names and source indices after wiping credentials.
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
                    serviceNames.emplace_back(ts[j].primary.data(), ts[j].primary.size());
                    indexMap.push_back({tokIdx, j});
                }
                for (auto& t : ts)
                    seal::Cryptography::cleanseString(t.primary, t.secondary, t.tertiary);
            }
            else
            {
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

template <secure_password SecurePwd>
void FileOperations::processBatch(const std::vector<std::string>& lines,
                                  bool uncensored,
                                  const SecurePwd& password)
{
    if (lines.empty())
        return;

    std::vector<std::string> allHexTokens;
    std::vector<std::wstring> serviceNames;
    std::vector<TokenMapping> indexMap;
    std::vector<std::string> otherPlain;
    std::vector<std::string> encHex;

    for (const auto& L : lines)
    {
        if (processFilePath(L, password))
            continue;

        auto hexTokens = seal::utils::extractHexTokens(L);
        if (!hexTokens.empty())
        {
            scanHexTokens(hexTokens, password, allHexTokens, serviceNames, indexMap, otherPlain);
            continue;
        }

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
            displayTriplesUncensored(allHexTokens, indexMap, password);
        }
        else
        {
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

template <secure_password SecurePwd>
bool FileOperations::streamEncrypt(const SecurePwd& password)
{
    try
    {
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

template <secure_password SecurePwd>
bool FileOperations::streamDecrypt(const SecurePwd& password)
{
    try
    {
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
    // write-through cannot control SSD wear leveling, snapshots or copy-on-write placement.
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
        return DeleteFileA(path.c_str()) != 0;
    }

    auto fileSize = static_cast<size_t>(std::bit_cast<long long>(liSize));
    constexpr size_t CHUNK = 65536;
    std::vector<unsigned char> buf(std::min(fileSize, CHUNK));

    for (int pass = 0; pass < 3; ++pass)
    {
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
                if (RAND_bytes(buf.data(), static_cast<int>(chunk)) != 1)
                {
                    std::cerr << "(shred) RAND_bytes failed pass " << (pass + 1) << ": " << path
                              << "\n";
                    CloseHandle(hFile);
                    return false;
                }
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

    std::vector<unsigned char> salt(seal::cfg::SALT_LEN);
    seal::Cryptography::opensslCheck(RAND_bytes(salt.data(), (int)salt.size()),
                                     "RAND_bytes(salt) failed");
    std::vector<unsigned char> iv(seal::cfg::IV_LEN);
    seal::Cryptography::opensslCheck(RAND_bytes(iv.data(), (int)iv.size()),
                                     "RAND_bytes(iv) failed");

    const seal::Cryptography::PacketHeader header = seal::Cryptography::makeHeader();
    auto key = seal::Cryptography::deriveKey(pwd, std::span<const unsigned char>(salt), header.kdf);

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

    std::span<const unsigned char> aad(header.bytes.data(), header.size);
    if (!aad.empty())
    {
        int tmp = 0;
        seal::Cryptography::opensslCheck(
            EVP_EncryptUpdate(ctx.p, nullptr, &tmp, aad.data(), (int)aad.size()),
            "EncryptUpdate(AAD) failed");
    }

    std::string tmpPath = dstPath + ".tmp";
    std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cerr << "(encrypt-stream) cannot write temp file: " << tmpPath << "\n";
        seal::Cryptography::cleanseString(key);
        return false;
    }

    if (!aad.empty())
    {
        out.write(reinterpret_cast<const char*>(aad.data()), (std::streamsize)aad.size());
    }
    out.write(reinterpret_cast<const char*>(salt.data()), (std::streamsize)salt.size());
    out.write(reinterpret_cast<const char*>(iv.data()), (std::streamsize)iv.size());

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
        int fin = 0;
        seal::Cryptography::opensslCheck(EVP_EncryptFinal_ex(ctx.p, ctBuf.data(), &fin),
                                         "EncryptFinal failed");
        if (fin > 0)
        {
            out.write(reinterpret_cast<const char*>(ctBuf.data()), fin);
        }

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

// authenticate once without disk output, then re-read to commit plaintext; see the header flow.
template <secure_password SecurePwd>
bool FileOperations::decryptFileStreaming(const std::string& srcPath,
                                          const std::string& dstPath,
                                          const SecurePwd& pwd)
{
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

    in.seekg(0, std::ios::end);
    auto fileSize = static_cast<size_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    std::array<unsigned char, 8> headBuf{};
    const size_t headRead = std::min<size_t>(headBuf.size(), fileSize);
    in.read(reinterpret_cast<char*>(headBuf.data()), (std::streamsize)headRead);

    seal::Cryptography::PacketHeader header;
    try
    {
        header = seal::Cryptography::parsePacketHeader(
            std::span<const unsigned char>(headBuf.data(), headRead));
    }
    catch (const std::exception& e)
    {
        std::cerr << "(decrypt-stream) bad packet header: " << e.what() << ": " << srcPath << "\n";
        return false;
    }
    std::span<const unsigned char> aadExpected(header.bytes.data(), header.size);
    const size_t headerSize = header.size + seal::cfg::SALT_LEN + seal::cfg::IV_LEN;

    if (fileSize < headerSize + seal::cfg::TAG_LEN)
    {
        std::cerr << "(decrypt-stream) file too short: " << srcPath << "\n";
        return false;
    }
    in.seekg((std::streamoff)header.size, std::ios::beg);

    std::vector<unsigned char> salt(seal::cfg::SALT_LEN);
    in.read(reinterpret_cast<char*>(salt.data()), (std::streamsize)salt.size());
    std::vector<unsigned char> iv(seal::cfg::IV_LEN);
    in.read(reinterpret_cast<char*>(iv.data()), (std::streamsize)iv.size());

    size_t ctLen = fileSize - headerSize - seal::cfg::TAG_LEN;

    auto ctStartPos = in.tellg();
    in.seekg(-(std::streamoff)seal::cfg::TAG_LEN, std::ios::end);
    std::vector<unsigned char> tag(seal::cfg::TAG_LEN);
    in.read(reinterpret_cast<char*>(tag.data()), (std::streamsize)tag.size());
    in.seekg(ctStartPos);

    try
    {
        auto key =
            seal::Cryptography::deriveKey(pwd, std::span<const unsigned char>(salt), header.kdf);

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

        std::vector<unsigned char> ctBuf(seal::cfg::FILE_CHUNK);
        std::vector<unsigned char> plainBuf(seal::cfg::FILE_CHUNK + 16);

        // verify without writing plaintext to disk.
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

        // reject size/time changes because the first pass authenticated earlier bytes.
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

        // re-read authenticated input to write plaintext.
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

        // GCM adds no padding; pass one verified the tag, so this final result is ignored.
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
