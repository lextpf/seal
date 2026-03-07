/**
 * @file FileOperations.cpp
 * @brief File operation implementations for seal.
 * @author Alex (https://github.com/lextpf)
 */

#include "FileOperations.h"

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

template <class SecurePwd>
bool FileOperations::encryptFileInPlace(const char* path, const SecurePwd& pwd)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        std::cerr << "(encrypt) cannot open: " << path << "\n";
        return false;
    }
    std::vector<unsigned char> plain((std::istreambuf_iterator<char>(in)), {});
    auto packet = seal::Cryptography::encryptPacket(std::span<const unsigned char>(plain), pwd);
    seal::Cryptography::cleanseString(plain);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::cerr << "(encrypt) cannot overwrite: " << path << "\n";
        return false;
    }
    out.write(reinterpret_cast<const char*>(packet.data()), (std::streamsize)packet.size());
    return (bool)out;
}

template <class SecurePwd>
bool FileOperations::decryptFileInPlace(const char* path, const SecurePwd& pwd)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        std::cerr << "(decrypt) cannot open: " << path << "\n";
        return false;
    }
    std::vector<unsigned char> blob((std::istreambuf_iterator<char>(in)), {});
    try
    {
        auto plain = seal::Cryptography::decryptPacket(std::span<const unsigned char>(blob), pwd);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            std::cerr << "(decrypt) cannot overwrite: " << path << "\n";
            return false;
        }
        out.write(reinterpret_cast<const char*>(plain.data()), (std::streamsize)plain.size());
        seal::Cryptography::cleanseString(plain);
        return (bool)out;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(decrypt) " << e.what() << "\n";
        return false;
    }
}

template <class SecurePwd>
std::string FileOperations::encryptLine(const std::string& s, const SecurePwd& pwd)
{
    auto packet = seal::Cryptography::encryptPacket(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(s.data()), s.size()),
        pwd);
    return seal::utils::to_hex(packet);
}

template <class SecurePwd>
seal::secure_string<seal::locked_allocator<char>> FileOperations::decryptLine(
    const std::string& rawHex, const SecurePwd& pwd)
{
    std::string compact = seal::utils::stripSpaces(rawHex);
    std::vector<unsigned char> blob;
    if (!seal::utils::from_hex(std::string_view{compact}, blob))
        throw std::runtime_error("Invalid hex input");
    auto bytes = seal::Cryptography::decryptPacket(std::span<const unsigned char>(blob), pwd);
    seal::secure_string<seal::locked_allocator<char>> out;
    out.s.assign(reinterpret_cast<const char*>(bytes.data()),
                 reinterpret_cast<const char*>(bytes.data()) + bytes.size());
    seal::Cryptography::cleanseString(bytes);
    return out;
}

template <class A>
bool FileOperations::parseTriples(std::string_view plain,
                                  std::vector<seal::secure_triplet16<A>>& out)
{
    out.clear();
    std::string tok;

    auto flush = [&](std::string& t) -> bool
    {
        std::string s = seal::utils::trim(t);
        t.clear();
        if (s.empty())
            return true;

        size_t c1 = s.find(':'),
               c2 = (c1 == std::string::npos ? std::string::npos : s.find(':', c1 + 1));
        if (c1 == std::string::npos || c2 == std::string::npos ||
            s.find(':', c2 + 1) != std::string::npos)
            return false;

        auto mk = [&](size_t off, size_t len)
        {
            seal::basic_secure_string<wchar_t, A> r;
            r.s.assign(s.begin() + off, s.begin() + off + len);
            return r;
        };

        out.emplace_back(mk(0, c1), mk(c1 + 1, c2 - (c1 + 1)), mk(c2 + 1, s.size() - (c2 + 1)));
        return true;
    };

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
    if (!flush(tok))
    {
        out.clear();
        return false;
    }
    return !out.empty();
}

template <class SecurePwd>
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

    uint64_t total = 0, ok = 0, fail = 0;
    std::vector<std::future<bool>> futures;

    do
    {
        const char* name = fd.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;
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

        futures.push_back(std::async(std::launch::async,
                                     FileOperations::processFilePath<SecurePwd>,
                                     full,
                                     std::ref(password)));
        ++total;

    } while (FindNextFileA(h, &fd));

    FindClose(h);

    for (auto& future : futures)
    {
        bool result = future.get();
        if (result)
            ++ok;
        else
            ++fail;
    }

    std::cout << "[dir] " << dir << ": " << ok << " ok, " << fail << " failed, " << total
              << " total\n";
    return fail == 0;
}

template <class SecurePwd>
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

    if (_stricmp(t.c_str(), ".") == 0)
    {
        t = std::filesystem::current_path().string();
    }

    if (seal::utils::isDirectoryA(t))
    {
        (void)processDirectory(t, password, true);
        return true;
    }

    if (!seal::utils::fileExistsA(t))
        return false;

    const bool isPmg = seal::utils::endsWithCi(t, ".seal");

    if (isPmg)
    {
        // Decrypt
        std::string newName = seal::utils::strip_ext_ci(t, std::string_view{".seal"});
        auto fileProcessingFuture = std::async(std::launch::async,
                                               FileOperations::decryptFileInPlace<SecurePwd>,
                                               t.c_str(),
                                               std::cref(password));
        bool success = fileProcessingFuture.get();

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
        // Encrypt
        std::string newName = seal::utils::add_ext(t, std::string_view{".seal"});
        auto fileProcessingFuture = std::async(std::launch::async,
                                               FileOperations::encryptFileInPlace<SecurePwd>,
                                               t.c_str(),
                                               std::cref(password));
        bool success = fileProcessingFuture.get();

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

template <class SecurePwd>
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
                aggTriples.insert(aggTriples.end(),
                                  std::make_move_iterator(ts.begin()),
                                  std::make_move_iterator(ts.end()));
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

static void displayTriples(std::vector<seal::secure_triplet16_t>& aggTriples, bool uncensored)
{
    if (uncensored)
    {
        std::ostringstream oss;
        for (size_t i = 0; i < aggTriples.size(); ++i)
        {
            if (i)
                oss << ", ";
            std::string sv = FileOperations::tripleToUtf8(aggTriples[i]);
            oss << sv;
            seal::Cryptography::cleanseString(sv);
        }
        std::cout << oss.str() << "\n";
    }
    else
    {
        interactiveMaskedWin(aggTriples);
        std::cout << "(Masked; Click **** to copy)\n";
    }
    for (auto& t : aggTriples)
    {
        seal::Cryptography::cleanseString(t.primary, t.secondary, t.tertiary);
    }
}

template <class SecurePwd>
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
        if (processFilePath(L, password))
            continue;

        auto hexTokens = seal::utils::extractHexTokens(L);
        if (!hexTokens.empty())
        {
            decryptHexTokens(hexTokens, password, aggTriples, otherPlain);
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

template <class SecurePwd>
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

template <class SecurePwd>
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

using SecNarrow = seal::secure_string<>;
using SecWide = seal::basic_secure_string<wchar_t>;

template bool FileOperations::encryptFileInPlace(const char*, const SecNarrow&);
template bool FileOperations::encryptFileInPlace(const char*, const SecWide&);

template bool FileOperations::decryptFileInPlace(const char*, const SecNarrow&);
template bool FileOperations::decryptFileInPlace(const char*, const SecWide&);

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
