#include "Cryptography.hpp"
#include "FileOperations.hpp"
#include "LockedAllocator.hpp"
#include "SecureString.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace
{
using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;

SecureWide makePw(const wchar_t* s)
{
    SecureWide pw;
    for (const wchar_t* p = s; *p; ++p)
    {
        pw.push_back(*p);
    }
    return pw;
}

std::filesystem::path makeNestedTree()
{
    namespace fs = std::filesystem;
    // A deep+wide tree: depth 3, several files per level. Pre-fix, encrypting
    // this could deadlock the bounded same-pool recursion.
    fs::path root = fs::temp_directory_path() / "seal_fileops_test_tree";
    fs::remove_all(root);
    for (const char* sub : {"", "a", "b", "a/aa", "a/ab", "b/ba", "a/aa/aaa"})
    {
        fs::path dir = sub[0] ? root / sub : root;
        fs::create_directories(dir);
        for (int i = 0; i < 3; ++i)
        {
            std::ofstream f(dir / ("file" + std::to_string(i) + ".txt"));
            f << "payload " << sub << " " << i;
        }
    }
    return root;
}

size_t countByExt(const std::filesystem::path& root, const std::string& ext)
{
    namespace fs = std::filesystem;
    size_t n = 0;
    for (const auto& e : fs::recursive_directory_iterator(root))
    {
        if (e.is_regular_file() && e.path().extension() == ext)
        {
            ++n;
        }
    }
    return n;
}
}  // namespace

TEST(FileOperationsDirectoryTest, NestedTreeEncryptDecryptRoundTripCompletes)
{
    namespace fs = std::filesystem;
    fs::path root = makeNestedTree();
    const size_t plainCount = countByExt(root, ".txt");
    ASSERT_EQ(plainCount, 21u);  // 7 dirs * 3 files

    SecureWide pw = makePw(L"correct horse battery staple");

    // Encrypt the whole tree. Must COMPLETE (no hang) and produce one .seal per file.
    EXPECT_TRUE(seal::FileOperations::processDirectory(root.string(), pw, true));
    EXPECT_EQ(countByExt(root, ".seal"), plainCount);
    EXPECT_EQ(countByExt(root, ".txt"), 0u);

    // Decrypt the whole tree back. Round-trip restores the plaintext files.
    EXPECT_TRUE(seal::FileOperations::processDirectory(root.string(), pw, true));
    EXPECT_EQ(countByExt(root, ".txt"), plainCount);
    EXPECT_EQ(countByExt(root, ".seal"), 0u);

    fs::remove_all(root);
}
