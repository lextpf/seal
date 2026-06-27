#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "Vault.hpp"

namespace
{
namespace fs = std::filesystem;

using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;

SecureWide pw()
{
    SecureWide s;
    for (wchar_t c : std::wstring(L"dir-master"))
    {
        s.push_back(c);
    }
    return s;
}

fs::path makeTree()
{
    fs::path root = fs::temp_directory_path() / "seal_dircrypto_test";
    fs::remove_all(root);
    for (const char* sub : {"", "a", "a/aa", "b"})
    {
        fs::path d = (sub[0] != '\0') ? root / sub : root;
        fs::create_directories(d);
        for (int i = 0; i < 3; ++i)
        {
            std::ofstream(d / ("f" + std::to_string(i) + ".txt")) << "payload " << sub << i;
        }
    }
    return root;
}

int countExt(const fs::path& root, const std::string& ext)
{
    int n = 0;
    for (auto& e : fs::recursive_directory_iterator(root))
    {
        if (e.is_regular_file() && e.path().extension() == ext)
        {
            ++n;
        }
    }
    return n;
}
}  // namespace

TEST(DirectoryCryptoTest, NestedTreeRoundTrips)
{
    const fs::path root = makeTree();
    const int total = countExt(root, ".txt");
    ASSERT_EQ(total, 12);

    EXPECT_EQ(seal::encryptDirectory(root, pw()), total);
    EXPECT_EQ(countExt(root, ".txt"), 0);
    EXPECT_EQ(countExt(root, ".seal"), total);

    EXPECT_EQ(seal::decryptDirectory(root, pw()), total);
    EXPECT_EQ(countExt(root, ".txt"), total);
    EXPECT_EQ(countExt(root, ".seal"), 0);

    fs::remove_all(root);
}
