#include <gtest/gtest.h>

#include "src/CredentialCsv.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{
std::string readFixture(const char* name)
{
    const auto p = std::filesystem::path(SEAL_SOURCE_DIR) / "tests" / "fixtures" / name;
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
}  // namespace

TEST(CredentialCsvTest, SniffsChromeHeader)
{
    EXPECT_TRUE(seal::csv::LooksLikeChromeCsv("name,url,username,password"));
    EXPECT_TRUE(seal::csv::LooksLikeChromeCsv("name,url,username,password,note\r"));
    EXPECT_TRUE(seal::csv::LooksLikeChromeCsv("\xEF\xBB\xBFname,url,username,password"));
    EXPECT_FALSE(seal::csv::LooksLikeChromeCsv("plat:user:pass"));
    EXPECT_FALSE(seal::csv::LooksLikeChromeCsv("username,password"));
}

TEST(CredentialCsvTest, ParsesBasicChromeExport)
{
    std::vector<seal::csv::Credential> out;
    seal::csv::Stats stats;
    ASSERT_TRUE(seal::csv::ParseChromeCsv(readFixture("chrome_basic.csv"), out, stats));

    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0].platform, "GitHub");
    EXPECT_EQ(out[0].username, "alice");
    EXPECT_EQ(out[0].password, "gh-pass-1");
    // Blank name falls back to the URL host.
    EXPECT_EQ(out[1].platform, "accounts.google.com");
    EXPECT_EQ(out[1].username, "bob");
    EXPECT_EQ(stats.imported, 2u);
    EXPECT_EQ(stats.skippedNoPassword, 1u);
    EXPECT_EQ(stats.badRows, 0u);
}

TEST(CredentialCsvTest, ParsesQuotedFieldsCommasAndEmbeddedNewlines)
{
    std::vector<seal::csv::Credential> out;
    seal::csv::Stats stats;
    ASSERT_TRUE(seal::csv::ParseChromeCsv(readFixture("chrome_quoted.csv"), out, stats));

    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0].platform, "Quoted, Inc");
    EXPECT_EQ(out[0].password, "p,w\"x\"\nline2");
    EXPECT_EQ(out[1].platform, "Plain");
    EXPECT_EQ(stats.imported, 2u);
}

TEST(CredentialCsvTest, RejectsNonCsvContent)
{
    std::vector<seal::csv::Credential> out;
    seal::csv::Stats stats;
    EXPECT_FALSE(seal::csv::ParseChromeCsv("github:alice:pw", out, stats));
}

TEST(CredentialCsvTest, WriteCsvRowQuotesExactlyWhenNeeded)
{
    EXPECT_EQ(seal::csv::WriteCsvRow({"a", "b", "c"}), "a,b,c\r\n");
    EXPECT_EQ(seal::csv::WriteCsvRow({"a,b", "q\"q", "nl\nx"}), "\"a,b\",\"q\"\"q\",\"nl\nx\"\r\n");
}
