#include "../src/Diagnostics.hpp"

#include <gtest/gtest.h>

#include <string>

namespace
{

using seal::diag::errorFields;
using seal::diag::joinFields;
using seal::diag::kv;
using seal::diag::reasonFromMessage;
using seal::diag::sanitizeAscii;

// preserve the exact reason/detail wire format.
TEST(DiagnosticsErrorFields, MatchesManualReasonDetailPair)
{
    const char* what = "Wrong password";
    EXPECT_EQ(errorFields(what),
              kv("reason", reasonFromMessage(what)) + " " + kv("detail", sanitizeAscii(what)));
}

TEST(DiagnosticsErrorFields, MapsKnownReasonAndTokenisesDetail)
{
    EXPECT_EQ(errorFields("Wrong password"), "reason=wrong_password detail=Wrong_password");
    EXPECT_EQ(errorFields("no data here"), "reason=empty_input detail=no_data_here");
}

TEST(DiagnosticsErrorFields, UnknownMessageFallsBackToException)
{
    const std::string out = errorFields("something unexpected happened");
    EXPECT_EQ(out.rfind("reason=exception ", 0), 0u) << out;
}

TEST(DiagnosticsErrorFields, EmptyMessageYieldsNoneDetail)
{
    EXPECT_EQ(errorFields(""), "reason=exception detail=none");
}

// the returned string must remain two whitespace-separated fields.
TEST(DiagnosticsErrorFields, ExpandsToTwoFieldsInJoinFields)
{
    const std::string line = joinFields({"event=x.finish", "result=fail", errorFields("timeout")});
    EXPECT_EQ(line, "event=x.finish result=fail reason=timeout detail=timeout");
}

// string literals must select the text overload, not convert to bool.
TEST(DiagnosticsKv, CStringValueIsNotBoolified)
{
    const char* cmd = "encrypt";
    EXPECT_EQ(kv("command", cmd), "command=encrypt");
    EXPECT_EQ(kv("k", "hello"), "k=hello");
    EXPECT_EQ(kv("v", static_cast<const char*>(nullptr)), "v=none");
}

}  // namespace
