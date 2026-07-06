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

// errorFields must be byte-identical to the manual reason/detail pair it
// replaced at every call site, so the refactor cannot change any log line.
TEST(DiagnosticsErrorFields, MatchesManualReasonDetailPair)
{
    const char* what = "Wrong password";
    EXPECT_EQ(errorFields(what),
              kv("reason", reasonFromMessage(what)) + " " + kv("detail", sanitizeAscii(what)));
}

// Known messages map to their stable reason token; the detail keeps case but
// collapses its embedded space to '_' so the value stays a single token.
TEST(DiagnosticsErrorFields, MapsKnownReasonAndTokenisesDetail)
{
    EXPECT_EQ(errorFields("Wrong password"), "reason=wrong_password detail=Wrong_password");
    EXPECT_EQ(errorFields("no data here"), "reason=empty_input detail=no_data_here");
}

// Unrecognised text falls through to reason=exception.
TEST(DiagnosticsErrorFields, UnknownMessageFallsBackToException)
{
    const std::string out = errorFields("something unexpected happened");
    EXPECT_EQ(out.rfind("reason=exception ", 0), 0u) << out;
}

// An empty message still yields two well-formed fields (detail collapses to none).
TEST(DiagnosticsErrorFields, EmptyMessageYieldsNoneDetail)
{
    EXPECT_EQ(errorFields(""), "reason=exception detail=none");
}

// The single returned string must expand to exactly two logfmt fields when
// dropped into a joinFields list -- the diag module's round-trip invariant.
TEST(DiagnosticsErrorFields, ExpandsToTwoFieldsInJoinFields)
{
    const std::string line = joinFields({"event=x.finish", "result=fail", errorFields("timeout")});
    EXPECT_EQ(line, "event=x.finish result=fail reason=timeout detail=timeout");
}

// Regression: a const char*/string-literal value must format its TEXT, not bind
// to the bool overload (pointer-to-bool) and log "=true". Guards the CLI
// arg-parser's kv("command", cmdName)/kv("syntax", usage) call sites.
TEST(DiagnosticsKv, CStringValueIsNotBoolified)
{
    const char* cmd = "encrypt";
    EXPECT_EQ(kv("command", cmd), "command=encrypt");
    EXPECT_EQ(kv("k", "hello"), "k=hello");
    EXPECT_EQ(kv("v", static_cast<const char*>(nullptr)), "v=none");
}

}  // namespace
