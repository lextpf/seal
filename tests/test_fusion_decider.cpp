#include "../src/FusionDecider.hpp"
#include "../src/Probe.hpp"

#include <gtest/gtest.h>

#include <vector>

using seal::FusionDecider;
using seal::FusionOutcome;
using seal::ProbeResult;
using seal::Verdict;

namespace
{
ProbeResult mk(Verdict v, float c, const char* name)
{
    ProbeResult r;
    r.m_Verdict = v;
    r.m_Confidence = c;
    r.m_ProbeName = name;
    return r;
}
}  // namespace

class FusionDeciderTest : public ::testing::Test
{
};

TEST_F(FusionDeciderTest, EmptyInputReturnsUnknown)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results;
    EXPECT_EQ(decider.decide(results), Verdict::Unknown);
}

TEST_F(FusionDeciderTest, AllUnknownReturnsUnknown)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Unknown, 0.0F, "uia_is_password"),
        mk(Verdict::Unknown, 0.0F, "win32_es_password"),
    };
    EXPECT_EQ(decider.decide(results), Verdict::Unknown);
}

TEST_F(FusionDeciderTest, Tier1ShortCircuitsAtThreshold)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.97F, "win32_es_password"),
        mk(Verdict::Username, 0.6F, "uia_metadata"),
    };
    EXPECT_EQ(decider.decide(results), Verdict::Password);
}

TEST_F(FusionDeciderTest, Tier1JustBelowThresholdFallsToVote)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.94F, "win32_es_password"),
        mk(Verdict::Username, 0.6F, "uia_metadata"),
    };
    // Tier-1 threshold is 0.95; neither qualifies. Tier-2 vote:
    //   score(Password) = 0.94 * 0.7  = 0.658
    //   score(Username) = 0.60 * 0.6  = 0.360
    //   diff 0.298 < 0.7 margin -> Unknown
    EXPECT_EQ(decider.decide(results), Verdict::Unknown);
}

TEST_F(FusionDeciderTest, TwoTier1AgreeingShortCircuits)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.96F, "uia_is_password"),
        mk(Verdict::Password, 0.97F, "win32_es_password"),
    };
    EXPECT_EQ(decider.decide(results), Verdict::Password);
}

TEST_F(FusionDeciderTest, TwoTier1DisagreeingFallsToVote)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.96F, "uia_is_password"),
        mk(Verdict::Username, 0.97F, "win32_es_password"),
    };
    // Both Tier-1 hits but disagreeing -> fall to Tier-2 vote on all probes.
    //   score(Password) = 0.96 * 0.85 = 0.816
    //   score(Username) = 0.97 * 0.70 = 0.679
    //   diff 0.137 < 0.7 margin -> Unknown
    EXPECT_EQ(decider.decide(results), Verdict::Unknown);
}

TEST_F(FusionDeciderTest, Tier2VoteAboveMarginReturnsPassword)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.8F, "uia_metadata"),     // 0.8 * 0.60 = 0.48
        mk(Verdict::Password, 0.9F, "uia_is_password"),  // 0.9 * 0.85 = 0.765
        mk(Verdict::Username, 0.3F, "ime_state"),        // 0.3 * 0.30 = 0.09
    };
    // Score(P) = 1.245, Score(U) = 0.09, diff 1.155 >= 0.7 -> Password.
    EXPECT_EQ(decider.decide(results), Verdict::Password);
}

TEST_F(FusionDeciderTest, Tier2VoteAboveMarginReturnsUsername)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Username, 0.9F, "uia_metadata"),     // 0.9 * 0.60 = 0.54
        mk(Verdict::Username, 0.9F, "uia_is_password"),  // 0.9 * 0.85 = 0.765
        mk(Verdict::Password, 0.3F, "ime_state"),        // 0.3 * 0.30 = 0.09
    };
    // Score(U) = 1.305, Score(P) = 0.09, diff 1.215 >= 0.7 -> Username.
    EXPECT_EQ(decider.decide(results), Verdict::Username);
}

TEST_F(FusionDeciderTest, UnknownVerdictsIgnoredInVote)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Unknown, 0.9F, "uia_is_password"),
        mk(Verdict::Password, 0.9F, "uia_metadata"),
        mk(Verdict::Unknown, 0.9F, "win32_es_password"),
    };
    // Only metadata contributes: 0.9 * 0.6 = 0.54 < 0.7 margin -> Unknown.
    EXPECT_EQ(decider.decide(results), Verdict::Unknown);
}

TEST_F(FusionDeciderTest, UnknownProbeNameIgnored)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.96F, "some_unknown_probe"),
    };
    // No registered profile; contributes nothing to Tier-1 or Tier-2.
    EXPECT_EQ(decider.decide(results), Verdict::Unknown);
}

// M5: bridge alone at Tier-1 threshold must NOT short-circuit. Falls
// through to Tier-2 where weight 0.9 is still high, but a single
// disagreeing probe can pull the score under the 0.7 margin.
TEST_F(FusionDeciderTest, BridgeAloneAtTier1ThresholdFallsToVote)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.97F, "browser_extension"),
        // Tier-2 vote: P = 0.97 * 0.9 = 0.873; U = 0; diff >= 0.7 -> Password.
        // Bridge alone still produces a verdict; M5 just routes through
        // Tier-2 (weights + margin) instead of an unconditional short-circuit.
    };
    EXPECT_EQ(decider.decide(results), Verdict::Password);
}

TEST_F(FusionDeciderTest, BridgeAloneCounteredByLowerProbeFallsBelowMargin)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.97F, "browser_extension"),  // 0.97 * 0.9 = 0.873
        mk(Verdict::Username, 0.5F, "uia_metadata"),        // 0.5 * 0.6 = 0.30
    };
    // diff 0.573 < 0.7 -> Unknown. Under M5, a single low-confidence
    // dissent overrides a Tier-1-grade bridge claim.
    EXPECT_EQ(decider.decide(results), Verdict::Unknown);
}

TEST_F(FusionDeciderTest, BridgePlusUiaAgreeingShortCircuits)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.97F, "browser_extension"),
        mk(Verdict::Password, 0.96F, "uia_is_password"),
    };
    // Two Tier-1 hits agreeing; M5 gate is satisfied (bridge not alone),
    // short-circuit fires.
    EXPECT_EQ(decider.decide(results), Verdict::Password);
}

TEST_F(FusionDeciderTest, BridgeAgreesWithWin32ButUiaDisagrees)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.97F, "browser_extension"),  // 0.873
        mk(Verdict::Password, 0.97F, "win32_es_password"),  // 0.679
        mk(Verdict::Username, 0.97F, "uia_is_password"),    // 0.825
    };
    // Three Tier-1 hits but disagreement -> bypass short-circuit, vote:
    //   score(Password) = 0.873 + 0.679 = 1.552
    //   score(Username) = 0.825
    //   diff = 0.727 >= 0.7 -> Password.
    EXPECT_EQ(decider.decide(results), Verdict::Password);
}

// --- decideDetailed: the flags the zero-gesture auto-fill path gates on. ---

// Bridge + an on-disk Tier-1 probe agree: short-circuit fires AND the bridge
// is corroborated -> the auto path is allowed to release the secret.
TEST_F(FusionDeciderTest, DetailedBridgePlusUiaAgreeIsCorroborated)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.97F, "browser_extension"),
        mk(Verdict::Password, 0.96F, "uia_is_password"),
    };
    const FusionOutcome out = decider.decideDetailed(results);
    EXPECT_EQ(out.m_Verdict, Verdict::Password);
    EXPECT_TRUE(out.m_Tier1ShortCircuit);
    EXPECT_TRUE(out.m_BridgeCorroborated);
}

// Bridge ALONE still yields a verdict via the Tier-2 vote (0.873 >= margin),
// but neither flag is set -> the auto path MUST refuse. This is the M5 hole
// that decideDetailed exists to expose (decide() alone cannot distinguish it).
TEST_F(FusionDeciderTest, DetailedBridgeAloneIsNotCorroborated)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.97F, "browser_extension"),
    };
    const FusionOutcome out = decider.decideDetailed(results);
    EXPECT_EQ(out.m_Verdict, Verdict::Password);  // decide() compatibility
    EXPECT_FALSE(out.m_Tier1ShortCircuit);
    EXPECT_FALSE(out.m_BridgeCorroborated);
}

// Bridge Password vs a text field: on-disk probes are Unknown (the Threat-3
// verdict-flip). Bridge-alone -> not corroborated -> auto path refuses.
TEST_F(FusionDeciderTest, DetailedBridgeOverTextFieldNotCorroborated)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.97F, "browser_extension"),
        mk(Verdict::Unknown, 0.0F, "uia_is_password"),
        mk(Verdict::Unknown, 0.0F, "win32_es_password"),
        mk(Verdict::Unknown, 0.0F, "uia_metadata"),
    };
    const FusionOutcome out = decider.decideDetailed(results);
    EXPECT_FALSE(out.m_BridgeCorroborated);
}

// Two on-disk probes agree with no bridge in play: short-circuit fires, but
// there is no bridge hit to corroborate, so m_BridgeCorroborated stays false.
TEST_F(FusionDeciderTest, DetailedOnDiskOnlyIsNotBridgeCorroborated)
{
    const FusionDecider decider;
    const std::vector<ProbeResult> results = {
        mk(Verdict::Password, 0.96F, "uia_is_password"),
        mk(Verdict::Password, 0.97F, "win32_es_password"),
    };
    const FusionOutcome out = decider.decideDetailed(results);
    EXPECT_EQ(out.m_Verdict, Verdict::Password);
    EXPECT_TRUE(out.m_Tier1ShortCircuit);
    EXPECT_FALSE(out.m_BridgeCorroborated);
}
