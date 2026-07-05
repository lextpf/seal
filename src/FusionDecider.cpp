#include "FusionDecider.hpp"

#include <array>
#include <string_view>

namespace seal
{

namespace
{

constexpr float kTier1Threshold = 0.95F;
constexpr float kMargin = 0.7F;

struct ProbeProfile
{
    std::string_view m_Name;
    float m_Tier2Weight = 0.0F;
    bool m_Tier1Eligible = false;
};

constexpr std::array<ProbeProfile, 5> kProfiles = {{
    {"browser_extension", 0.9F, true},
    {"win32_es_password", 0.7F, true},
    {"uia_is_password", 0.85F, true},
    {"uia_metadata", 0.6F, false},
    {"ime_state", 0.3F, false},
}};

const ProbeProfile* lookup(const char* name)
{
    if (name == nullptr)
    {
        return nullptr;
    }
    const std::string_view needle{name};
    for (const auto& profile : kProfiles)
    {
        if (profile.m_Name == needle)
        {
            return &profile;
        }
    }
    return nullptr;
}

}  // namespace

Verdict FusionDecider::decide(std::span<const ProbeResult> results) const
{
    return decideDetailed(results).m_Verdict;
}

FusionOutcome FusionDecider::decideDetailed(std::span<const ProbeResult> results) const
{
    FusionOutcome outcome;

    // Pass 1: collect Tier-1 short-circuit candidates.
    Verdict tier1Verdict = Verdict::Unknown;
    int tier1HitCount = 0;
    int tier1BridgeOnlyCount = 0;  // M5: bridge must agree with another Tier-1 probe.
    bool tier1Conflict = false;

    for (const auto& result : results)
    {
        if (result.m_Verdict == Verdict::Unknown)
        {
            continue;
        }
        const ProbeProfile* profile = lookup(result.m_ProbeName);
        if ((profile == nullptr) || !profile->m_Tier1Eligible)
        {
            continue;
        }
        if (result.m_Confidence < kTier1Threshold)
        {
            continue;
        }
        if (tier1HitCount == 0)
        {
            tier1Verdict = result.m_Verdict;
        }
        else if (result.m_Verdict != tier1Verdict)
        {
            tier1Conflict = true;
        }
        if (std::string_view{result.m_ProbeName} == std::string_view{"browser_extension"})
        {
            ++tier1BridgeOnlyCount;
        }
        ++tier1HitCount;
    }

    // M5: browser-extension alone cannot short-circuit - another Tier-1
    // probe must agree, otherwise a poisoned bridge map could mis-route.
    const bool bridgeOnlyHit = (tier1HitCount > 0) && (tier1HitCount == tier1BridgeOnlyCount);
    const bool shortCircuit = tier1HitCount > 0 && !tier1Conflict && !bridgeOnlyHit;
    outcome.m_Tier1ShortCircuit = shortCircuit;
    // Corroborated only when a bridge Tier-1 hit was part of an agreeing,
    // non-bridge-only short-circuit - i.e. an on-disk Tier-1 probe agreed.
    outcome.m_BridgeCorroborated = shortCircuit && (tier1BridgeOnlyCount > 0);

    if (shortCircuit)
    {
        outcome.m_Verdict = tier1Verdict;
        return outcome;
    }

    // Pass 2: Tier-2 weighted vote across every probe with a known profile.
    float scorePassword = 0.0F;
    float scoreUsername = 0.0F;
    for (const auto& result : results)
    {
        if (result.m_Verdict == Verdict::Unknown)
        {
            continue;
        }
        const ProbeProfile* profile = lookup(result.m_ProbeName);
        if (profile == nullptr)
        {
            continue;
        }
        const float contribution = profile->m_Tier2Weight * result.m_Confidence;
        if (result.m_Verdict == Verdict::Password)
        {
            scorePassword += contribution;
        }
        else
        {
            scoreUsername += contribution;
        }
    }

    if (scorePassword - scoreUsername >= kMargin)
    {
        outcome.m_Verdict = Verdict::Password;
    }
    else if (scoreUsername - scorePassword >= kMargin)
    {
        outcome.m_Verdict = Verdict::Username;
    }
    else
    {
        outcome.m_Verdict = Verdict::Unknown;
    }
    return outcome;
}

}  // namespace seal
