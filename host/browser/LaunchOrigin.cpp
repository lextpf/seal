#include "LaunchOrigin.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <shellapi.h>

#include <string>
#include <string_view>

namespace seal::browser_host
{
namespace
{

// Pinned Chrome extension origin (deterministic from the manifest "key";
// see src/CliModes.cpp kSealExtensionIdAscii). Update in lockstep if the
// key is ever regenerated.
constexpr std::wstring_view kPinnedChromeOrigin =
    L"chrome-extension://dfjclelhkideboildnjihgildihjjmdo/";
constexpr std::wstring_view kFirefoxOriginPrefix = L"moz-extension://";

// Wide prefix compare; we control the origin strings so case-sensitivity
// is fine.
bool hasPrefix(std::wstring_view full, std::wstring_view prefix) noexcept
{
    if (full.size() < prefix.size())
    {
        return false;
    }
    return full.compare(0, prefix.size(), prefix) == 0;
}

}  // namespace

// argv[1] must be the native-messaging origin the browser passes:
// Chrome -> `chrome-extension://<id>/`, Firefox -> `moz-extension://<uuid>/`.
// Any other shape (raw exec, malware spawn) is rejected before we touch
// the bridge pipe.
bool isLegitimateLaunchOrigin()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr)
    {
        return false;
    }
    bool ok = false;
    if (argc >= 2 && argv[1] != nullptr)
    {
        const std::wstring_view origin(argv[1]);
        if (origin == kPinnedChromeOrigin)
        {
            ok = true;
        }
        else if (hasPrefix(origin, kFirefoxOriginPrefix))
        {
            // Firefox uses a per-install UUID, so the scheme is the
            // strongest claim we can make here. The bridge still
            // requires the parent to be a signed firefox.exe.
            ok = true;
        }
    }
    LocalFree(static_cast<HLOCAL>(argv));
    return ok;
}

}  // namespace seal::browser_host
