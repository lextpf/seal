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

// Pinned Chrome extension origin. The id derives from the manifest "key" and is
// hardcoded twice: here, and as kSealExtensionIdAscii in src/CliModes.cpp, which
// writes the allowed_origins list. Regenerating the key means updating both.
constexpr std::wstring_view kPinnedChromeOrigin =
    L"chrome-extension://dfjclelhkideboildnjihgildihjjmdo/";
constexpr std::wstring_view kFirefoxOriginPrefix = L"moz-extension://";

// Wide prefix compare. The origin strings are fixed and lower-case, so a
// case-sensitive match is enough.
bool hasPrefix(std::wstring_view full, std::wstring_view prefix) noexcept
{
    if (full.size() < prefix.size())
    {
        return false;
    }
    return full.compare(0, prefix.size(), prefix) == 0;
}

}  // namespace

// argv[1] has to be the native-messaging origin the browser passes: Chrome sends
// `chrome-extension://<id>/`, Firefox sends `moz-extension://<uuid>/`. Any other
// shape, such as a raw exec or a malware spawn, is rejected before this process
// touches the bridge pipe.
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
            // Firefox derives the origin from a per-install UUID, so there is no
            // fixed id to pin and the scheme is the strongest claim available
            // here. The bridge still requires a signed firefox.exe parent.
            ok = true;
        }
    }
    LocalFree(static_cast<HLOCAL>(argv));
    return ok;
}

}  // namespace seal::browser_host
