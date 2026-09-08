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

// Manifest key changes must also update kSealExtensionIdAscii in src/CliModes.cpp.
constexpr std::wstring_view kPinnedChromeOrigin =
    L"chrome-extension://dfjclelhkideboildnjihgildihjjmdo/";
constexpr std::wstring_view kFirefoxOriginPrefix = L"moz-extension://";

bool hasPrefix(std::wstring_view full, std::wstring_view prefix) noexcept
{
    if (full.size() < prefix.size())
    {
        return false;
    }
    return full.compare(0, prefix.size(), prefix) == 0;
}

}  // namespace

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
            // Gecko origins have per-install UUIDs; signed browser ancestry remains required.
            ok = true;
        }
    }
    LocalFree(static_cast<HLOCAL>(argv));
    return ok;
}

}  // namespace seal::browser_host
