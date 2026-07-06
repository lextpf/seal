#include "CameraSelector.hpp"

#include "ConsoleStyle.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"

#include <QtCore/QString>

#include <opencv2/highgui.hpp>
#include <opencv2/imgproc.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <comdef.h>
#include <dshow.h>
#include <windows.h>

#pragma comment(lib, "strmiids.lib")

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cwctype>
#include <iostream>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace
{
bool IsVirtualCameraName(const std::wstring& name);
bool IsObsCameraName(const std::wstring& name);

// Route diagnostics through the Qt logging system so they inherit the
// unified `[ts] [LVL] [seal.camera] [tid=N]` prefix.
void writeCameraDiag(seal::console::Tone tone, std::initializer_list<std::string> fields)
{
    writeToneLine(logCamera(), tone, fields);
}

std::string narrowToken(std::string_view text, size_t maxLen = 32)
{
    return seal::diag::sanitizeAscii(text, maxLen);
}

std::string nameMeta(const std::wstring& name)
{
    return seal::diag::joinFields({seal::diag::kv("name_len", name.size()),
                                   seal::diag::kv("virtual_hint", IsVirtualCameraName(name)),
                                   seal::diag::kv("obs_hint", IsObsCameraName(name))});
}

// Virtual-camera keywords used by ChooseCameraIndexFromNames,
// IsVirtualCameraName, and BuildCameraPriorityList for consistent filtering.
constexpr std::array<std::wstring_view, 5> kVirtualCameraKeywords = {
    L"camo", L"virtual", L"obs", L"droidcam", L"ndi"};

std::wstring ToLower(std::wstring s)
{
    std::transform(
        s.begin(), s.end(), s.begin(), [](wchar_t ch) { return (wchar_t)std::towlower(ch); });
    return s;
}

bool EnvFlagEnabled(const char* key)
{
    if (const char* raw = std::getenv(key))
    {
        const std::string v = raw;
        return v == "1" || v == "true" || v == "TRUE" || v == "yes" || v == "YES";
    }
    return false;
}

bool TryGetEnvIndex(const char* key, int& out)
{
    if (const char* raw = std::getenv(key))
    {
        char* end = nullptr;
        long idx = std::strtol(raw, &end, 10);
        if (end != raw && *end == '\0' && idx >= 0 && idx <= 99)
        {
            out = (int)idx;
            return true;
        }
    }
    return false;
}

// List video capture devices via DirectShow (CLSID_SystemDeviceEnum) by
// FriendlyName. Indices match OpenCV's camera indices; unreadable names
// become empty strings to keep the mapping aligned.
std::vector<std::wstring> EnumerateVideoDeviceNamesDShow()
{
    std::vector<std::wstring> names;

    // Try MTA; if the thread is STA (Qt event loop), retry STA so
    // CoInitializeEx doesn't return RPC_E_CHANGED_MODE.
    //   S_OK    -> we own the init; must CoUninitialize.
    //   S_FALSE -> COM was already initialised; DO NOT uninitialize.
    HRESULT hrCo = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (hrCo == RPC_E_CHANGED_MODE)
    {
        hrCo = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    }
    const bool weInitializedCom = (hrCo == S_OK);

    ICreateDevEnum* devEnum = nullptr;
    IEnumMoniker* enumMoniker = nullptr;

    HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum,
                                  nullptr,
                                  CLSCTX_INPROC_SERVER,
                                  IID_ICreateDevEnum,
                                  (void**)&devEnum);
    if (SUCCEEDED(hr) && devEnum)
    {
        hr = devEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &enumMoniker, 0);
        if (hr == S_OK && enumMoniker)
        {
            IMoniker* moniker = nullptr;
            while (enumMoniker->Next(1, &moniker, nullptr) == S_OK)
            {
                IPropertyBag* bag = nullptr;
                if (SUCCEEDED(moniker->BindToStorage(0, 0, IID_IPropertyBag, (void**)&bag)) && bag)
                {
                    VARIANT varName;
                    VariantInit(&varName);
                    if (SUCCEEDED(bag->Read(L"FriendlyName", &varName, 0)) && varName.vt == VT_BSTR)
                    {
                        names.emplace_back(varName.bstrVal);
                    }
                    else
                    {
                        names.emplace_back(L"");
                    }
                    VariantClear(&varName);
                    bag->Release();
                }
                else
                {
                    names.emplace_back(L"");
                }
                moniker->Release();
            }
        }
    }

    if (enumMoniker)
        enumMoniker->Release();
    if (devEnum)
        devEnum->Release();
    if (weInitializedCom)
    {
        CoUninitialize();
    }

    return names;
}

// Priority cascade: (1) SEAL_CAMERA_INDEX env override; (2) SEAL_PREFERRED_CAMERA
// keyword match (e.g. "razer kiyo"); (3) first non-virtual camera (skips OBS,
// Camo, DroidCam, ...); (4) index 0 as last-resort fallback.
int ChooseCameraIndexFromNames(const std::vector<std::wstring>& names, bool log)
{
    // Priority 1: env override.
    if (const char* forced = std::getenv("SEAL_CAMERA_INDEX"))
    {
        char* end = nullptr;
        long idx = std::strtol(forced, &end, 10);
        if (end != forced && *end == '\0' && idx >= 0 && idx <= 99)
        {
            if (log)
            {
                writeCameraDiag(seal::console::Tone::Info,
                                {"event=camera.select.hint",
                                 "source=env_index",
                                 seal::diag::kv("index", static_cast<int>(idx))});
            }
            return (int)idx;
        }
    }

    if (names.empty())
    {
        return 0;
    }

    if (log)
    {
        writeCameraDiag(
            seal::console::Tone::Info,
            {"event=camera.enumerate.finish", "result=ok", seal::diag::kv("count", names.size())});
        for (size_t i = 0; i < names.size(); ++i)
        {
            writeCameraDiag(
                seal::console::Tone::Debug,
                {"event=camera.enumerate.device", seal::diag::kv("index", i), nameMeta(names[i])});
        }
    }

    // Priority 2: preferred-keyword match (comma-separated
    // SEAL_PREFERRED_CAMERA). Skipped if unset.
    std::vector<std::wstring> preferredKeywords;
    if (const char* pref = std::getenv("SEAL_PREFERRED_CAMERA"))
    {
        std::string raw = pref;
        size_t start = 0;
        while (start < raw.size())
        {
            size_t end = raw.find(',', start);
            if (end == std::string::npos)
            {
                end = raw.size();
            }
            std::string token = raw.substr(start, end - start);
            while (!token.empty() && token.front() == ' ')
            {
                token.erase(token.begin());
            }
            while (!token.empty() && token.back() == ' ')
            {
                token.pop_back();
            }
            if (!token.empty())
            {
                int needed =
                    MultiByteToWideChar(CP_UTF8, 0, token.c_str(), (int)token.size(), nullptr, 0);
                if (needed > 0)
                {
                    std::wstring wide(static_cast<size_t>(needed), L'\0');
                    MultiByteToWideChar(
                        CP_UTF8, 0, token.c_str(), (int)token.size(), wide.data(), needed);
                    preferredKeywords.push_back(ToLower(wide));
                }
            }
            start = end + 1;
        }
    }
    for (size_t i = 0; i < names.size(); ++i)
    {
        const std::wstring nameLower = ToLower(names[i]);
        for (const auto& kw : preferredKeywords)
        {
            if (nameLower.find(kw) != std::wstring::npos)
            {
                if (log)
                {
                    writeCameraDiag(seal::console::Tone::Info,
                                    {"event=camera.select.hint",
                                     "source=preferred_keyword",
                                     seal::diag::kv("index", i),
                                     nameMeta(names[i])});
                }
                return (int)i;
            }
        }
    }

    // Priority 3: first non-virtual camera (virtuals often deliver
    // garbage frames or need special setup).
    for (size_t i = 0; i < names.size(); ++i)
    {
        const std::wstring nameLower = ToLower(names[i]);
        bool avoid = false;
        for (const auto& kw : kVirtualCameraKeywords)
        {
            if (nameLower.find(kw) != std::wstring::npos)
            {
                avoid = true;
                break;
            }
        }
        if (!avoid)
        {
            if (log)
            {
                writeCameraDiag(seal::console::Tone::Info,
                                {"event=camera.select.hint",
                                 "source=first_physical",
                                 seal::diag::kv("index", i),
                                 nameMeta(names[i])});
            }
            return (int)i;
        }
    }

    return 0;
}

// Heuristic match against keywords used by software cameras.
bool IsVirtualCameraName(const std::wstring& name)
{
    const std::wstring nameLower = ToLower(name);
    for (const auto& kw : kVirtualCameraKeywords)
    {
        if (nameLower.find(kw) != std::wstring::npos)
        {
            return true;
        }
    }
    return false;
}

bool IsObsCameraName(const std::wstring& name)
{
    const std::wstring nameLower = ToLower(name);
    return nameLower.find(L"obs") != std::wstring::npos;
}

// De-duped probe order: forced > preferred > physical > virtual >
// fallback 0..3. 'seen' guarantees uniqueness across tiers.
std::vector<int> BuildCameraPriorityList(const std::vector<std::wstring>& names,
                                         int preferredFromNames)
{
    std::vector<int> priority;
    std::set<int> seen;
    auto addUnique = [&](int idx)
    {
        if (idx < 0)
            return;
        if (seen.insert(idx).second)
            priority.push_back(idx);
    };

    int forcedIndex = -1;
    if (TryGetEnvIndex("SEAL_CAMERA_INDEX", forcedIndex))
    {
        addUnique(forcedIndex);
    }

    if (!names.empty())
    {
        addUnique(preferredFromNames);

        for (size_t i = 0; i < names.size(); ++i)
        {
            if (!IsVirtualCameraName(names[i]))
            {
                addUnique((int)i);
            }
        }
        for (size_t i = 0; i < names.size(); ++i)
        {
            addUnique((int)i);
        }
    }
    else
    {
        addUnique(0);
        addUnique(1);
        addUnique(2);
        addUnique(3);
    }
    return priority;
}

// Try a few reads to confirm the camera actually delivers frames.
bool ProbeFrame(cv::VideoCapture& cap, cv::Mat& frame)
{
    for (int i = 0; i < 4; ++i)
    {
        if (cap.read(frame) && !frame.empty())
        {
            return true;
        }
        Sleep(5);
    }
    return false;
}

// Open a camera at the given index/backend, request resolution, and verify frames arrive.
bool TryOpenCamera(cv::VideoCapture& cap,
                   int cameraIndex,
                   int api,
                   const char* apiName,
                   cv::Mat& probeFrame,
                   bool requestHighRes)
{
    cap.release();
    const std::string apiToken = narrowToken(apiName);

    const bool opened = (api == cv::CAP_ANY) ? cap.open(cameraIndex) : cap.open(cameraIndex, api);
    if (!opened)
    {
        writeCameraDiag(seal::console::Tone::Warning,
                        {"event=camera.open.finish",
                         "result=fail",
                         seal::diag::kv("index", cameraIndex),
                         seal::diag::kv("backend", apiToken),
                         "reason=open_failed"});
        return false;
    }

    if (!ProbeFrame(cap, probeFrame))
    {
        writeCameraDiag(seal::console::Tone::Warning,
                        {"event=camera.open.finish",
                         "result=fail",
                         seal::diag::kv("index", cameraIndex),
                         seal::diag::kv("backend", apiToken),
                         "reason=no_frames"});
        cap.release();
        return false;
    }

    if (requestHighRes)
    {
        cap.set(cv::CAP_PROP_FRAME_WIDTH, 1920);
        cap.set(cv::CAP_PROP_FRAME_HEIGHT, 1080);
    }
    else
    {
        cap.set(cv::CAP_PROP_FRAME_WIDTH, 1280);
        cap.set(cv::CAP_PROP_FRAME_HEIGHT, 720);
    }

    if (!cap.read(probeFrame) || probeFrame.empty())
    {
        if (requestHighRes)
        {
            writeCameraDiag(seal::console::Tone::Warning,
                            {"event=camera.open.fallback",
                             seal::diag::kv("index", cameraIndex),
                             seal::diag::kv("backend", apiToken),
                             "reason=high_res_unstable",
                             "from=1920x1080",
                             "to=1280x720"});
            cap.set(cv::CAP_PROP_FRAME_WIDTH, 1280);
            cap.set(cv::CAP_PROP_FRAME_HEIGHT, 720);
            if (!cap.read(probeFrame) || probeFrame.empty())
            {
                writeCameraDiag(seal::console::Tone::Warning,
                                {"event=camera.open.finish",
                                 "result=fail",
                                 seal::diag::kv("index", cameraIndex),
                                 seal::diag::kv("backend", apiToken),
                                 "reason=fallback_failed"});
                cap.release();
                return false;
            }
        }
        else
        {
            writeCameraDiag(seal::console::Tone::Warning,
                            {"event=camera.open.finish",
                             "result=fail",
                             seal::diag::kv("index", cameraIndex),
                             seal::diag::kv("backend", apiToken),
                             "reason=stream_failed_720p"});
            cap.release();
            return false;
        }
    }

    writeCameraDiag(seal::console::Tone::Success,
                    {"event=camera.open.finish",
                     "result=ok",
                     seal::diag::kv("index", cameraIndex),
                     seal::diag::kv("backend", apiToken),
                     seal::diag::kv("width", probeFrame.cols),
                     seal::diag::kv("height", probeFrame.rows),
                     seal::diag::kv("requested_high_res", requestHighRes)});
    return true;
}

// Higher score = better camera. Resolution dominates (pixel area / 1000 +
// a large bonus at >= 1080p); +500 for DShow (more reliable than MSMF on
// UVC); +200 for the preferred index.
double ScoreCandidate(int index, int w, int h, int preferredIndex, bool backendDshow)
{
    double score = 0.0;
    score += (double)w * (double)h / 1000.0;  // pixel area
    if (w >= 1900 && h >= 1000)
        score += 5000.0;  // Full HD or higher
    if (backendDshow)
        score += 500.0;  // DShow > MSMF on most UVC hardware
    if (index == preferredIndex)
        score += 200.0;  // preferred camera boost
    return score;
}

}  // namespace

namespace seal
{

int EnvIntOrDefault(const char* key, int defaultValue, int minValue, int maxValue)
{
    if (const char* raw = std::getenv(key))
    {
        char* end = nullptr;
        long value = std::strtol(raw, &end, 10);
        if (end != raw && *end == '\0')
        {
            if (value < minValue)
                value = minValue;
            if (value > maxValue)
                value = maxValue;
            return (int)value;
        }
    }
    return defaultValue;
}

// Enumerate, probe, score, and select the best available camera.
bool PickBestCamera(cv::VideoCapture& cap, cv::Mat& frame)
{
    const auto names = EnumerateVideoDeviceNamesDShow();
    const int preferredByName = names.empty() ? -1 : ChooseCameraIndexFromNames(names, true);
    const auto cameraPriority = BuildCameraPriorityList(names, preferredByName);
    const int preferredIndexHint = preferredByName >= 0
                                       ? preferredByName
                                       : (cameraPriority.empty() ? -1 : cameraPriority.front());
    int forcedIndex = -1;
    const bool hasForcedIndex = TryGetEnvIndex("SEAL_CAMERA_INDEX", forcedIndex);
    const bool allowVirtualFallback = EnvFlagEnabled("SEAL_ALLOW_VIRTUAL_CAMERA");
    const bool allowObsCamera = EnvFlagEnabled("SEAL_ALLOW_OBS_CAMERA");
    const bool quickCameraSelect = !EnvFlagEnabled("SEAL_DISABLE_CAMERA_QUICK_SELECT");

    struct BackendTry
    {
        int api;
        const char* name;
    };
    const std::vector<BackendTry> backendOrder = {
        {cv::CAP_DSHOW, "DSHOW"},
    };

    // Scored camera candidate used to rank all usable devices.
    struct CameraCandidate
    {
        int index = -1;
        int api = cv::CAP_ANY;
        const char* backend = "";
        int width = 0;
        int height = 0;
        double score = -1.0;
        bool preferredByName = false;
        bool knownByName = false;
        bool virtualByName = false;
        bool valid = false;
    };

    std::vector<CameraCandidate> candidates;
    CameraCandidate chosen;
    bool chooseOk = false;
    bool cameraOpenForChosen = false;
    bool quickCameraHit = false;

    for (int idx : cameraPriority)
    {
        for (const auto& be : backendOrder)
        {
            if (!TryOpenCamera(cap, idx, be.api, be.name, frame, true))
                continue;

            const int w = (int)cap.get(cv::CAP_PROP_FRAME_WIDTH);
            const int h = (int)cap.get(cv::CAP_PROP_FRAME_HEIGHT);
            const bool isDshow = be.api == cv::CAP_DSHOW;
            const double score = ScoreCandidate(idx, w, h, preferredIndexHint, isDshow);

            writeCameraDiag(seal::console::Tone::Debug,
                            {"event=camera.candidate",
                             seal::diag::kv("index", idx),
                             seal::diag::kv("backend", narrowToken(be.name)),
                             seal::diag::kv("width", w),
                             seal::diag::kv("height", h),
                             seal::diag::kv("score", score, 2)});

            CameraCandidate cand;
            cand.index = idx;
            cand.api = be.api;
            cand.backend = be.name;
            cand.width = w;
            cand.height = h;
            cand.score = score;
            cand.knownByName = idx >= 0 && idx < (int)names.size();
            cand.virtualByName = cand.knownByName ? IsVirtualCameraName(names[idx]) : false;
            cand.preferredByName = cand.knownByName && (idx == preferredByName);
            cand.valid = true;
            candidates.push_back(cand);

            const bool quickForcedHit = hasForcedIndex && idx == forcedIndex;
            const bool quickPreferredHit =
                !hasForcedIndex && preferredByName >= 0 && idx == preferredByName;
            if (quickCameraSelect && (quickForcedHit || quickPreferredHit))
            {
                chosen = cand;
                chooseOk = true;
                cameraOpenForChosen = true;
                quickCameraHit = true;
                writeCameraDiag(seal::console::Tone::Info,
                                {"event=camera.select.quick",
                                 "result=ok",
                                 seal::diag::kv("index", idx),
                                 seal::diag::kv("backend", narrowToken(be.name)),
                                 seal::diag::kv("forced", quickForcedHit)});
                break;
            }

            cap.release();
            frame.release();
        }
        if (quickCameraHit)
            break;
    }

    if (candidates.empty())
    {
        writeCameraDiag(seal::console::Tone::Error,
                        {"event=camera.select.finish", "result=fail", "reason=no_candidates"});
        return false;
    }

    auto chooseBest = [&](auto predicate)
    {
        bool found = false;
        CameraCandidate bestLocal;
        for (const auto& c : candidates)
        {
            if (!predicate(c))
                continue;
            if (!found || c.score > bestLocal.score)
            {
                bestLocal = c;
                found = true;
            }
        }
        if (found)
            chosen = bestLocal;
        return found;
    };

    // Cascade: forced env > preferred name > physical > unknown > virtual.
    if (!chooseOk)
    {
        if (hasForcedIndex)
        {
            chooseOk = chooseBest([&](const CameraCandidate& c) { return c.index == forcedIndex; });
            if (!chooseOk)
            {
                writeCameraDiag(seal::console::Tone::Warning,
                                {"event=camera.select.hint",
                                 "result=fail",
                                 "source=env_index",
                                 seal::diag::kv("index", forcedIndex),
                                 "reason=not_available"});
            }
        }
        else
        {
            chooseOk = chooseBest([&](const CameraCandidate& c) { return c.preferredByName; });
            if (!chooseOk)
            {
                chooseOk = chooseBest([&](const CameraCandidate& c)
                                      { return c.knownByName && !c.virtualByName; });
            }
            if (!chooseOk)
            {
                chooseOk = chooseBest([&](const CameraCandidate& c) { return !c.knownByName; });
            }
            if (!chooseOk && allowVirtualFallback)
            {
                chooseOk = chooseBest(
                    [&](const CameraCandidate& c)
                    {
                        if (!c.virtualByName)
                            return false;
                        if (!c.knownByName)
                            return false;
                        if (IsObsCameraName(names[c.index]) && !allowObsCamera)
                            return false;
                        return true;
                    });
            }
        }
    }

    if (!chooseOk)
    {
        writeCameraDiag(seal::console::Tone::Error,
                        {"event=camera.select.finish",
                         "result=fail",
                         "reason=no_usable_camera",
                         seal::diag::kv("allow_virtual_fallback", allowVirtualFallback),
                         seal::diag::kv("allow_obs_camera", allowObsCamera)});
        return false;
    }

    // Re-open the chosen camera if scoring released it.
    if (!cameraOpenForChosen &&
        !TryOpenCamera(cap, chosen.index, chosen.api, chosen.backend, frame, true))
    {
        writeCameraDiag(seal::console::Tone::Error,
                        {"event=camera.select.finish",
                         "result=fail",
                         seal::diag::kv("index", chosen.index),
                         seal::diag::kv("backend", narrowToken(chosen.backend)),
                         "reason=reopen_failed"});
        return false;
    }

    writeCameraDiag(seal::console::Tone::Success,
                    {"event=camera.select.finish",
                     "result=ok",
                     seal::diag::kv("index", chosen.index),
                     seal::diag::kv("backend", narrowToken(chosen.backend)),
                     seal::diag::kv("width", chosen.width),
                     seal::diag::kv("height", chosen.height),
                     seal::diag::kv("known_by_name", chosen.knownByName),
                     seal::diag::kv("virtual_by_name", chosen.virtualByName)});
    return true;
}

}  // namespace seal
