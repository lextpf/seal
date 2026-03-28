#include "CameraSelector.h"

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

// Single source of truth for virtual-camera keywords. Used by
// ChooseCameraIndexFromNames, IsVirtualCameraName, and BuildCameraPriorityList
// to avoid duplication and ensure consistent filtering.
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

// Walk DirectShow's COM device enumerator (CLSID_SystemDeviceEnum) to list
// all video capture devices by their "FriendlyName" property.
// Returns one name per device in enumeration order (index 0 = first device).
// Empty strings are inserted for devices whose name cannot be read so that
// indices stay aligned with OpenCV's integer camera indices.
std::vector<std::wstring> EnumerateVideoDeviceNamesDShow()
{
    std::vector<std::wstring> names;

    // Try MTA first; if the thread is already STA (e.g. Qt event loop),
    // CoInitializeEx returns RPC_E_CHANGED_MODE - retry with STA to match.
    // S_OK  = we initialized COM (must call CoUninitialize).
    // S_FALSE = COM was already initialized on this thread (do NOT uninitialize,
    //           or we'll unbalance the reference count for the calling thread).
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

// Pick the best camera index using a priority cascade:
//   1. SEAL_CAMERA_INDEX env var (user override, highest priority)
//   2. Preferred keyword match (e.g. "razer kiyo") - known-good physical webcams
//   3. First non-virtual camera (skips OBS, Camo, DroidCam, etc.)
//   4. Fallback to index 0
int ChooseCameraIndexFromNames(const std::vector<std::wstring>& names, bool log)
{
    // Priority 1: forced env override
    if (const char* forced = std::getenv("SEAL_CAMERA_INDEX"))
    {
        char* end = nullptr;
        long idx = std::strtol(forced, &end, 10);
        if (end != forced && *end == '\0' && idx >= 0 && idx <= 99)
        {
            if (log)
                std::cerr << "Using SEAL_CAMERA_INDEX=" << idx << "\n";
            return (int)idx;
        }
    }

    if (names.empty())
    {
        return 0;
    }

    if (log)
    {
        std::cerr << "Detected cameras:\n";
        for (size_t i = 0; i < names.size(); ++i)
        {
            std::wcerr << L"  [" << i << L"] " << names[i] << L"\n";
        }
    }

    // Priority 2: preferred physical cameras by keyword match.
    // Configurable via SEAL_PREFERRED_CAMERA env var (comma-separated keywords).
    // If not set, this tier is skipped entirely.
    std::vector<std::wstring> preferredKeywords;
    if (const char* pref = std::getenv("SEAL_PREFERRED_CAMERA"))
    {
        // Parse comma-separated keywords from the env var.
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
            // Trim whitespace
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
                    std::wcerr << L"Selecting preferred webcam: " << names[i] << L" (index " << i
                               << L")\n";
                }
                return (int)i;
            }
        }
    }

    // Priority 3: first non-virtual camera.
    // Virtual cameras often produce garbage frames or require special setup.
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
                std::wcerr << L"Selecting first non-virtual camera: " << names[i] << L" (index "
                           << i << L")\n";
            }
            return (int)i;
        }
    }

    return 0;
}

// Heuristic: names containing these keywords are usually software cameras.
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

// Build a de-duplicated probe order: forced > preferred > physical > virtual > fallback 0-3.
// The set<int> 'seen' ensures each index appears at most once, even if multiple
// priority tiers would select the same device.
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

    const bool opened = (api == cv::CAP_ANY) ? cap.open(cameraIndex) : cap.open(cameraIndex, api);
    if (!opened)
    {
        std::cerr << "Camera open failed: index " << cameraIndex << " via " << apiName << "\n";
        return false;
    }

    if (!ProbeFrame(cap, probeFrame))
    {
        std::cerr << "Camera opened but no frames: index " << cameraIndex << " via " << apiName
                  << "\n";
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
            std::cerr << "1080p unstable on index " << cameraIndex << " via " << apiName
                      << ", falling back to 1280x720\n";
            cap.set(cv::CAP_PROP_FRAME_WIDTH, 1280);
            cap.set(cv::CAP_PROP_FRAME_HEIGHT, 720);
            if (!cap.read(probeFrame) || probeFrame.empty())
            {
                std::cerr << "Camera stream failed after resolution fallback: index " << cameraIndex
                          << " via " << apiName << "\n";
                cap.release();
                return false;
            }
        }
        else
        {
            std::cerr << "Camera stream failed at 720p: index " << cameraIndex << " via " << apiName
                      << "\n";
            cap.release();
            return false;
        }
    }

    std::cerr << "Camera ready: index " << cameraIndex << " via " << apiName << "\n";
    return true;
}

// Score-based camera ranking. Higher score = better camera.
//   - Resolution dominates (pixel area / 1000, plus a big bonus for >= 1080p)
//   - DShow backend bonus (+500): more reliable than MSMF on many UVC devices
//   - Preferred index bonus (+200): user's or auto-detected favourite camera
double ScoreCandidate(int index, int w, int h, int preferredIndex, bool backendDshow)
{
    double score = 0.0;
    score += (double)w * (double)h / 1000.0;  // base: pixel count
    if (w >= 1900 && h >= 1000)
        score += 5000.0;  // large bonus for Full HD or higher
    if (backendDshow)
        score += 500.0;  // DShow is more stable than MSMF on most hardware
    if (index == preferredIndex)
        score += 200.0;  // slight boost for the user's preferred camera
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

            std::cerr << "Candidate camera: index " << idx << " via " << be.name << " @" << w << "x"
                      << h << " score=" << score << "\n";

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
                std::cerr << "Quick camera select: index " << idx << " via " << be.name << "\n";
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
        std::cerr << "Could not open webcam\n";
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

    // Selection cascade: forced env > preferred name > physical > unknown > virtual.
    if (!chooseOk)
    {
        if (hasForcedIndex)
        {
            chooseOk = chooseBest([&](const CameraCandidate& c) { return c.index == forcedIndex; });
            if (!chooseOk)
            {
                std::cerr << "Forced camera index SEAL_CAMERA_INDEX=" << forcedIndex
                          << " was not available.\n";
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
        std::cerr << "No usable camera found.\n"
                  << "Close/disable Camo and OBS Virtual Camera, then retry.\n"
                  << "Set SEAL_ALLOW_VIRTUAL_CAMERA=1 for virtual fallback.\n"
                  << "Set SEAL_ALLOW_OBS_CAMERA=1 to allow OBS.\n";
        return false;
    }

    // Re-open the chosen camera if it was released during scoring.
    if (!cameraOpenForChosen &&
        !TryOpenCamera(cap, chosen.index, chosen.api, chosen.backend, frame, true))
    {
        std::cerr << "Selected camera could not be reopened for capture.\n";
        return false;
    }

    std::cerr << "Using camera index " << chosen.index << " via " << chosen.backend << " @"
              << chosen.width << "x" << chosen.height;
    if (chosen.knownByName)
    {
        std::wcerr << L" name=\"" << names[chosen.index] << L"\"";
    }
    std::cerr << "\n";
    return true;
}

}  // namespace seal
