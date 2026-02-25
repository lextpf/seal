#include "QrCapture.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cwctype>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/objdetect.hpp>
#include <opencv2/videoio.hpp>
#include <opencv2/highgui.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dshow.h>
#include <comdef.h>

#pragma comment(lib, "strmiids.lib")

namespace {

// Maximum time the QR detection loop can run before auto-cancelling.
constexpr int kDefaultCaptureTimeoutSec = 60;

// Reject oversized frames that could trigger buffer overflows in imgproc.
constexpr int kMaxFrameDimension = 3840;

// QR v40 max is ~4296 bytes; anything larger is anomalous.
constexpr size_t kMaxQrDataBytes = 4096;

// 1 GiB process memory cap to block heap-spray / decompression bombs.
constexpr SIZE_T kCaptureMemoryLimitBytes = 1ULL << 30;

// RAII Job Object sandbox caps process memory during capture, lifts on destruction.
struct CaptureJobGuard {
    HANDLE hJob = nullptr;

    explicit CaptureJobGuard(SIZE_T memoryLimitBytes) {
        hJob = CreateJobObjectW(nullptr, nullptr);
        if (!hJob) return;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = memoryLimitBytes;

        if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                     &info, sizeof(info))) {
            CloseHandle(hJob);
            hJob = nullptr;
            return;
        }

        if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
            // Non-fatal: pre-Win10 non-nestable Job or access denied.
            CloseHandle(hJob);
            hJob = nullptr;
        }
    }

    ~CaptureJobGuard() {
        if (!hJob) return;
        // Lift the memory cap so the rest of sage runs unconstrained.
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        (void)SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                      &info, sizeof(info));
        CloseHandle(hJob);
    }

    CaptureJobGuard(const CaptureJobGuard&) = delete;
    CaptureJobGuard& operator=(const CaptureJobGuard&) = delete;
};

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](wchar_t ch) { return (wchar_t)std::towlower(ch); });
    return s;
}

bool EnvFlagEnabled(const char* key) {
    if (const char* raw = std::getenv(key)) {
        const std::string v = raw;
        return v == "1" || v == "true" || v == "TRUE" || v == "yes" || v == "YES";
    }
    return false;
}

int EnvIntOrDefault(const char* key, int defaultValue, int minValue, int maxValue) {
    if (const char* raw = std::getenv(key)) {
        char* end = nullptr;
        long value = std::strtol(raw, &end, 10);
        if (end != raw && *end == '\0') {
            if (value < minValue) value = minValue;
            if (value > maxValue) value = maxValue;
            return (int)value;
        }
    }
    return defaultValue;
}

bool TryGetEnvIndex(const char* key, int& out) {
    if (const char* raw = std::getenv(key)) {
        char* end = nullptr;
        long idx = std::strtol(raw, &end, 10);
        if (end != raw && *end == '\0' && idx >= 0 && idx <= 99) {
            out = (int)idx;
            return true;
        }
    }
    return false;
}

// Walk DirectShow's device enumerator to list all connected webcams by friendly name.
std::vector<std::wstring> EnumerateVideoDeviceNamesDShow() {
    std::vector<std::wstring> names;

    HRESULT hrCo = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool coInitialized = SUCCEEDED(hrCo);

    ICreateDevEnum* devEnum = nullptr;
    IEnumMoniker* enumMoniker = nullptr;

    HRESULT hr = CoCreateInstance(
        CLSID_SystemDeviceEnum, nullptr, CLSCTX_INPROC_SERVER,
        IID_ICreateDevEnum, (void**)&devEnum
    );
    if (SUCCEEDED(hr) && devEnum) {
        hr = devEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &enumMoniker, 0);
        if (hr == S_OK && enumMoniker) {
            IMoniker* moniker = nullptr;
            while (enumMoniker->Next(1, &moniker, nullptr) == S_OK) {
                IPropertyBag* bag = nullptr;
                if (SUCCEEDED(moniker->BindToStorage(0, 0, IID_IPropertyBag, (void**)&bag)) && bag) {
                    VARIANT varName;
                    VariantInit(&varName);
                    if (SUCCEEDED(bag->Read(L"FriendlyName", &varName, 0)) && varName.vt == VT_BSTR) {
                        names.emplace_back(varName.bstrVal);
                    } else {
                        names.emplace_back(L"");
                    }
                    VariantClear(&varName);
                    bag->Release();
                } else {
                    names.emplace_back(L"");
                }
                moniker->Release();
            }
        }
    }

    if (enumMoniker) enumMoniker->Release();
    if (devEnum) devEnum->Release();
    if (coInitialized) CoUninitialize();

    return names;
}

// Pick the best camera index: forced env > preferred keyword > first non-virtual.
int ChooseCameraIndexFromNames(const std::vector<std::wstring>& names, bool log) {
    if (const char* forced = std::getenv("TESS_CAMERA_INDEX")) {
        char* end = nullptr;
        long idx = std::strtol(forced, &end, 10);
        if (end != forced && *end == '\0' && idx >= 0 && idx <= 99) {
            if (log) std::cerr << "Using TESS_CAMERA_INDEX=" << idx << "\n";
            return (int)idx;
        }
    }

    if (names.empty()) {
        return 0;
    }

    if (log) {
        std::cerr << "Detected cameras:\n";
        for (size_t i = 0; i < names.size(); ++i) {
            std::wcerr << L"  [" << i << L"] " << names[i] << L"\n";
        }
    }

    // Preferred physical cameras by keyword match (most specific first).
    const std::vector<std::wstring> preferredKeywords = {
        L"razer kiyo", L"razer"
    };
    for (size_t i = 0; i < names.size(); ++i) {
        const std::wstring nameLower = ToLower(names[i]);
        for (const auto& kw : preferredKeywords) {
                if (nameLower.find(kw) != std::wstring::npos) {
                if (log) {
                    std::wcerr << L"Selecting preferred webcam: " << names[i]
                               << L" (index " << i << L")\n";
                }
                return (int)i;
            }
        }
    }

    // Virtual cameras often produce garbage frames or require special setup.
    const std::vector<std::wstring> avoidKeywords = {
        L"camo", L"virtual", L"obs", L"droidcam", L"ndi"
    };
    for (size_t i = 0; i < names.size(); ++i) {
        const std::wstring nameLower = ToLower(names[i]);
        bool avoid = false;
        for (const auto& kw : avoidKeywords) {
            if (nameLower.find(kw) != std::wstring::npos) {
                avoid = true;
                break;
            }
        }
        if (!avoid) {
            if (log) {
                std::wcerr << L"Selecting first non-virtual camera: " << names[i]
                           << L" (index " << i << L")\n";
            }
            return (int)i;
        }
    }

    return 0;
}

// Heuristic: names containing these keywords are usually software cameras.
bool IsVirtualCameraName(const std::wstring& name) {
    const std::wstring nameLower = ToLower(name);
    const std::vector<std::wstring> avoidKeywords = {
        L"camo", L"virtual", L"obs", L"droidcam", L"ndi"
    };
    for (const auto& kw : avoidKeywords) {
        if (nameLower.find(kw) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool IsObsCameraName(const std::wstring& name) {
    const std::wstring nameLower = ToLower(name);
    return nameLower.find(L"obs") != std::wstring::npos;
}

// Build a de-duplicated probe order: forced > preferred > physical > virtual > fallback 0-3.
std::vector<int> BuildCameraPriorityList(const std::vector<std::wstring>& names, int preferredFromNames) {
    std::vector<int> priority;
    std::set<int> seen;
    auto addUnique = [&](int idx) {
        if (idx < 0) return;
        if (seen.insert(idx).second) priority.push_back(idx);
    };

    int forcedIndex = -1;
    if (TryGetEnvIndex("TESS_CAMERA_INDEX", forcedIndex)) {
        addUnique(forcedIndex);
    }

    if (!names.empty()) {
        addUnique(preferredFromNames);

        for (size_t i = 0; i < names.size(); ++i) {
            if (!IsVirtualCameraName(names[i])) {
                addUnique((int)i);
            }
        }
        for (size_t i = 0; i < names.size(); ++i) {
            addUnique((int)i);
        }
    } else {
        addUnique(0);
        addUnique(1);
        addUnique(2);
        addUnique(3);
    }
    return priority;
}

// Try a few reads to confirm the camera actually delivers frames.
bool ProbeFrame(cv::VideoCapture& cap, cv::Mat& frame) {
    for (int i = 0; i < 4; ++i) {
        if (cap.read(frame) && !frame.empty()) {
            return true;
        }
        Sleep(5);
    }
    return false;
}

// Open a camera at the given index/backend, request resolution, and verify frames arrive.
bool TryOpenCamera(cv::VideoCapture& cap, int cameraIndex, int api, const char* apiName, cv::Mat& probeFrame, bool requestHighRes) {
    cap.release();

    const bool opened = (api == cv::CAP_ANY) ? cap.open(cameraIndex) : cap.open(cameraIndex, api);
    if (!opened) {
        std::cerr << "Camera open failed: index " << cameraIndex << " via " << apiName << "\n";
        return false;
    }

    if (!ProbeFrame(cap, probeFrame)) {
        std::cerr << "Camera opened but no frames: index " << cameraIndex << " via " << apiName << "\n";
        cap.release();
        return false;
    }

    if (requestHighRes) {
        cap.set(cv::CAP_PROP_FRAME_WIDTH, 1920);
        cap.set(cv::CAP_PROP_FRAME_HEIGHT, 1080);
    } else {
        cap.set(cv::CAP_PROP_FRAME_WIDTH, 1280);
        cap.set(cv::CAP_PROP_FRAME_HEIGHT, 720);
    }

    if (!cap.read(probeFrame) || probeFrame.empty()) {
        if (requestHighRes) {
            std::cerr << "1080p unstable on index " << cameraIndex << " via " << apiName
                      << ", falling back to 1280x720\n";
            cap.set(cv::CAP_PROP_FRAME_WIDTH, 1280);
            cap.set(cv::CAP_PROP_FRAME_HEIGHT, 720);
            if (!cap.read(probeFrame) || probeFrame.empty()) {
                std::cerr << "Camera stream failed after resolution fallback: index " << cameraIndex
                          << " via " << apiName << "\n";
                cap.release();
                return false;
            }
        } else {
            std::cerr << "Camera stream failed at 720p: index " << cameraIndex
                      << " via " << apiName << "\n";
            cap.release();
            return false;
        }
    }

    std::cerr << "Camera ready: index " << cameraIndex << " via " << apiName << "\n";
    return true;
}

// Scored camera candidate used by PickBestCamera to rank all usable devices.
struct CameraCandidate {
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

// Higher score = better camera. Favours resolution, DShow backend, and preferred index.
double ScoreCandidate(int index, int w, int h, int preferredIndex, bool backendDshow) {
    double score = 0.0;
    score += (double)w * (double)h / 1000.0;
    if (w >= 1900 && h >= 1000) score += 5000.0;
    if (backendDshow) score += 500.0;
    if (index == preferredIndex) score += 200.0;
    return score;
}

// Enumerate, probe, score, and select the best available camera.
bool PickBestCamera(cv::VideoCapture& cap, cv::Mat& frame) {
    const auto names = EnumerateVideoDeviceNamesDShow();
    const int preferredByName = names.empty() ? -1 : ChooseCameraIndexFromNames(names, true);
    const auto cameraPriority = BuildCameraPriorityList(names, preferredByName);
    const int preferredIndexHint = preferredByName >= 0 ? preferredByName
                                                         : (cameraPriority.empty() ? -1 : cameraPriority.front());
    int forcedIndex = -1;
    const bool hasForcedIndex = TryGetEnvIndex("TESS_CAMERA_INDEX", forcedIndex);
    const bool allowVirtualFallback = EnvFlagEnabled("TESS_ALLOW_VIRTUAL_CAMERA");
    const bool allowObsCamera = EnvFlagEnabled("TESS_ALLOW_OBS_CAMERA");
    const bool quickCameraSelect = !EnvFlagEnabled("TESS_DISABLE_CAMERA_QUICK_SELECT");

    struct BackendTry { int api; const char* name; };
    const std::vector<BackendTry> backendOrder = {
        {cv::CAP_DSHOW, "DSHOW"},
    };

    std::vector<CameraCandidate> candidates;
    CameraCandidate chosen;
    bool chooseOk = false;
    bool cameraOpenForChosen = false;
    bool quickCameraHit = false;

    for (int idx : cameraPriority) {
        for (const auto& be : backendOrder) {
            if (!TryOpenCamera(cap, idx, be.api, be.name, frame, true))
                continue;

            const int w = (int)cap.get(cv::CAP_PROP_FRAME_WIDTH);
            const int h = (int)cap.get(cv::CAP_PROP_FRAME_HEIGHT);
            const bool isDshow = be.api == cv::CAP_DSHOW;
            const double score = ScoreCandidate(idx, w, h, preferredIndexHint, isDshow);

            std::cerr << "Candidate camera: index " << idx << " via " << be.name
                      << " @" << w << "x" << h << " score=" << score << "\n";

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
            const bool quickPreferredHit = !hasForcedIndex && preferredByName >= 0 && idx == preferredByName;
            if (quickCameraSelect && (quickForcedHit || quickPreferredHit)) {
                chosen = cand;
                chooseOk = true;
                cameraOpenForChosen = true;
                quickCameraHit = true;
                std::cerr << "Quick camera select: index " << idx
                          << " via " << be.name << "\n";
                break;
            }

            cap.release();
            frame.release();
        }
        if (quickCameraHit) break;
    }

    if (candidates.empty()) {
        std::cerr << "Could not open webcam\n";
        return false;
    }

    auto chooseBest = [&](auto predicate) {
        bool found = false;
        CameraCandidate bestLocal;
        for (const auto& c : candidates) {
            if (!predicate(c)) continue;
            if (!found || c.score > bestLocal.score) {
                bestLocal = c;
                found = true;
            }
        }
        if (found) chosen = bestLocal;
        return found;
    };

    // Selection cascade: forced env > preferred name > physical > unknown > virtual.
    if (!chooseOk) {
        if (hasForcedIndex) {
            chooseOk = chooseBest([&](const CameraCandidate& c) {
                return c.index == forcedIndex;
            });
            if (!chooseOk) {
                std::cerr << "Forced camera index TESS_CAMERA_INDEX=" << forcedIndex
                          << " was not available.\n";
            }
        } else {
            chooseOk = chooseBest([&](const CameraCandidate& c) {
                return c.preferredByName;
            });
            if (!chooseOk) {
                chooseOk = chooseBest([&](const CameraCandidate& c) {
                    return c.knownByName && !c.virtualByName;
                });
            }
            if (!chooseOk) {
                chooseOk = chooseBest([&](const CameraCandidate& c) {
                    return !c.knownByName;
                });
            }
            if (!chooseOk && allowVirtualFallback) {
                chooseOk = chooseBest([&](const CameraCandidate& c) {
                    if (!c.virtualByName) return false;
                    if (!c.knownByName) return false;
                    if (IsObsCameraName(names[c.index]) && !allowObsCamera) return false;
                    return true;
                });
            }
        }
    }

    if (!chooseOk) {
        std::cerr << "No usable camera found.\n"
                  << "Close/disable Camo and OBS Virtual Camera, then retry.\n"
                  << "Set TESS_ALLOW_VIRTUAL_CAMERA=1 for virtual fallback.\n"
                  << "Set TESS_ALLOW_OBS_CAMERA=1 to allow OBS.\n";
        return false;
    }

    // Re-open the chosen camera if it was released during scoring.
    if (!cameraOpenForChosen &&
        !TryOpenCamera(cap, chosen.index, chosen.api, chosen.backend, frame, true)) {
        std::cerr << "Selected camera could not be reopened for capture.\n";
        return false;
    }

    std::cerr << "Using camera index " << chosen.index << " via " << chosen.backend
              << " @" << chosen.width << "x" << chosen.height;
    if (chosen.knownByName) {
        std::wcerr << L" name=\"" << names[chosen.index] << L"\"";
    }
    std::cerr << "\n";
    return true;
}

} // namespace

sage::secure_string<> sage::captureQrFromWebcam() {
    sage::secure_string<> result;

    // Constrain process memory while OpenCV is active.
    CaptureJobGuard jobGuard(kCaptureMemoryLimitBytes);

    // Avoid a common MSMF startup failure mode on some UVC webcams.
    _putenv("OPENCV_VIDEOIO_MSMF_ENABLE_HW_TRANSFORMS=0");

    cv::VideoCapture cap;
    cv::Mat frame;

    if (!PickBestCamera(cap, frame)) {
        return result;
    }

    // Camera warmup - display live video while auto-exposure settles.
    const int cameraWarmupMs = EnvIntOrDefault("TESS_CAMERA_WARMUP_MS", 250, 0, 5000);
    if (cameraWarmupMs > 0) {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(cameraWarmupMs)) {
            cap >> frame;
            if (frame.empty()) break;
            cv::imshow("webcam", frame);
            int key = cv::waitKey(1);
            if (key == 27) {
                cv::destroyAllWindows();
                return result;
            }
        }
    }

    // Auto-focus the webcam window so the user can press ESC immediately.
    {
        HWND hwnd = FindWindowA(nullptr, "webcam");
        if (hwnd) {
            SetForegroundWindow(hwnd);
            SetFocus(hwnd);
        }
    }

    std::cerr << "QR scanner ready. Point webcam at a QR code.\n";

    // QR decode loop
    cv::QRCodeDetector qrDetector;
    const auto captureStart = std::chrono::steady_clock::now();
    const int captureTimeoutSec = EnvIntOrDefault(
        "TESS_CAPTURE_TIMEOUT_SEC", kDefaultCaptureTimeoutSec, 5, 300);

    while (true) {
        // Enforce capture timeout.
        {
            auto elapsed = std::chrono::steady_clock::now() - captureStart;
            if (elapsed > std::chrono::seconds(captureTimeoutSec)) {
                std::cerr << "QR capture timed out after " << captureTimeoutSec << "s\n";
                break;
            }
        }

        // Flush stale queued frames so we always process the latest one.
        for (int i = 0; i < 2; ++i) cap.grab();
        if (!cap.read(frame) || frame.empty()) break;

        // Reject oversized frames from malicious virtual-camera drivers.
        if (frame.cols > kMaxFrameDimension || frame.rows > kMaxFrameDimension) {
            std::cerr << "Frame " << frame.cols << "x" << frame.rows
                      << " exceeds " << kMaxFrameDimension << "px limit, skipping\n";
            continue;
        }

        // Downscale + grayscale for fast detection.
        cv::Mat gray;
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
        const double scale = std::min(1.0, 480.0 / gray.cols);
        if (scale < 1.0)
            cv::resize(gray, gray, cv::Size(), scale, scale, cv::INTER_AREA);

        // Try normal, then inverted (white-on-black QR codes).
        std::vector<cv::Point> points;
        std::string data = qrDetector.detectAndDecode(gray, points);
        if (data.empty()) {
            cv::bitwise_not(gray, gray);
            points.clear();
            data = qrDetector.detectAndDecode(gray, points);
        }

        // Move decoded text into locked secure memory, wipe the pageable std::string.
        if (!data.empty()) {
            // Reject anomalously large payloads (QR v40 max is ~4296 bytes).
            if (data.size() > kMaxQrDataBytes) {
                std::cerr << "QR data (" << data.size()
                          << " bytes) exceeds " << kMaxQrDataBytes << "B limit, rejected\n";
                SecureZeroMemory(data.data(), data.size());
                continue;
            }
            result.s.assign(data.begin(), data.end());
            SecureZeroMemory(data.data(), data.size());
            break;
        }

        cv::imshow("webcam", frame);
        if (cv::waitKey(1) == 27) break;  // ESC = cancel
    }

    cap.release();
    cv::destroyAllWindows();

    return result;
}
