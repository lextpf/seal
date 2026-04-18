#include "QrCapture.h"

#include "CameraSelector.h"
#include "ConsoleStyle.h"
#include "Diagnostics.h"
#include "Logging.h"

#include <QtCore/QString>

#include <opencv2/core.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/objdetect.hpp>
#include <opencv2/videoio.hpp>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

namespace
{
// Route diagnostics through the Qt logging system so they inherit the
// unified `[ts] [LVL] [seal.qr] [tid=N]` prefix from sealMessageHandler.
// Tone maps to Qt severity: Debug→qCDebug, Info/Step/Success→qCInfo,
// Warning→qCWarning, Error→qCCritical.
void writeQrDiag(seal::console::Tone tone, std::initializer_list<std::string> fields)
{
    const QString line = QString::fromStdString(seal::diag::joinFields(fields));
    switch (tone)
    {
        case seal::console::Tone::Debug:
        case seal::console::Tone::Plain:
            qCDebug(logQr).noquote() << line;
            break;
        case seal::console::Tone::Warning:
            qCWarning(logQr).noquote() << line;
            break;
        case seal::console::Tone::Error:
            qCCritical(logQr).noquote() << line;
            break;
        case seal::console::Tone::Info:
        case seal::console::Tone::Step:
        case seal::console::Tone::Success:
        case seal::console::Tone::Summary:
        case seal::console::Tone::Banner:
        default:
            qCInfo(logQr).noquote() << line;
            break;
    }
}

// Maximum time the QR detection loop can run before auto-cancelling.
constexpr int kDefaultCaptureTimeoutSec = 60;

// Reject oversized frames that could trigger buffer overflows in imgproc.
constexpr int kMaxFrameDimension = 3840;

// QR v40 max is ~4296 bytes; anything larger is anomalous.
constexpr size_t kMaxQrDataBytes = 4096;

// 1 GiB process memory cap to block heap-spray / decompression bombs.
constexpr SIZE_T kCaptureMemoryLimitBytes = 1ULL << 30;

// Ensures at most one CaptureJobGuard is active process-wide. Without this,
// a second guard's destructor would clear the memory limit while the first
// capture is still running, silently disabling the sandbox.
std::atomic<bool> g_CaptureJobActive{false};

// RAII Job Object that caps process memory at a fixed limit while OpenCV is active.
// OpenCV may decode arbitrary camera frames; a malicious virtual-camera driver or
// a decompression bomb could trigger unbounded allocations. The Job Object enforces
// a hard 1 GiB ceiling. The destructor clears the limit so the rest of the process
// (UI, vault ops) runs unconstrained.
struct CaptureJobGuard
{
    HANDLE hJob = nullptr;
    bool m_Owns = false;  // true only if this instance acquired the exclusive flag

    explicit CaptureJobGuard(SIZE_T memoryLimitBytes)
    {
        // Enforce single-instance: if another guard is active, skip setup.
        bool expected = false;
        if (!g_CaptureJobActive.compare_exchange_strong(expected, true))
            return;
        m_Owns = true;

        hJob = CreateJobObjectW(nullptr, nullptr);
        if (!hJob)
            return;

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = memoryLimitBytes;

        if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &info, sizeof(info)))
        {
            CloseHandle(hJob);
            hJob = nullptr;
            return;
        }

        if (!AssignProcessToJobObject(hJob, GetCurrentProcess()))
        {
            // Non-fatal: pre-Win10 non-nestable Job or access denied.
            CloseHandle(hJob);
            hJob = nullptr;
        }
    }

    ~CaptureJobGuard()
    {
        if (hJob)
        {
            // Lift the memory cap so the rest of seal runs unconstrained.
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = {};
            (void)SetInformationJobObject(
                hJob, JobObjectExtendedLimitInformation, &info, sizeof(info));
            CloseHandle(hJob);
        }
        if (m_Owns)
            g_CaptureJobActive.store(false);
    }

    CaptureJobGuard(const CaptureJobGuard&) = delete;
    CaptureJobGuard& operator=(const CaptureJobGuard&) = delete;
};

}  // namespace

seal::secure_string<> seal::captureQrFromWebcam()
{
    seal::secure_string<> result;

    // Constrain process memory while OpenCV is active.
    CaptureJobGuard jobGuard(kCaptureMemoryLimitBytes);

    // OPENCV_VIDEOIO_MSMF_ENABLE_HW_TRANSFORMS is set once during
    // process init (main.cpp) to avoid a data race between this
    // worker thread's getenv calls and the GUI thread.

    cv::VideoCapture cap;
    cv::Mat frame;

    if (!seal::PickBestCamera(cap, frame))
    {
        return result;
    }

    // Camera warmup: display live video for a short period so the sensor's
    // auto-exposure and auto-white-balance converge. Without this, the first
    // frames are often too dark or washed out for reliable QR detection.
    const int cameraWarmupMs = seal::EnvIntOrDefault("SEAL_CAMERA_WARMUP_MS", 250, 0, 5000);
    if (cameraWarmupMs > 0)
    {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(cameraWarmupMs))
        {
            cap >> frame;
            if (frame.empty())
                break;
            cv::imshow("webcam", frame);
            int key = cv::waitKey(1);
            if (key == 27)
            {
                cv::destroyAllWindows();
                return result;
            }
        }
    }

    // Auto-focus the webcam window so the user can press ESC immediately.
    {
        HWND hwnd = FindWindowA(nullptr, "webcam");
        if (hwnd)
        {
            SetForegroundWindow(hwnd);
            SetFocus(hwnd);
        }
    }

    writeQrDiag(seal::console::Tone::Info, {"event=qr.capture.ready", "result=ok"});

    // QR decode loop
    cv::QRCodeDetector qrDetector;
    const auto captureStart = std::chrono::steady_clock::now();
    const int captureTimeoutSec =
        seal::EnvIntOrDefault("SEAL_CAPTURE_TIMEOUT_SEC", kDefaultCaptureTimeoutSec, 5, 300);

    while (true)
    {
        // Enforce capture timeout.
        {
            auto elapsed = std::chrono::steady_clock::now() - captureStart;
            if (elapsed > std::chrono::seconds(captureTimeoutSec))
            {
                writeQrDiag(seal::console::Tone::Warning,
                            {"event=qr.capture.finish",
                             "result=fail",
                             "reason=timeout",
                             seal::diag::kv("timeout_s", captureTimeoutSec)});
                break;
            }
        }

        // Flush 2 stale frames from the driver's internal queue. VideoCapture
        // buffers frames; without this, cap.read() returns an old frame and QR
        // detection lags behind the live camera view by several hundred ms.
        for (int i = 0; i < 2; ++i)
            cap.grab();
        if (!cap.read(frame) || frame.empty())
            break;

        // Reject oversized frames from malicious virtual-camera drivers.
        if (frame.cols > kMaxFrameDimension || frame.rows > kMaxFrameDimension)
        {
            writeQrDiag(seal::console::Tone::Warning,
                        {"event=qr.frame.skip",
                         "result=skip",
                         "reason=frame_too_large",
                         seal::diag::kv("width", frame.cols),
                         seal::diag::kv("height", frame.rows),
                         seal::diag::kv("limit_px", kMaxFrameDimension)});
            continue;
        }

        // Convert to grayscale and downscale to 480px wide for fast QR detection.
        // QR finder patterns are high-contrast; colour info adds no value but doubles
        // the pixel count. Downscaling further cuts detection time ~4x on 1080p frames.
        cv::Mat gray;
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
        const double scale = std::min(1.0, 480.0 / gray.cols);
        if (scale < 1.0)
            cv::resize(gray, gray, cv::Size(), scale, scale, cv::INTER_AREA);

        // Try standard (dark-on-light) QR first, then invert and retry.
        // Inverted QR codes (white modules on black background) are used by
        // some generators; bitwise_not flips them to the standard polarity.
        std::vector<cv::Point> points;
        std::string data = qrDetector.detectAndDecode(gray, points);
        if (data.empty())
        {
            cv::bitwise_not(gray, gray);
            points.clear();
            data = qrDetector.detectAndDecode(gray, points);
        }

        // Move decoded text into locked secure memory, then wipe the pageable
        // std::string so the credential doesn't linger on a swappable heap page.
        if (!data.empty())
        {
            // Reject anomalously large payloads. QR v40 max is ~4296 bytes;
            // anything bigger likely comes from a crafted virtual-camera frame.
            if (data.size() > kMaxQrDataBytes)
            {
                writeQrDiag(seal::console::Tone::Warning,
                            {"event=qr.decode.skip",
                             "result=skip",
                             "reason=payload_too_large",
                             seal::diag::kv("payload_len", data.size()),
                             seal::diag::kv("limit_bytes", kMaxQrDataBytes)});
                SecureZeroMemory(data.data(), data.size());
                continue;
            }
            result.s.assign(data.begin(), data.end());
            writeQrDiag(seal::console::Tone::Success,
                        {"event=qr.decode.finish",
                         "result=ok",
                         seal::diag::kv("payload_len", result.size())});
            SecureZeroMemory(data.data(), data.size());
            break;
        }

        cv::imshow("webcam", frame);
        if (cv::waitKey(1) == 27)
            break;  // ESC = cancel
    }

    cap.release();
    cv::destroyAllWindows();

    return result;
}
