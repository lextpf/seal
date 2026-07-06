#include "QrCapture.hpp"

#include "CameraSelector.hpp"
#include "CancellationToken.hpp"
#include "ConsoleStyle.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"

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
// Route diagnostics through Qt logging for the unified prefix.
void writeQrDiag(seal::console::Tone tone, std::initializer_list<std::string> fields)
{
    writeToneLine(logQr(), tone, fields);
}

// Maximum time the QR detection loop can run before auto-cancelling.
constexpr int kDefaultCaptureTimeoutSec = 60;

// Reject oversized frames that could trigger buffer overflows in imgproc.
constexpr int kMaxFrameDimension = 3840;

// QR v40 max is ~4296 bytes; anything larger is anomalous.
constexpr size_t kMaxQrDataBytes = 4096;

// 1 GiB process memory cap to block heap-spray / decompression bombs.
constexpr SIZE_T kCaptureMemoryLimitBytes = 1ULL << 30;

// At most one CaptureJobGuard active process-wide; otherwise a second
// destructor would clear the cap mid-capture and disable the sandbox.
std::atomic<bool> g_CaptureJobActive{false};

// RAII Job Object that caps process memory while OpenCV decodes frames.
// A malicious virtual-camera driver or decompression bomb could trigger
// unbounded allocation; the 1 GiB ceiling fail-fasts. Destructor clears
// the limit so the rest of seal runs unconstrained.
struct CaptureJobGuard
{
    HANDLE hJob = nullptr;
    bool m_Owns = false;  // true only if this instance acquired the exclusive flag

    explicit CaptureJobGuard(SIZE_T memoryLimitBytes)
    {
        // Single-instance: skip setup if another guard is active.
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

seal::secure_string<> seal::captureQrFromWebcam(seal::CancellationToken token)
{
    seal::secure_string<> result;

    // Memory cap while OpenCV is active.
    CaptureJobGuard jobGuard(kCaptureMemoryLimitBytes);

    cv::VideoCapture cap;
    cv::Mat frame;

    if (!seal::PickBestCamera(cap, frame))
    {
        return result;
    }

    const int cameraWarmupMs = seal::EnvIntOrDefault("SEAL_CAMERA_WARMUP_MS", 250, 0, 5000);
    if (cameraWarmupMs > 0)
    {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(cameraWarmupMs))
        {
            if (token.cancelled())
            {
                cv::destroyAllWindows();
                return result;
            }
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

    {
        HWND hwnd = FindWindowA(nullptr, "webcam");
        if (hwnd)
        {
            SetForegroundWindow(hwnd);
            SetFocus(hwnd);
        }
    }

    writeQrDiag(seal::console::Tone::Info, {"event=qr.capture.ready", "result=ok"});

    cv::QRCodeDetector qrDetector;
    const auto captureStart = std::chrono::steady_clock::now();
    const int captureTimeoutSec =
        seal::EnvIntOrDefault("SEAL_CAPTURE_TIMEOUT_SEC", kDefaultCaptureTimeoutSec, 5, 300);

    while (true)
    {
        // Poll cooperative cancellation token first.
        if (token.cancelled())
        {
            writeQrDiag(seal::console::Tone::Warning,
                        {"event=qr.capture.finish", "result=fail", "reason=cancelled"});
            break;
        }

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

        for (int i = 0; i < 2; ++i)
            cap.grab();
        if (!cap.read(frame) || frame.empty())
            break;

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

        cv::Mat gray;
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
        const double scale = std::min(1.0, 480.0 / gray.cols);
        if (scale < 1.0)
            cv::resize(gray, gray, cv::Size(), scale, scale, cv::INTER_AREA);

        std::vector<cv::Point> points;
        std::string data = qrDetector.detectAndDecode(gray, points);
        if (data.empty())
        {
            cv::bitwise_not(gray, gray);
            points.clear();
            data = qrDetector.detectAndDecode(gray, points);
        }

        if (!data.empty())
        {
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
            result.assign(data.begin(), data.end());
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
