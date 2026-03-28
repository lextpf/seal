#pragma once
#include "Cryptography.h"

namespace seal
{

/**
 * @brief Webcam QR code capture with secure memory handling.
 * @author Alex (https://github.com/lextpf)
 * @ingroup QrCapture
 *
 * Provides a single entry point for scanning a QR code from a webcam
 * and returning the decoded text directly in locked, guard-paged memory
 * (`seal::secure_string`).
 *
 * ## :material-camera: Capture Flow
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * flowchart LR
 *     Enum["Enumerate\ncameras"] --> Probe["Probe &\nscore"]
 *     Probe --> Select["Select\nbest"]
 *     Select --> Warmup["Warmup\n(auto-exposure)"]
 *     Warmup --> Detect{"QR\ndetected?"}
 *     Detect -->|yes| Copy["Secure copy\n& wipe"]
 *     Detect -->|no / Esc| Cancel["Cancel"]
 * ```
 *
 * 1. A DirectShow camera is selected via priority scoring.
 * 2. A live preview window opens while auto-exposure settles.
 * 3. `cv::QRCodeDetector` scans each frame (grayscale + downscale).
 * 4. On first decode the text is moved into `secure_string` and the
 *    OpenCV `std::string` is wiped with `SecureZeroMemory`.
 * 5. The user can press Escape to cancel at any point.
 *
 * ## :material-shield-lock: Security Measures
 *
 * - **Job Object sandbox** - process memory is capped at 1 GiB while
 *   OpenCV is active, preventing heap-spray / decompression bombs.
 * - **Frame validation** - frames exceeding 3840 px are rejected to
 *   block oversized-frame buffer overflow attacks.
 * - **Payload cap** - decoded QR data larger than 4 KiB is rejected.
 *   This is just below the QR v40 binary-mode maximum (~4296 bytes).
 * - **Timeout** - the detection loop auto-cancels after 60s
 *   (configurable via `SEAL_CAPTURE_TIMEOUT_SEC`, range 5-300s).
 * - **Minimal OpenCV build** - only core, imgproc, objdetect, videoio,
 *   and highgui modules are linked; codec libraries are stripped due to CVEs.
 *
 * ## :material-alert-circle: Residual Exposure
 *
 * OpenCV's `detectAndDecode()` unavoidably returns a heap-allocated
 * `std::string` in pageable memory.  This is the only window where
 * the plaintext sits outside locked pages; it is wiped immediately
 * after copying into the `secure_string`.
 *
 * Configurable via environment variables:
 * - `SEAL_CAMERA_WARMUP_MS` - auto-exposure warm-up period (default: 250 ms, range 0-5000)
 * - `SEAL_CAPTURE_TIMEOUT_SEC` - detection loop timeout (default: 60 s, range 5-300)
 * - `SEAL_CAMERA_INDEX` - force a specific camera index instead of auto-selection
 */

/**
 * @brief Launch the webcam and scan for a QR code.
 * @return Decoded QR text in a secure string. Returns an empty string
 *         if no QR code is detected before timeout, the user presses
 *         Escape, or camera initialization fails.
 */
secure_string<> captureQrFromWebcam();

}  // namespace seal
