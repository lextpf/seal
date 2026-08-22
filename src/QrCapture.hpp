#pragma once
#include "CancellationToken.hpp"
#include "Cryptography.hpp"

namespace seal
{

/**
 * @brief Launch the webcam and scan for a QR code, with cooperative cancellation.
 * @author Alex (https://github.com/lextpf)
 * @ingroup QrCapture
 *
 * The decoded text is returned in locked, guard-paged memory (`seal::secure_string`). The whole
 * capture runs inline: the call selects and opens a camera, shows an OpenCV highgui window titled
 * `webcam`, and returns on decode, timeout, Escape, cancellation or camera failure. The camera is
 * released and every window it opened is destroyed before it returns.
 *
 * An oversized frame or an oversized payload skips that iteration only; the loop keeps scanning
 * until an exit condition holds.
 *
 * ## :material-camera: Capture flow
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
 * PickBestCamera() selects the DirectShow device by priority scoring, a live preview window opens
 * while auto-exposure settles, and Escape cancels at any point. `SEAL_CAMERA_INDEX` forces one
 * camera index instead of auto-selection; CameraSelector.hpp documents the rest of the camera
 * environment variables.
 *
 * ## :material-shield-lock: Security measures
 *
 * The numeric limits behind these guards are in the table further down.
 *
 * - **Job Object sandbox** - caps process memory while OpenCV is active, which stops a heap spray
 *   or a decompression bomb.
 * - **Frame validation** - an oversized frame is rejected so it cannot overflow an imgproc buffer.
 * - **Payload cap** - the limit sits just below the QR v40 binary-mode maximum of ~4296 bytes, so
 *   a larger payload is anomalous.
 * - **Timeout** - the detection loop auto-cancels rather than holding the camera.
 *
 * The build does not reduce OpenCV. This file calls only core, imgproc, objdetect, videoio and
 * highgui, but CMakeLists.txt links `${OpenCV_LIBS}` whole, and vcpkg installs opencv4 with its
 * default features, so imgcodecs, dnn and the jpeg/png/tiff/webp codecs are linked in as well.
 *
 * @par Security caps
 * | Guard                 | Source                     | Value                        |
 * |-----------------------|----------------------------|------------------------------|
 * | Process memory cap    | `kCaptureMemoryLimitBytes` | 1 GiB (`1ULL << 30`)         |
 * | Max frame dimension   | `kMaxFrameDimension`       | 3840 px (width or height)    |
 * | Max decoded payload   | `kMaxQrDataBytes`          | 4096 bytes                   |
 * | Detection timeout     | `SEAL_CAPTURE_TIMEOUT_SEC` | 60 s default, clamp 5-300    |
 * | Auto-exposure warm-up | `SEAL_CAMERA_WARMUP_MS`    | 250 ms default, clamp 0-5000 |
 *
 * @par Plaintext exposure window
 * The decoded text lives in a pageable OpenCV `std::string` for exactly one copy before it reaches
 * locked pages and the pageable copy is wiped:
 * @verbatim
 * webcam frame (BGR cv::Mat, pageable)
 *      | cvtColor BGR->GRAY, resize to <= 480 px wide
 *      v
 * grayscale cv::Mat
 *      | QRCodeDetector::detectAndDecode (retried once on inverted image)
 *      v
 * std::string data   <-- pageable plaintext: the one unlocked window
 *      | result.assign(begin, end)   copy into locked, guard-paged storage
 *      v
 * secure_string<> result
 *      | SecureZeroMemory(data)      wipe the pageable copy
 *      v
 * returned secret
 * @endverbatim
 *
 * @par Cancellation
 * Polling starts at the warm-up loop: @p token is read once per warm-up iteration and once per
 * detection iteration, so the caller can cancel through `AsyncHandle::cancel()` instead of the
 * Escape key. PickBestCamera() takes no token, so a cancel raised while cameras are enumerated,
 * probed and opened is not observed until that phase ends; CameraSelector.hpp documents that phase
 * as possibly several seconds. The default token is never cancelled, which makes a no-arg call a
 * plain blocking capture.
 *
 * @par Threading
 * The call blocks for the camera probe, then the warm-up, then up to the configured detection
 * timeout, so run it off the GUI thread (see AsyncRunner).
 *
 * @param token Cancellation token read once per warm-up iteration and once per detection
 *              iteration. Camera selection runs before the first read.
 * @return Decoded QR text in a secure string. Empty when no QR code is detected before the
 *         timeout, when the user presses Escape, when the token is cancelled, or when camera
 *         initialisation fails.
 *
 * @note Not reentrant. Only the first concurrent call installs the 1 GiB Job Object cap; a
 *       second runs uncapped, and both compete for the same camera and window.
 *
 * @see seal::PickBestCamera, seal::EnvIntOrDefault, seal::CancellationToken
 */
secure_string<> captureQrFromWebcam(CancellationToken token = {});

}  // namespace seal
