#pragma once
#include "CancellationToken.hpp"
#include "Cryptography.hpp"

namespace seal
{

/**
 * @fn secure_string<> captureQrFromWebcam(CancellationToken token = {})
 * @brief Scan webcam QR text into locked memory with cooperative cancellation.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup QrCapture
 *
 * Blocks through camera selection, warm-up and detection; run off the GUI thread.
 * Opens a `webcam` preview and releases the camera and windows before returning.
 * Oversized detection frames or payloads skip that iteration. The detection timeout
 * starts after camera selection and warm-up; it does not bound the entire call.
 *
 * ### :material-camera: Capture flow
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
 *     Detect -->|no| Detect
 *     Detect -->|Esc / timeout / cancellation| Cancel["Cancel"]
 * ```
 *
 * ### :material-shield-lock: Limits
 *
 * | Limit              | Setting or constant        | Value                        |
 * |--------------------|----------------------------|------------------------------|
 * | Process memory     | `kCaptureMemoryLimitBytes` | 1 GiB                        |
 * | Frame width/height | `kMaxFrameDimension`       | 3840 px                      |
 * | Decoded payload    | `kMaxQrDataBytes`          | 4096 bytes                   |
 * | Detection timeout  | `SEAL_CAPTURE_TIMEOUT_SEC` | 60 s default; clamp 5-300    |
 * | Camera warm-up     | `SEAL_CAMERA_WARMUP_MS`    | 250 ms default; clamp 0-5000 |
 *
 * The Job Object attempts a process memory cap; capture continues if setup fails.
 * Only the first concurrent call attempts the cap. Payload size is checked after
 * OpenCV decodes it, so that check does not bound the decoder's temporary allocations.
 *
 * @verbatim
 * webcam frame (BGR cv::Mat, pageable)
 *      | cvtColor BGR->GRAY, resize to <= 480 px wide
 *      v
 * grayscale cv::Mat
 *      | QRCodeDetector::detectAndDecode (retried once on inverted image)
 *      v
 * std::string data   <-- pageable decoded text; OpenCV also owns frame buffers
 *      | result.assign(begin, end)   copy into locked, guard-paged storage
 *      v
 * secure_string<> result
 *      | SecureZeroMemory(data)      wipe the pageable copy
 *      v
 * returned secret
 * @endverbatim
 *
 * @param token Polled per warm-up and detection iteration. Camera selection can
 *              take seconds and does not observe cancellation. In-progress driver
 *              and decoder calls are not interrupted.
 * @return Decoded text; empty on timeout, Escape, cancellation or camera failure.
 * @note Not reentrant: concurrent calls also compete for the camera and preview.
 * @see seal::PickBestCamera
 */
secure_string<> captureQrFromWebcam(CancellationToken token = {});

}  // namespace seal
