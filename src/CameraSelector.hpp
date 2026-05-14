#pragma once

#include <opencv2/core.hpp>
#include <opencv2/videoio.hpp>

namespace seal
{

/**
 * @brief Enumerate, probe, score, and open the best available camera.
 * @author Alex (https://github.com/lextpf)
 * @ingroup QrCapture
 *
 * Walks DirectShow device enumeration, probes each candidate with multiple
 * backends, scores by resolution and backend reliability, and opens the
 * highest-scoring usable camera.
 *
 * Priority cascade:
 *   1. `SEAL_CAMERA_INDEX` env var (user override)
 *   2. `SEAL_PREFERRED_CAMERA` keyword match
 *   3. First non-virtual camera (skips OBS, Camo, DroidCam, etc.)
 *   4. Fallback to index 0
 *
 * @param[out] cap   OpenCV VideoCapture, opened on success.
 * @param[out] frame Probe frame from the selected camera.
 * @return `true` if a usable camera was found and opened.
 */
bool PickBestCamera(cv::VideoCapture& cap, cv::Mat& frame);

/**
 * @brief Read an integer from an environment variable with range clamping.
 * @param key          Environment variable name.
 * @param defaultValue Value returned when the variable is absent or malformed.
 * @param minValue     Lower clamp bound.
 * @param maxValue     Upper clamp bound.
 * @return Parsed and clamped value, or @p defaultValue.
 */
int EnvIntOrDefault(const char* key, int defaultValue, int minValue, int maxValue);

}  // namespace seal
