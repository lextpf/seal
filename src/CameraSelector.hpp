#pragma once

#include <opencv2/core.hpp>
#include <opencv2/videoio.hpp>

namespace seal
{

/**
 * @fn bool PickBestCamera(cv::VideoCapture& cap, cv::Mat& frame)
 * @brief Probe DirectShow cameras and leave the selected device open.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup QrCapture
 *
 * FriendlyName indices match OpenCV indices; unreadable names keep empty slots.
 * Enumeration balances COM initialization on the calling thread.
 *
 * @verbatim
 *   EnumerateVideoDeviceNamesDShow  ->  FriendlyName per index
 *          |
 *   BuildCameraPriorityList: forced env > name hint > physical > virtual
 *          |                 (0..3 instead, when enumeration returned no device)
 *          |  TryOpenCamera + ScoreCandidate per index, DSHOW backend only
 *          v
 *   quick select: first forced / name-hinted index that opens wins, probing stops
 *          |  (disabled by SEAL_DISABLE_CAMERA_QUICK_SELECT)
 *          v
 *   selection cascade: forced env | name hint | physical | unknown | virtual (opt-in)
 *          |  highest score inside the first class that has a candidate
 *          v
 *   re-open the winner when scoring released it
 * @endverbatim
 *
 * Score = pixels/1000 + 5000 at >= 1900x1000 + 500 for DirectShow + 200 for the
 * hinted index. Only DirectShow is probed, so its bonus is constant.
 *
 * | Environment variable               | Effect                             |
 * |------------------------------------|------------------------------------|
 * | `SEAL_CAMERA_INDEX`                | Force device 0-99                  |
 * | `SEAL_PREFERRED_CAMERA`            | Comma-separated name substrings    |
 * | `SEAL_ALLOW_VIRTUAL_CAMERA`        | Allow virtual fallback             |
 * | `SEAL_ALLOW_OBS_CAMERA`            | Also allow OBS in virtual fallback |
 * | `SEAL_DISABLE_CAMERA_QUICK_SELECT` | Probe beyond first forced/name hit |
 *
 * Name matching ignores case. Flags accept exactly `1`, `true`, `TRUE`, `yes`,
 * `YES`. Virtual keywords are camo, virtual, obs, droidcam and ndi. Forced/name
 * matches bypass virtual fallback flags; an unusable forced index fails selection.
 *
 * @param[out] cap open on success, released on failure.
 * @param[out] frame selected probe frame; requests 1920x1080, then 1280x720 if needed.
 * @return True when a usable camera is open.
 * @note Blocks for device probing; run off the GUI thread and do not overlap captures.
 */
bool PickBestCamera(cv::VideoCapture& cap, cv::Mat& frame);

/**
 * @fn int EnvIntOrDefault(const char* key, int defaultValue, int minValue, int maxValue)
 * @brief Parse a complete decimal integer and clamp it to inclusive bounds.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup QrCapture
 *
 * Absent, empty or malformed input returns `defaultValue` without clamping.
 * Inverted bounds return `maxValue` for parsed input.
 */
int EnvIntOrDefault(const char* key, int defaultValue, int minValue, int maxValue);

}  // namespace seal
