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
 * Lists video devices through DirectShow (`CLSID_SystemDeviceEnum`), probes them in priority
 * order over the DirectShow backend, scores every device that delivers frames, and leaves the
 * winner open in @p cap.
 *
 * Names come from the `FriendlyName` property. A name index matches the OpenCV camera index,
 * and an unreadable name becomes an empty string to keep that mapping aligned. Enumeration
 * initialises COM on the calling thread and uninitialises it only when this call performed the
 * initialisation.
 *
 * @par Two independent stages
 * The probe order decides what is tried; the selection cascade decides what is kept. They are
 * not the same list. The stage names are the file-local helpers in the .cpp.
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
 * Score = pixels/1000, plus 5000 at 1900x1000 or larger, plus 500 for DirectShow, plus 200 for
 * the hinted index. DirectShow is the only backend in the try list, so that bonus is constant.
 *
 * @par Environment overrides
 * | Variable                           | Effect                                           |
 * |------------------------------------|--------------------------------------------------|
 * | `SEAL_CAMERA_INDEX`                | Force a specific 0..99 device index              |
 * | `SEAL_PREFERRED_CAMERA`            | Comma-separated name keywords (case-insensitive) |
 * | `SEAL_ALLOW_VIRTUAL_CAMERA`        | Permit virtual cameras as a last resort          |
 * | `SEAL_ALLOW_OBS_CAMERA`            | Permit an OBS virtual camera (with the above)    |
 * | `SEAL_DISABLE_CAMERA_QUICK_SELECT` | Skip the early-out on a forced/preferred hit     |
 *
 * A keyword matches as a substring of the lowercased device name. A flag variable is enabled
 * only by the exact values `1`, `true`, `TRUE`, `yes` or `YES`; `True` and `on` do not.
 *
 * @note Virtual-camera keywords: camo, virtual, obs, droidcam, ndi. The two flags gate the
 *       virtual class of the selection cascade only - `SEAL_ALLOW_VIRTUAL_CAMERA` enters that
 *       class, and an OBS device inside it also needs `SEAL_ALLOW_OBS_CAMERA`. A forced index
 *       or a name hit still selects the device it names, virtual or not.
 * @warning A forced `SEAL_CAMERA_INDEX` that no probe can open fails the whole call; there is
 *          no fallback to another device.
 *
 * @param[out] cap   OpenCV VideoCapture, opened on success and left released on every failure
 *                   path.
 * @param[out] frame Probe frame from the selected camera. 1920x1080 is requested first, with a
 *                   1280x720 fallback when that resolution does not stream.
 * @return `true` when a usable camera was found and opened.
 *
 * @note The call blocks while it opens and reads each candidate device, which can take
 *       seconds, and drives the camera hardware directly. Do not run it on the GUI thread,
 *       and never run two captures at once.
 */
bool PickBestCamera(cv::VideoCapture& cap, cv::Mat& frame);

/**
 * @brief Read an integer from an environment variable with range clamping.
 * @ingroup QrCapture
 *
 * The whole value must parse as one base-10 integer; a trailing character makes it malformed.
 * Only a parsed value is clamped, so @p defaultValue comes back unchanged even when it lies
 * outside the bounds. The bounds are not validated: an inverted range always returns @p maxValue.
 *
 * @param key Environment variable name, read with `std::getenv`.
 * @param defaultValue Returned when the variable is absent, empty or malformed.
 * @param minValue Inclusive lower bound applied to a parsed value.
 * @param maxValue Inclusive upper bound applied to a parsed value.
 * @return Parsed and clamped value, or @p defaultValue.
 */
int EnvIntOrDefault(const char* key, int defaultValue, int minValue, int maxValue);

}  // namespace seal
