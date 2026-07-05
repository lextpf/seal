#pragma once

/**
 * @brief The argv[1] native-messaging launch-origin gate.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * The browser always passes the extension's origin as argv[1]
 * (`chrome-extension://<pinned-id>/` or `moz-extension://<uuid>/`); a direct
 * exec by malware never carries it. This is the cheapest gate and runs first,
 * before any pipe is touched.
 */

namespace seal::browser_host
{

/**
 * @brief Whether argv[1] is a recognised native-messaging launch origin.
 *
 * Matches the pinned Chrome extension origin exactly, or any `moz-extension://`
 * prefix (Firefox uses a per-install UUID, so the scheme is the strongest claim
 * here; the bridge still requires a signed firefox.exe parent).
 *
 * @return true iff argv[1] is a valid extension origin.
 */
bool isLegitimateLaunchOrigin();

}  // namespace seal::browser_host
