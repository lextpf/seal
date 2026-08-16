#pragma once

/**
 * @brief The argv[1] native-messaging launch-origin gate.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * The browser always passes the extension's origin as argv[1], either
 * `chrome-extension://<pinned-id>/` or `moz-extension://<uuid>/`. A direct exec by
 * malware never carries it. This is the cheapest gate, so it runs first, before any
 * pipe is touched.
 *
 * The Gecko branch is unreachable in the shipped product: `install-browser-extension`
 * writes no Gecko manifest (see `src/CliModes.cpp`), so no installed configuration can
 * launch this host with a `moz-extension://` origin. The branch exists only so a
 * hand-installed manifest is not rejected outright, which is also why its weaker
 * any-UUID match is tolerable.
 */

namespace seal::browser_host
{

/**
 * @brief Whether argv[1] is a recognised native-messaging launch origin.
 *
 * Matches the pinned Chrome extension origin exactly, or any `moz-extension://`
 * prefix. Firefox derives its origin from a per-install UUID, so the scheme is the
 * strongest claim available; the bridge still requires a signed firefox.exe parent.
 *
 * @return true iff argv[1] is a recognised extension origin.
 */
bool isLegitimateLaunchOrigin();

}  // namespace seal::browser_host
