#pragma once

/**
 * @brief Validate the native-messaging origin before opening a bridge pipe.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Origin strings are caller-controlled and do not authenticate a launch.
 * Gecko origins support manual manifests; the installer supplies none.
 */

namespace seal::browser_host
{

/**
 * @fn bool isLegitimateLaunchOrigin()
 * @brief Accept the pinned chrome origin or a moz-extension scheme prefix.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Gecko uses a per-install UUID. Browser ancestry checks still apply.
 */
bool isLegitimateLaunchOrigin();

}  // namespace seal::browser_host
