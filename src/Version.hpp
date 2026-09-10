#pragma once

/**
 * @brief version macros for CLI output.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * keep major, minor and patch values equal to CMakeLists.txt; no automatic check enforces this.
 */

#define SEAL_VERSION_MAJOR 1
#define SEAL_VERSION_MINOR 0
#define SEAL_VERSION_PATCH 0
#define SEAL_VERSION_RELEASE 0

/**
 * @brief stringify expanded version components.
 *
 * call through SEAL_VERSION_STRINGIFY so macro arguments expand before the `#` operator.
 */
#define SEAL_VERSION_STRINGIFY_IMPL(major, minor, patch, release) \
    #major "." #minor "." #patch "." #release
/// expand macro values before stringification.
#define SEAL_VERSION_STRINGIFY(major, minor, patch, release) \
    SEAL_VERSION_STRINGIFY_IMPL(major, minor, patch, release)

/// complete version string (e.g., "1.0.0.0").
#define SEAL_VERSION        \
    SEAL_VERSION_STRINGIFY( \
        SEAL_VERSION_MAJOR, SEAL_VERSION_MINOR, SEAL_VERSION_PATCH, SEAL_VERSION_RELEASE)
