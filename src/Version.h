#pragma once

/// Major version number.
#define SEAL_VERSION_MAJOR 0
/// Minor version number.
#define SEAL_VERSION_MINOR 1
/// Patch version number.
#define SEAL_VERSION_PATCH 0
/// Release version number.
#define SEAL_VERSION_RELEASE 0

/**
 * Stringify version components.
 *
 * @param major Major version.
 * @param minor Minor version.
 * @param patch Patch version.
 * @param release Release version.
 *
 * @see SEAL_VERSION
 */
#define SEAL_VERSION_STRINGIFY(major, minor, patch, release) \
    #major "." #minor "." #patch "." #release

/// Complete version string (e.g., "0.1.0.0").
#define SEAL_VERSION        \
    SEAL_VERSION_STRINGIFY( \
        SEAL_VERSION_MAJOR, SEAL_VERSION_MINOR, SEAL_VERSION_PATCH, SEAL_VERSION_RELEASE)
