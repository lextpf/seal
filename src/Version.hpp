#pragma once

/// Major version number.
#define SEAL_VERSION_MAJOR 1
/// Minor version number.
#define SEAL_VERSION_MINOR 0
/// Patch version number.
#define SEAL_VERSION_PATCH 0
/// Release version number.
#define SEAL_VERSION_RELEASE 0

/**
 * @brief Stringify version components into a `"major.minor.patch.release"` literal.
 *
 * Uses the preprocessor stringification operator (`#`) to convert
 * numeric macro arguments into a dot-separated version string at
 * compile time. Not intended to be called directly; use SEAL_VERSION instead.
 *
 * @param major Major version.
 * @param minor Minor version.
 * @param patch Patch version.
 * @param release Release version.
 *
 * @see SEAL_VERSION
 */
#define SEAL_VERSION_STRINGIFY_IMPL(major, minor, patch, release) \
    #major "." #minor "." #patch "." #release
#define SEAL_VERSION_STRINGIFY(major, minor, patch, release) \
    SEAL_VERSION_STRINGIFY_IMPL(major, minor, patch, release)

/// Complete version string (e.g., "1.0.0.0").
#define SEAL_VERSION        \
    SEAL_VERSION_STRINGIFY( \
        SEAL_VERSION_MAJOR, SEAL_VERSION_MINOR, SEAL_VERSION_PATCH, SEAL_VERSION_RELEASE)
