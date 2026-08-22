#pragma once

/**
 * @brief Compile-time version numbers and the printable version string.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * The four numeric macros are the single source of the version that
 * `seal -v` / `seal --version` prints and that opens the `seal --help` banner.
 *
 * @warning Keep the first three in step with `project(seal VERSION ...)` in
 * CMakeLists.txt by hand; nothing checks the two against each other.
 */

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
 * `#` stops further expansion of its operand, so reach this inner macro only
 * through SEAL_VERSION_STRINGIFY. Calling it with a macro name stringifies the
 * name itself.
 *
 * @see SEAL_VERSION
 */
#define SEAL_VERSION_STRINGIFY_IMPL(major, minor, patch, release) \
    #major "." #minor "." #patch "." #release
/// Expands its arguments once, then stringifies them via
/// SEAL_VERSION_STRINGIFY_IMPL.
#define SEAL_VERSION_STRINGIFY(major, minor, patch, release) \
    SEAL_VERSION_STRINGIFY_IMPL(major, minor, patch, release)

/// Complete version string (e.g., "1.0.0.0").
#define SEAL_VERSION        \
    SEAL_VERSION_STRINGIFY( \
        SEAL_VERSION_MAJOR, SEAL_VERSION_MINOR, SEAL_VERSION_PATCH, SEAL_VERSION_RELEASE)
