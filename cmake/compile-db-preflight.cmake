# Require the main dynamic installation and matching source and toolchain paths.
# Reject dependency installation and feature selection before the toolchain runs.
if(VCPKG_MANIFEST_INSTALL OR VCPKG_MANIFEST_FEATURES)
    message(FATAL_ERROR "The compile-db sidecar requires VCPKG_MANIFEST_INSTALL=OFF, "
        "and an empty VCPKG_MANIFEST_FEATURES value.")
endif()

set(_seal_main_cache "${CMAKE_SOURCE_DIR}/build/CMakeCache.txt")
string(CONCAT _seal_sidecar_help "Run build.bat for the dynamic application configuration first. "
    "Keep static builds separate; do not configure compile-db against a static installation.")
if(NOT EXISTS "${_seal_main_cache}")
    message(FATAL_ERROR "Missing main build cache: ${_seal_main_cache}. ${_seal_sidecar_help}")
endif()

foreach(_seal_key IN ITEMS VCPKG_TARGET_TRIPLET VCPKG_HOST_TRIPLET VCPKG_INSTALLED_DIR
        CMAKE_HOME_DIRECTORY CMAKE_TOOLCHAIN_FILE)
    file(STRINGS "${_seal_main_cache}" _seal_matches REGEX "^${_seal_key}:[^=]*=")
    list(LENGTH _seal_matches _seal_count)
    if(NOT _seal_count EQUAL 1)
        message(FATAL_ERROR "Missing or ambiguous ${_seal_key} in ${_seal_main_cache}. "
            "${_seal_sidecar_help}")
    endif()
    string(REGEX REPLACE "^[^=]*=" "" "_seal_main_${_seal_key}" "${_seal_matches}")
endforeach()

foreach(_seal_key IN ITEMS VCPKG_TARGET_TRIPLET VCPKG_HOST_TRIPLET)
    if(NOT "${${_seal_key}}" STREQUAL "x64-windows-release-msvc143"
            OR NOT "${_seal_main_${_seal_key}}" STREQUAL "${${_seal_key}}")
        message(FATAL_ERROR "compile-db ${_seal_key} does not match the main dynamic build. "
            "${_seal_sidecar_help}")
    endif()
endforeach()

foreach(_seal_pair IN ITEMS VCPKG_INSTALLED_DIR CMAKE_TOOLCHAIN_FILE)
    file(REAL_PATH "${${_seal_pair}}" _seal_sidecar_path)
    file(REAL_PATH "${_seal_main_${_seal_pair}}" _seal_main_path)
    string(TOLOWER "${_seal_sidecar_path}" _seal_sidecar_path)
    string(TOLOWER "${_seal_main_path}" _seal_main_path)
    if(NOT _seal_sidecar_path STREQUAL _seal_main_path)
        message(FATAL_ERROR "compile-db ${_seal_pair} differs from the main build. "
            "${_seal_sidecar_help}")
    endif()
endforeach()

file(REAL_PATH "${CMAKE_SOURCE_DIR}" _seal_source)
file(REAL_PATH "${_seal_main_CMAKE_HOME_DIRECTORY}" _seal_main_source)
string(TOLOWER "${_seal_source}" _seal_source)
string(TOLOWER "${_seal_main_source}" _seal_main_source)
if(NOT _seal_source STREQUAL _seal_main_source)
    message(FATAL_ERROR "The main build cache belongs to another source directory. "
        "${_seal_sidecar_help}")
endif()

if(NOT EXISTS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/share/Qt6/Qt6Config.cmake"
        OR NOT IS_DIRECTORY "${VCPKG_INSTALLED_DIR}/${VCPKG_HOST_TRIPLET}/tools/Qt6/bin")
    message(FATAL_ERROR "The main dynamic Qt installation is incomplete. ${_seal_sidecar_help}")
endif()
