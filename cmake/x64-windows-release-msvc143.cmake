set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_BUILD_TYPE release)

# MSVC 14.44 currently crashes while building Qt in this repo; pin to 14.43.
set(VCPKG_PLATFORM_TOOLSET v143)
set(VCPKG_PLATFORM_TOOLSET_VERSION 14.43)

# Avoid MSVC ICEs in Qt sources when PCH is enabled.
list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS -DBUILD_WITH_PCH=OFF)

# Keep CL's internal parallelism low to avoid compiler crashes.
set(VCPKG_C_FLAGS "/MP1")
set(VCPKG_CXX_FLAGS "/MP1")
