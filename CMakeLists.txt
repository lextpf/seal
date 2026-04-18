cmake_minimum_required(VERSION 3.20)

project(seal
    VERSION 1.0.0
    DESCRIPTION "AES-256-GCM encrypt/decrypt console utility with locked memory and guard pages"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT when using a static vcpkg triplet (/MT instead of /MD).
# This eliminates the runtime dependency on vcruntime140.dll / msvcp140.dll.
if(VCPKG_TARGET_TRIPLET MATCHES "static")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(NOT WIN32)
    message(FATAL_ERROR "This project requires Windows")
endif()

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_TESTS "Enable test builds" ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(MSVC)
    add_compile_options(/W4 /WX- /permissive- /Zc:__cplusplus /EHsc)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /DNDEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /Zi /RTC1")

    # --- Security hardening flags ---
    # Control Flow Guard - prevents ROP/JOP attacks
    add_compile_options(/guard:cf)
    add_link_options(/guard:cf)

    # Spectre v1 mitigations (requires Spectre-mitigated libs from VS installer)
    option(ENABLE_SPECTRE "Enable /Qspectre mitigation (requires Spectre libs)" OFF)
    if(ENABLE_SPECTRE)
        add_compile_options(/Qspectre)
    endif()

    # CET Shadow Stack (Intel CET hardware enforcement)
    add_link_options(/CETCOMPAT)

    # High-entropy ASLR (64-bit)
    add_link_options(/HIGHENTROPYVA)

    # Explicit DEP and ASLR (usually default, but be explicit)
    add_link_options(/NXCOMPAT /DYNAMICBASE)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

# vcpkg's static Qt6 ships CMake targets for some QML style plugins
# (FluentWinUI3, NativeStyle) but omits the compiled .obj resource files
# they reference. Qt6QmlPlugins.cmake unconditionally includes every
# QmlPlugin Config file, so broken targets must be removed before
# find_package sees them. We only use the Basic style — remove all
# unused style configs to avoid present and future breakage.
if(VCPKG_TARGET_TRIPLET MATCHES "static")
    set(_vcpkg_installed "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}")

    # Remove share-level style packages we don't use (all except Basic).
    file(GLOB _unused_style_dirs
        "${_vcpkg_installed}/share/Qt6QuickControls2FluentWinUI3*"
        "${_vcpkg_installed}/share/Qt6QuickControls2NativeStyle*"
        "${_vcpkg_installed}/share/Qt6QuickControls2Fusion*"
        "${_vcpkg_installed}/share/Qt6QuickControls2Imagine*"
        "${_vcpkg_installed}/share/Qt6QuickControls2Material*"
        "${_vcpkg_installed}/share/Qt6QuickControls2Universal*"
        "${_vcpkg_installed}/share/Qt6QuickControls2Windows*"
    )
    foreach(_dir ${_unused_style_dirs})
        file(GLOB _files "${_dir}/*")
        if(_files)
            file(REMOVE ${_files})
        endif()
    endforeach()

    # Remove QML plugin configs for all unused styles (keeps only Basic).
    file(GLOB _broken_qml_plugins
        "${_vcpkg_installed}/share/Qt6Qml/QmlPlugins/*fluentwinui3*"
        "${_vcpkg_installed}/share/Qt6Qml/QmlPlugins/*nativestyle*"
        "${_vcpkg_installed}/share/Qt6Qml/QmlPlugins/*fusionstyle*"
        "${_vcpkg_installed}/share/Qt6Qml/QmlPlugins/*imaginestyle*"
        "${_vcpkg_installed}/share/Qt6Qml/QmlPlugins/*materialstyle*"
        "${_vcpkg_installed}/share/Qt6Qml/QmlPlugins/*universalstyle*"
        "${_vcpkg_installed}/share/Qt6Qml/QmlPlugins/*windowsstyle*"
    )
    if(_broken_qml_plugins)
        message(STATUS "Removing broken static QML style plugin targets (vcpkg bug)")
        file(REMOVE ${_broken_qml_plugins})
    endif()
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2 Widgets)
find_package(OpenSSL REQUIRED)

message(STATUS "Qt6 version: ${Qt6_VERSION}")
message(STATUS "OpenSSL version: ${OpenSSL_VERSION}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

if(DEFINED OpenSSL_VERSION AND NOT "${OpenSSL_VERSION}" STREQUAL "" AND OpenSSL_VERSION VERSION_LESS "3.0.0")
    message(WARNING "OpenSSL version ${OpenSSL_VERSION} found, but 3.0.0 or higher is recommended")
endif()

find_package(OpenCV REQUIRED)
message(STATUS "OpenCV version: ${OpenCV_VERSION}")

set(WINDOWS_LIBS
    Shell32
    User32
    Credui
    Ole32
    oleaut32
    Oleacc
    Advapi32
    Comdlg32
    Crypt32
    dwmapi
)

# Static OpenCV videoio (MSMF backend) requires these.
if(VCPKG_TARGET_TRIPLET MATCHES "static")
    list(APPEND WINDOWS_LIBS mf mfplat mfreadwrite mfuuid shlwapi)
endif()

set(SEAL_SOURCES
    src/main.cpp
    src/Cryptography.cpp
    src/Utils.cpp
    src/Clipboard.cpp
    src/Console.cpp
    src/ConsoleStyle.cpp
    src/Diagnostics.cpp
    src/FileOperations.cpp
    src/Backend.cpp
    src/QrCapture.cpp
    src/FillController.cpp
    src/VaultModel.cpp
    src/QmlMain.cpp
    src/Vault.cpp
    src/Logging.cpp
    src/PasswordGen.cpp
    src/WindowChrome.cpp
    src/NativeDialogs.cpp
    src/CameraSelector.cpp
    src/CliDispatch.cpp
    src/CliHandler.cpp
    src/WindowController.cpp
    src/CliModes.cpp
)

qt_standard_project_setup()
qt_policy(SET QTP0001 NEW)
qt_policy(SET QTP0004 NEW)

set_source_files_properties(qml/Theme.qml PROPERTIES
    QT_QML_SINGLETON_TYPE TRUE
)

qt_add_executable(seal
    ${SEAL_SOURCES}
)

target_include_directories(seal PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
    target_link_libraries(seal PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
else()
    target_link_libraries(seal PRIVATE
        ${OPENSSL_LIBRARIES}
    )
    if(OPENSSL_LIB_DIR)
        target_link_directories(seal PRIVATE ${OPENSSL_LIB_DIR})
    endif()
endif()

target_link_libraries(seal PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Widgets
    ${WINDOWS_LIBS}
    ${OpenCV_LIBS}
)

target_compile_definitions(seal PRIVATE
    NOMINMAX
    _WIN32_WINNT=0x0A00
    USE_QT_UI
)

file(GLOB SEAL_SVGS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} assets/svgs/*.svg)

qt_add_qml_module(seal
    URI seal
    VERSION 1.0
    RESOURCE_PREFIX /qt/qml
    QML_FILES
        qml/Theme.qml
        qml/Main.qml
        qml/HeaderBar.qml
        qml/SearchBar.qml
        qml/AccountsTable.qml
        qml/AccountRow.qml
        qml/ActionBar.qml
        qml/StatusFooter.qml
        qml/AccountDialog.qml
        qml/ConfirmDialog.qml
        qml/DialogBlobs.qml
        qml/PasswordDialog.qml
        qml/RippleEffect.qml
        qml/SvgIcon.qml
        qml/TintedButton.qml
        qml/CliPanel.qml
    RESOURCES
        "assets/fonts/b0a4eabe-5fe5-41e3-8dc3-2df2b82ec4eb.ttf"
        ${SEAL_SVGS}
)

# Static Qt6: register QML plugins at link time (qmlimportscanner runs
# automatically to determine which QML modules the app actually imports).
if(VCPKG_TARGET_TRIPLET MATCHES "static")
    qt_import_qml_plugins(seal)
endif()

# Dead-code elimination for static builds.
if(MSVC AND VCPKG_TARGET_TRIPLET MATCHES "static")
    target_link_options(seal PRIVATE /OPT:REF /OPT:ICF)
endif()

# windeployqt + qt.conf are only needed for shared (dynamic) Qt builds.
# Static Qt links everything into the exe; there are no DLLs to deploy.
if(WIN32 AND NOT VCPKG_TARGET_TRIPLET MATCHES "static")
    if(TARGET Qt6::windeployqt)
        get_target_property(WINDEPLOYQT_EXECUTABLE Qt6::windeployqt IMPORTED_LOCATION)
    endif()

    if(NOT WINDEPLOYQT_EXECUTABLE)
        find_program(WINDEPLOYQT_EXECUTABLE NAMES windeployqt windeployqt.exe)
    endif()

    if(NOT WINDEPLOYQT_EXECUTABLE)
        message(FATAL_ERROR "windeployqt not found. Install Qt6 tools from vcpkg (qtbase).")
    endif()

    add_custom_command(TARGET seal POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
            --no-compiler-runtime
            --qmldir "${CMAKE_CURRENT_SOURCE_DIR}/qml"
            --dir "$<TARGET_FILE_DIR:seal>"
            "$<TARGET_FILE:seal>"
        COMMENT "Deploying Qt runtime and QML modules"
        VERBATIM
    )

    add_custom_command(TARGET seal POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/qt.conf"
            "$<TARGET_FILE_DIR:seal>/qt.conf"
        COMMENT "Copying qt.conf for QML import paths"
        VERBATIM
    )
endif()

install(TARGETS seal
    RUNTIME DESTINATION bin
)
if(NOT VCPKG_TARGET_TRIPLET MATCHES "static")
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/qt.conf"
        DESTINATION bin
    )
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/sealConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

if(ENABLE_TESTS)
    enable_testing()
    find_package(GTest REQUIRED CONFIG)

    add_executable(seal_tests
        tests/test_crypto.cpp
        tests/test_utils.cpp
        tests/test_integration.cpp
        src/Cryptography.cpp
        src/Utils.cpp
        src/Clipboard.cpp
        src/Console.cpp
        src/FileOperations.cpp
        src/PasswordGen.cpp
    )

    target_include_directories(seal_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_link_libraries(seal_tests PRIVATE
        GTest::gtest_main
        ${WINDOWS_LIBS}
    )

    if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
        target_link_libraries(seal_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    else()
        target_link_libraries(seal_tests PRIVATE ${OPENSSL_LIBRARIES})
    endif()

    target_compile_definitions(seal_tests PRIVATE
        NOMINMAX
        _WIN32_WINNT=0x0A00
    )

    include(GoogleTest)
    gtest_discover_tests(seal_tests)
endif()

set(CPACK_PACKAGE_NAME "seal")
set(CPACK_PACKAGE_VENDOR "seal Contributors")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "AES-256-GCM encryption utility")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_GENERATOR "ZIP;NSIS")
include(CPack)
