cmake_minimum_required(VERSION 3.20)

project(sage
    VERSION 1.0.0
    DESCRIPTION "AES-256-GCM encrypt/decrypt console utility with locked memory and guard pages"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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
    Secur32
    Advapi32
    Comdlg32
    Crypt32
    dwmapi
)

set(SAGE_SOURCES
    src/main.cpp
    src/Cryptography.cpp
    src/Utils.cpp
    src/Clipboard.cpp
    src/Console.cpp
    src/FileOperations.cpp
    src/Backend.cpp
    src/QrCapture.cpp
    src/FillController.cpp
    src/VaultModel.cpp
    src/QmlMain.cpp
    src/Vault.cpp
    src/Logging.cpp
)

qt_standard_project_setup()
qt_policy(SET QTP0001 NEW)
qt_policy(SET QTP0004 NEW)

set_source_files_properties(qml/Theme.qml PROPERTIES
    QT_QML_SINGLETON_TYPE TRUE
)

qt_add_executable(sage
    ${SAGE_SOURCES}
)

target_include_directories(sage PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
    target_link_libraries(sage PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
else()
    target_link_libraries(sage PRIVATE
        ${OPENSSL_LIBRARIES}
    )
    if(OPENSSL_LIB_DIR)
        target_link_directories(sage PRIVATE ${OPENSSL_LIB_DIR})
    endif()
endif()

target_link_libraries(sage PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Widgets
    ${WINDOWS_LIBS}
    ${OpenCV_LIBS}
)

target_compile_definitions(sage PRIVATE
    NOMINMAX
    _WIN32_WINNT=0x0A00
    USE_QT_UI
)

file(GLOB SAGE_SVGS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} assets/svgs/*.svg)

qt_add_qml_module(sage
    URI sage
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
        qml/DirectoryBar.qml
        qml/StatusFooter.qml
        qml/AccountDialog.qml
        qml/ConfirmDialog.qml
        qml/PasswordDialog.qml
        qml/RippleEffect.qml
        qml/SvgIcon.qml
    RESOURCES
        "assets/fonts/b0a4eabe-5fe5-41e3-8dc3-2df2b82ec4eb.ttf"
        ${SAGE_SVGS}
)

if(WIN32)
    if(TARGET Qt6::windeployqt)
        get_target_property(WINDEPLOYQT_EXECUTABLE Qt6::windeployqt IMPORTED_LOCATION)
    endif()

    if(NOT WINDEPLOYQT_EXECUTABLE)
        find_program(WINDEPLOYQT_EXECUTABLE NAMES windeployqt windeployqt.exe)
    endif()

    if(NOT WINDEPLOYQT_EXECUTABLE)
        message(FATAL_ERROR "windeployqt not found. Install Qt6 tools from vcpkg (qtbase).")
    endif()

    add_custom_command(TARGET sage POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
            --no-compiler-runtime
            --qmldir "${CMAKE_CURRENT_SOURCE_DIR}/qml"
            --dir "$<TARGET_FILE_DIR:sage>"
            "$<TARGET_FILE:sage>"
        COMMENT "Deploying Qt runtime and QML modules"
        VERBATIM
    )

    add_custom_command(TARGET sage POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/qt.conf"
            "$<TARGET_FILE_DIR:sage>/qt.conf"
        COMMENT "Copying qt.conf for QML import paths"
        VERBATIM
    )
endif()

install(TARGETS sage
    RUNTIME DESTINATION bin
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/qt.conf"
    DESTINATION bin
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/sageConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

if(ENABLE_TESTS)
    enable_testing()
    find_package(GTest REQUIRED CONFIG)

    add_executable(sage_tests
        tests/test_crypto.cpp
        tests/test_utils.cpp
        tests/test_integration.cpp
        src/Cryptography.cpp
        src/Utils.cpp
        src/Clipboard.cpp
        src/Console.cpp
        src/FileOperations.cpp
    )

    target_include_directories(sage_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_link_libraries(sage_tests PRIVATE
        GTest::gtest_main
        ${WINDOWS_LIBS}
    )

    if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
        target_link_libraries(sage_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    else()
        target_link_libraries(sage_tests PRIVATE ${OPENSSL_LIBRARIES})
    endif()

    target_compile_definitions(sage_tests PRIVATE
        NOMINMAX
        _WIN32_WINNT=0x0A00
    )

    include(GoogleTest)
    gtest_discover_tests(sage_tests)
endif()

set(CPACK_PACKAGE_NAME "sage")
set(CPACK_PACKAGE_VENDOR "sage Contributors")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "AES-256-GCM encryption utility")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_GENERATOR "ZIP;NSIS")
include(CPack)
