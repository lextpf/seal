@echo off
REM ============================================================================
REM build.bat - Complete build pipeline for seal
REM ============================================================================
REM This script:
REM   1. Configures the project using CMake with vcpkg toolchain
REM   2. Builds the Release configuration
REM   3. Generates API documentation with doxide + mkdocs (if available)
REM ============================================================================

setlocal enabledelayedexpansion

REM --- Visual Studio paths ---
set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\2022\Community\VC"
set "VSVCVARS=%MSVC_ROOT%\Auxiliary\Build\vcvars64.bat"

REM --- Repository root ---
set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"

REM --- vcpkg: use env VCPKG_ROOT if set, otherwise fall back ---
if not defined VCPKG_ROOT set "VCPKG_ROOT=%REPO_ROOT%\..\vcpkg"
set "REPO_OVERLAY_TRIPLETS=%REPO_ROOT%\triplets"
set "DEFAULT_TRIPLET=x64-windows-release-msvc143"
set "VCPKG_TRIPLET=%VCPKG_TRIPLET%"

REM --- Defaults for optional env overrides ---
if not defined VCPKG_TRIPLET set "VCPKG_TRIPLET=%DEFAULT_TRIPLET%"
if not defined VCPKG_MAX_CONCURRENCY set "VCPKG_MAX_CONCURRENCY=1"

REM --- Pin MSVC toolset version if the expected compiler is installed ---
if not defined VCVARS_VER if exist "%MSVC_ROOT%\Tools\MSVC\14.43.34808" set "VCVARS_VER=14.43"
set "PINNED_TOOLSET="
if defined VCVARS_VER set "PINNED_TOOLSET=v143,version=%VCVARS_VER%"
set "CMAKE_TOOLSET_ARG="
if defined PINNED_TOOLSET set "CMAKE_TOOLSET_ARG=-T %PINNED_TOOLSET%"

REM --- Overlay triplets ---
set "VCPKG_OVERLAY_TRIPLETS_ARG="
if exist "%REPO_OVERLAY_TRIPLETS%" set "VCPKG_OVERLAY_TRIPLETS_ARG=-DVCPKG_OVERLAY_TRIPLETS=%REPO_OVERLAY_TRIPLETS%"

REM --- Build output and vcpkg buildtrees (avoid MAX_PATH) ---
set "BUILD_DIR=%REPO_ROOT%\build"
if not defined VCPKG_BUILDTREES_ROOT set "VCPKG_BUILDTREES_ROOT=C:\b\seal-vcpkg"
if not exist "%VCPKG_BUILDTREES_ROOT%" mkdir "%VCPKG_BUILDTREES_ROOT%" >nul 2>&1
set "VCPKG_INSTALL_OPTIONS_ARG=-DVCPKG_INSTALL_OPTIONS=--x-buildtrees-root=%VCPKG_BUILDTREES_ROOT%"

REM --- Resolve vcpkg toolchain path ---
if "%VCPKG_ROOT:~-1%"=="\" set "VCPKG_ROOT=%VCPKG_ROOT:~0,-1%"
set "TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"

if not exist "%VSVCVARS%" (
    echo ERROR: vcvars64.bat not found at:
    echo   %VSVCVARS%
    exit /b 1
)

if not exist "%TOOLCHAIN_FILE%" (
    echo ERROR: vcpkg toolchain not found at:
    echo   %TOOLCHAIN_FILE%
    echo Set VCPKG_ROOT to your vcpkg installation directory.
    exit /b 1
)

set "SAVED_VCPKG_ROOT=%VCPKG_ROOT%"
if defined VCVARS_VER (
    call "%VSVCVARS%" -vcvars_ver=%VCVARS_VER%
) else (
    call "%VSVCVARS%"
)
if errorlevel 1 (
    echo ERROR: Failed to initialize Visual Studio build environment
    exit /b 1
)

REM vcvars64.bat may override VCPKG_ROOT with VS-bundled vcpkg; restore ours.
set "VCPKG_ROOT=%SAVED_VCPKG_ROOT%"

REM If the existing cache points to a different toolchain file, clear it first.
if exist "%BUILD_DIR%\CMakeCache.txt" (
    set "CACHED_TOOLCHAIN_FILE="
    for /f "tokens=2 delims==" %%I in ('findstr /B /C:"CMAKE_TOOLCHAIN_FILE:UNINITIALIZED=" /C:"CMAKE_TOOLCHAIN_FILE:FILEPATH=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_TOOLCHAIN_FILE=%%I"
    if defined CACHED_TOOLCHAIN_FILE (
        set "CACHED_TOOLCHAIN_FILE=!CACHED_TOOLCHAIN_FILE:/=\!"
        set "TOOLCHAIN_FILE=!TOOLCHAIN_FILE:/=\!"
        if /I not "!CACHED_TOOLCHAIN_FILE!"=="!TOOLCHAIN_FILE!" (
            echo INFO: Toolchain changed from:
            echo   !CACHED_TOOLCHAIN_FILE!
            echo to:
            echo   !TOOLCHAIN_FILE!
            echo Clearing CMake cache in %BUILD_DIR%
            del /f /q "%BUILD_DIR%\CMakeCache.txt" >nul 2>&1
            if exist "%BUILD_DIR%\CMakeFiles" rmdir /s /q "%BUILD_DIR%\CMakeFiles"
        )
    )
)

REM Generator toolset changes are sticky in CMakeCache; refresh cache when pinned toolset is active.
if defined PINNED_TOOLSET if exist "%BUILD_DIR%\CMakeCache.txt" (
    echo INFO: Refreshing CMake cache to apply generator toolset %PINNED_TOOLSET%
    del /f /q "%BUILD_DIR%\CMakeCache.txt" >nul 2>&1
    if exist "%BUILD_DIR%\CMakeFiles" rmdir /s /q "%BUILD_DIR%\CMakeFiles"
)

echo ============================================================================
echo                             SEAL BUILD PIPELINE
echo ============================================================================
echo Repo Root:            %REPO_ROOT%
echo vcpkg Root:           %VCPKG_ROOT%
echo Triplet:              %VCPKG_TRIPLET%
if defined VCPKG_OVERLAY_TRIPLETS_ARG echo Overlay Triplets:      %REPO_OVERLAY_TRIPLETS%
if defined VCVARS_VER echo MSVC Toolset:         %VCVARS_VER%
if defined PINNED_TOOLSET echo CMake Toolset Arg:    %PINNED_TOOLSET%
echo Max Concurrency:      %VCPKG_MAX_CONCURRENCY%
echo Buildtrees Root:      %VCPKG_BUILDTREES_ROOT%
echo Build Directory:      %BUILD_DIR%
echo.

echo [1/3] Configuring with CMake...
echo ----------------------------------------------------------------------------
cmake -S "%REPO_ROOT%" -B "%BUILD_DIR%" -G "Visual Studio 17 2022" -A x64 %CMAKE_TOOLSET_ARG% ^
  -DCMAKE_TOOLCHAIN_FILE="%TOOLCHAIN_FILE%" ^
  -DVCPKG_MANIFEST_MODE=ON ^
  -DVCPKG_MANIFEST_INSTALL=ON ^
  %VCPKG_INSTALL_OPTIONS_ARG% ^
  %VCPKG_OVERLAY_TRIPLETS_ARG% ^
  -DVCPKG_TARGET_TRIPLET="%VCPKG_TRIPLET%" ^
  -DVCPKG_HOST_TRIPLET="%VCPKG_TRIPLET%" ^
  -DENABLE_TESTS=ON
if errorlevel 1 (
    echo ERROR: CMake configuration failed
    exit /b %ERRORLEVEL%
)
echo.

echo [2/3] Building Release...
echo ----------------------------------------------------------------------------
cmake --build "%BUILD_DIR%" --config Release
if errorlevel 1 (
    echo ERROR: Build failed
    exit /b %ERRORLEVEL%
)
echo.

echo [3/3] Generating API documentation...
echo ----------------------------------------------------------------------------
where doxide >nul 2>&1
if errorlevel 1 (
    echo SKIP: doxide not found in PATH
) else (
    pushd "%REPO_ROOT%"
    doxide build
    if errorlevel 1 (
        echo ERROR: doxide build failed
        popd
        exit /b %ERRORLEVEL%
    )
    python scripts\_promote_subgroups.py
    if errorlevel 1 (
        echo ERROR: _promote_subgroups.py failed
        popd
        exit /b %ERRORLEVEL%
    )
    python scripts\_clean_docs.py
    if errorlevel 1 (
        echo ERROR: _clean_docs.py failed
        popd
        exit /b %ERRORLEVEL%
    )
    mkdocs build
    if errorlevel 1 (
        echo ERROR: mkdocs build failed
        popd
        exit /b %ERRORLEVEL%
    )
    popd
)
echo.

echo ============================================================================
echo                           BUILD PIPELINE COMPLETE
echo ============================================================================
echo.
echo Build Output:
echo   - EXE: %BUILD_DIR%\bin\Release\seal.exe
echo.
echo Documentation:
echo   - API: %REPO_ROOT%\site\ (if doxide available)
echo.

endlocal
exit /b 0
