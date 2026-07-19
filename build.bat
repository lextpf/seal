@echo off
REM ===========================================================================================
REM build.bat - Complete build pipeline for seal
REM ===========================================================================================
REM This script:
REM   1. clang-format - in-place formatting of src/*.cpp / src/*.hpp / src/*.h / src/*.c
REM   2. cmake        - CMake configure with vcpkg manifest install and VS 17 2022 generator
REM   3. clang-tidy   - static analysis for diagnosing and fixing typical programming errors
REM   4. build        - release build of the Release configuration via cmake --build
REM   5. doxide       - API documentation generation via doxide + mkdocs build
REM
REM Options:
REM   --static        static /MT build - a single portable seal.exe (no Qt DLLs)
REM   --skip-tidy     skip step 3 (clang-tidy static analysis)
REM   --help, -h      print usage and exit
REM
REM Environment overrides (each applied only when not already defined):
REM   VCPKG_ROOT              default <repo>/../vcpkg
REM   VCPKG_TRIPLET           default from the msvc143 overlay (static or dynamic)
REM   VCPKG_MAX_CONCURRENCY   default 1 (raise at your own risk; see the ICE note)
REM   VCVARS_VER              default 14.43 when that toolset is installed
REM   VCPKG_BUILDTREES_ROOT   default C:\b\seal-vcpkg
REM
REM MSVC_ROOT (near the top of this file) has no override and assumes the
REM Community edition. Edit it for Professional, Enterprise or Build Tools,
REM otherwise the run stops at "vcvars64.bat not found".
REM
REM Step 2 deletes build/CMakeCache.txt first, so every run is a full
REM reconfigure. Step 3 aborts the whole pipeline on the first clang-tidy
REM finding; use --skip-tidy to build past it.
REM
REM   MSVC has Internal Compiler Errors (ICEs) when building Qt6 via vcpkg.
REM   This forces us to pin the compiler to 14.43 (14.44 crashes), disable
REM   precompiled headers, limit parallelism to 1, and redirect vcpkg
REM   buildtrees to a short path (C:\b\) to dodge the 260-char MAX_PATH
REM   limit that Qt's deep build tree hits. The rest is defensive cache
REM   management so stale CMake state doesn't silently pick the wrong
REM   (crashing) compiler.
REM ===========================================================================================

setlocal enabledelayedexpansion

REM --- Parse command-line flags ---
set "STATIC_BUILD=0"
set "SKIP_TIDY=0"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--static" (
    set "STATIC_BUILD=1"
    shift
    goto parse_args
)
if /i "%~1"=="--skip-tidy" (
    set "SKIP_TIDY=1"
    shift
    goto parse_args
)
if /i "%~1"=="--help" (
    set USAGE_RC=0
    goto usage
)
if /i "%~1"=="-h" (
    set USAGE_RC=0
    goto usage
)
echo ERROR: unknown option "%~1"
set USAGE_RC=1
goto usage

:usage
echo.
echo Usage: build.bat [--static] [--skip-tidy] [--help]
echo.
echo   --static       Static /MT build - a single portable seal.exe (no Qt DLLs)
echo   --skip-tidy    Skip the clang-tidy static analysis step
echo   --help, -h     Show this message
echo.
exit /b !USAGE_RC!

:args_done

REM --- Visual Studio paths ---
set "MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\2022\Community\VC"
set "VSVCVARS=%MSVC_ROOT%\Auxiliary\Build\vcvars64.bat"

REM --- Repository root ---
set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"

REM --- vcpkg: use env VCPKG_ROOT if set, otherwise fall back ---
if not defined VCPKG_ROOT set "VCPKG_ROOT=%REPO_ROOT%\..\vcpkg"
set "REPO_OVERLAY_TRIPLETS=%REPO_ROOT%\cmake"
set "DEFAULT_TRIPLET=x64-windows-release-msvc143"
set "STATIC_TRIPLET=x64-windows-static-release-msvc143"

REM --- Defaults for optional env overrides ---
if "%STATIC_BUILD%"=="1" (
    if not defined VCPKG_TRIPLET set "VCPKG_TRIPLET=%STATIC_TRIPLET%"
) else (
    if not defined VCPKG_TRIPLET set "VCPKG_TRIPLET=%DEFAULT_TRIPLET%"
)
REM MSVC crashes under parallel compilation when building Qt6.
if not defined VCPKG_MAX_CONCURRENCY set "VCPKG_MAX_CONCURRENCY=1"

REM --- Pin MSVC toolset version if the expected compiler is installed ---
REM MSVC 14.44 ICEs on Qt6 sources; pin to 14.43 which is stable.
if not defined VCVARS_VER if exist "%MSVC_ROOT%\Tools\MSVC\14.43.34808" set "VCVARS_VER=14.43"
set "PINNED_TOOLSET="
if defined VCVARS_VER set "PINNED_TOOLSET=v143,version=%VCVARS_VER%"
set "CMAKE_TOOLSET_ARG="
if defined PINNED_TOOLSET set "CMAKE_TOOLSET_ARG=-T %PINNED_TOOLSET%"

REM --- Overlay triplets ---
set "VCPKG_OVERLAY_TRIPLETS_ARG="
if exist "%REPO_OVERLAY_TRIPLETS%" set "VCPKG_OVERLAY_TRIPLETS_ARG=-DVCPKG_OVERLAY_TRIPLETS=%REPO_OVERLAY_TRIPLETS%"

REM --- Build output and vcpkg buildtrees ---
set "BUILD_DIR=%REPO_ROOT%\build"
REM Qt6's vcpkg buildtree paths are deeply nested and exceed
REM the Windows 260-char MAX_PATH limit. Redirect to a short root path.
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

REM vcvars64.bat silently overwrites VCPKG_ROOT with the
REM VS-bundled vcpkg path, which isn't ours. Save and restore it.
set "SAVED_VCPKG_ROOT=%VCPKG_ROOT%"
if defined VCVARS_VER (
    call "%VSVCVARS%" -vcvars_ver=%VCVARS_VER%
) else (
    call "%VSVCVARS%"
)
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to initialize Visual Studio build environment
    exit /b 1
)
set "VCPKG_ROOT=%SAVED_VCPKG_ROOT%"

REM if VCPKG_ROOT changed between runs (e.g. env var updated),
REM the cached toolchain path becomes stale and CMake won't re-detect it.
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

REM CMake bakes the generator toolset (-T) into CMakeCache.
REM If we don't clear it, a stale cache can silently use the wrong (crashing)
REM MSVC version even though we pass the correct -T flag.
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
if defined VCPKG_OVERLAY_TRIPLETS_ARG echo Overlay Triplets:     %REPO_OVERLAY_TRIPLETS%
if defined VCVARS_VER echo MSVC Toolset:         %VCVARS_VER%
if defined PINNED_TOOLSET echo CMake Toolset Arg:    %PINNED_TOOLSET%
echo Max Concurrency:      %VCPKG_MAX_CONCURRENCY%
echo Buildtrees Root:      %VCPKG_BUILDTREES_ROOT%
echo Build Directory:      %BUILD_DIR%
echo.

REM ============================================================================
REM STEP 1: Run clang-format
REM ============================================================================
echo [1/5] Running clang-format...
echo ----------------------------------------------------------------------------

where clang-format >nul 2>&1
if errorlevel 1 (
    echo SKIP: clang-format not found in PATH
) else (
    for %%f in (src\*.cpp src\*.hpp src\*.c src\*.h) do (
        if exist "%%f" clang-format -i "%%f"
    )
    echo Formatting complete.
)
echo.

REM ============================================================================
REM STEP 2: CMake Configuration
REM ----------------------------------------------------------------------------
REM `--static` routes to the static-Qt preset; everything else uses default.
REM Both presets read $env{VCPKG_BUILDTREES_ROOT} for Qt's MAX_PATH redirect,
REM which this script has already exported.
REM ============================================================================
set "CONFIGURE_PRESET=default"
if "%STATIC_BUILD%"=="1" set "CONFIGURE_PRESET=static"

echo [2/5] Configuring with CMake ^(preset: %CONFIGURE_PRESET%^)...
echo ----------------------------------------------------------------------------
cmake --preset %CONFIGURE_PRESET%
if %ERRORLEVEL% neq 0 (
    echo ERROR: CMake configuration failed
    exit /b %ERRORLEVEL%
)
echo.

REM ============================================================================
REM STEP 3: Run clang-tidy
REM ============================================================================
echo [3/5] Running clang-tidy...
echo ----------------------------------------------------------------------------

if !SKIP_TIDY!==1 (
    echo SKIP: clang-tidy disabled by --skip-tidy
    goto :tidy_done
)

REM clang-tidy reads the Ninja compile-DB sidecar (build-cdb), which is pinned to
REM the dynamic triplet and shares build\vcpkg_installed. A static configure evicts
REM the dynamic Qt tree from that shared dir, so the sidecar's include paths vanish
REM (e.g. 'QObject' file not found). Regenerating it here would reinstall the dynamic
REM triplet over the static one and corrupt the static build. Static is a packaging
REM build - lint runs on the default (dynamic) build.bat instead.
if "%STATIC_BUILD%"=="1" (
    echo SKIP: clang-tidy is not run for static builds ^(lint runs on the default build^).
    goto :tidy_done
)

where clang-tidy >nul 2>&1
if errorlevel 1 (
    echo SKIP: clang-tidy not found in PATH
) else (
    if not exist "build-cdb\compile_commands.json" (
        echo   Generating compile_commands.json via Ninja sidecar...
        cmake --preset compile-db >nul
        if !ERRORLEVEL! neq 0 (
            echo ERROR: compile-db configure failed
            exit /b 1
        )
    )

    for %%f in (src\*.cpp tests\*.cpp) do (
        if exist "%%f" (
            echo   tidy: %%f
            clang-tidy --quiet --header-filter="[/\\]%%~nf\.hpp$" -p build-cdb "%%f"
            if !ERRORLEVEL! neq 0 (
                echo ERROR: clang-tidy reported issues in %%f
                exit /b 1
            )
        )
    )
    echo clang-tidy complete.
)

:tidy_done
echo.

REM ============================================================================
REM STEP 4: Build Release
REM ============================================================================
echo [4/5] Building Release...
echo ----------------------------------------------------------------------------
cmake --build "%BUILD_DIR%" --config Release
if %ERRORLEVEL% neq 0 (
    echo ERROR: Build failed
    exit /b %ERRORLEVEL%
)
echo.

REM ============================================================================
REM STEP 5: Generate API Documentation (doxide)
REM ============================================================================
echo [5/5] Generating API documentation...
echo ----------------------------------------------------------------------------
where doxide >nul 2>&1
if errorlevel 1 (
    echo SKIP: doxide not found in PATH
) else (
    pushd "%REPO_ROOT%"
    doxide build
    if !ERRORLEVEL! neq 0 (
        echo ERROR: doxide build failed [exit code !ERRORLEVEL!]
        popd
        exit /b 1
    )
    python scripts\_promote_subgroups.py
    if !ERRORLEVEL! neq 0 (
        echo ERROR: _promote_subgroups.py failed [exit code !ERRORLEVEL!]
        popd
        exit /b 1
    )
    python scripts\_clean_docs.py
    if !ERRORLEVEL! neq 0 (
        echo ERROR: _clean_docs.py failed [exit code !ERRORLEVEL!]
        popd
        exit /b 1
    )
    mkdocs build
    if !ERRORLEVEL! neq 0 (
        echo ERROR: mkdocs build failed [exit code !ERRORLEVEL!]
        popd
        exit /b 1
    )
    popd
)
echo.

REM ============================================================================
REM SUMMARY
REM ============================================================================
echo ============================================================================
echo                           BUILD PIPELINE COMPLETE
echo ============================================================================
echo.
echo Build Output:
echo   Release: build\bin\Release\seal.exe
if "%STATIC_BUILD%"=="1" (
    echo   Linkage: Static (/MT, %STATIC_TRIPLET%)
) else (
    echo   Linkage: Dynamic (/MD, %DEFAULT_TRIPLET%)
)
echo.
echo Documentation:
echo   - Md:   docs\  (if doxide available)
echo   - Html: site\  (if mkdocs available)
echo.
echo ============================================================================

endlocal
exit /b 0
