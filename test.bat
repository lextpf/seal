@echo off
REM ============================================================================
REM test.bat - Run seal unit tests using Google Test
REM ============================================================================
REM Build and run seal_tests in the existing build\ configuration.
REM This script does not configure CMake; run build.bat first. Compilation stays serial.

setlocal enabledelayedexpansion

echo ============================================================================
echo                            SEAL TEST RUNNER
echo ============================================================================
echo.

set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
set "BUILD_DIR=%REPO_ROOT%\build"

REM ============================================================================
REM STEP 1: Check CMake configuration
REM ============================================================================
echo [1/3] Checking CMake configuration...
echo ----------------------------------------------------------------------------
if not exist "%BUILD_DIR%\CMakeCache.txt" (
    echo ERROR: No CMake configuration found in "%BUILD_DIR%".
    echo Run build.bat first, then run test.bat again.
    exit /b 1
)
echo   Found existing configuration
echo.

REM ============================================================================
REM STEP 2: Build Tests
REM ============================================================================
echo [2/3] Building test executable...
echo ----------------------------------------------------------------------------
set "VCPKG_MAX_CONCURRENCY=1"
set "CMAKE_BUILD_PARALLEL_LEVEL=1"
set "CL_MPCount=1"
cmake --build "%BUILD_DIR%" --config Release --target seal_tests --parallel 1 -- /m:1 /p:CL_MPCount=1
if not "!ERRORLEVEL!"=="0" (
    echo ERROR: Build failed!
    exit /b 1
)
echo.

REM ============================================================================
REM STEP 3: Run Tests
REM ============================================================================
echo [3/3] Running tests...
echo ----------------------------------------------------------------------------
echo.

set ALL_PASSED=1

echo === seal_tests ===
if exist "%BUILD_DIR%\bin\Release\seal_tests.exe" (
    "%BUILD_DIR%\bin\Release\seal_tests.exe" --gtest_color=yes
    if not "!ERRORLEVEL!"=="0" set ALL_PASSED=0
) else if exist "%BUILD_DIR%\bin\seal_tests.exe" (
    "%BUILD_DIR%\bin\seal_tests.exe" --gtest_color=yes
    if not "!ERRORLEVEL!"=="0" set ALL_PASSED=0
) else (
    echo ERROR: seal_tests.exe not found!
    set ALL_PASSED=0
)
echo.

REM ============================================================================
REM SUMMARY
REM ============================================================================
echo ============================================================================
if %ALL_PASSED%==1 (
    echo                            ALL TESTS PASSED
) else (
    echo                            SOME TESTS FAILED
)
echo ============================================================================

if %ALL_PASSED%==1 (
    exit /b 0
) else (
    exit /b 1
)
