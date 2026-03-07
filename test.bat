@echo off
REM ============================================================================
REM test.bat - Run seal unit tests using Google Test
REM ============================================================================
REM This script:
REM   1. Configures CMake if needed
REM   2. Builds the test executable
REM   3. Runs the Google Test executable
REM ============================================================================

setlocal

echo ============================================================================
echo                            SEAL TEST RUNNER
echo ============================================================================
echo.

set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
set "BUILD_DIR=%REPO_ROOT%\build"

REM ============================================================================
REM STEP 1: Configure CMake
REM ============================================================================
echo [1/3] Checking CMake configuration...
echo ----------------------------------------------------------------------------
if not exist "%BUILD_DIR%\CMakeCache.txt" (
    echo   No existing configuration found, running build.bat to configure...
    call "%REPO_ROOT%\build.bat"
    if errorlevel 1 (
        echo ERROR: build.bat failed!
        pause
        exit /b 1
    )
    echo.
    echo   Configuration complete, continuing with tests...
) else (
    echo   Found existing configuration
)
echo.

REM ============================================================================
REM STEP 2: Build Tests
REM ============================================================================
echo [2/3] Building test executable...
echo ----------------------------------------------------------------------------
cmake --build "%BUILD_DIR%" --config Release --target seal_tests
if errorlevel 1 (
    echo ERROR: Build failed!
    pause
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
    if errorlevel 1 set ALL_PASSED=0
) else if exist "%BUILD_DIR%\bin\seal_tests.exe" (
    "%BUILD_DIR%\bin\seal_tests.exe" --gtest_color=yes
    if errorlevel 1 set ALL_PASSED=0
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

pause
if %ALL_PASSED%==1 (
    exit /b 0
) else (
    exit /b 1
)
