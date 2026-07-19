@echo off
REM ===========================================================================================
REM run.bat - Run seal: the Release build of the credential manager
REM ===========================================================================================
REM Starts build\bin\Release\seal.exe with the executable's own directory as the working
REM directory and waits for it to exit. seal.exe is a console-subsystem binary, so it inherits
REM this console: its logfmt diagnostics land in this window and Ctrl-C stops it. The line to
REM watch for is event=app.qml.load.ok - that is the window-is-up signal.
REM
REM run.bat takes no arguments. Bare seal.exe is GUI mode; every CLI subcommand (encrypt,
REM decrypt, gen, list, get, rekey, import, export, ...) keeps stdout pipe-clean for piping,
REM so call the executable directly for those rather than through this script.
REM
REM The working directory is the executable's own folder, not the repository root. seal
REM auto-loads the first .seal file carrying vault magic that it finds in the executable
REM directory, then the working directory, then %USERPROFILE% - and the protected-folder root
REM is the executable directory. Running from there keeps both searches on the same folder.
REM ===========================================================================================

setlocal enabledelayedexpansion

REM --- Parse command-line flags ---
if "%~1"=="" goto args_done
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
echo Usage: run.bat [--help]
echo.
echo   run.bat launches the Release GUI and takes no arguments.
echo   For CLI work call the executable directly, so its stdout stays pipe-clean:
echo     build\bin\Release\seal.exe --help
echo     build\bin\Release\seal.exe list [vault.seal]
echo     build\bin\Release\seal.exe get ^<platform^> --stdout
echo.
exit /b !USAGE_RC!

:args_done

echo ============================================================================
echo                                    SEAL
echo ============================================================================
echo.

REM --- Repository root ---
set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
set "BUILD_DIR=%REPO_ROOT%\build"

REM --- Release binary: the Visual Studio generator is multi-config and writes build\bin\Release,
REM     a single-config generator would write build\bin. test.bat probes both, so this does too. ---
set "APP_DIR=%BUILD_DIR%\bin\Release"
set "APP_EXE=%APP_DIR%\seal.exe"
if not exist "%APP_EXE%" if exist "%BUILD_DIR%\bin\seal.exe" (
    set "APP_DIR=%BUILD_DIR%\bin"
    set "APP_EXE=%BUILD_DIR%\bin\seal.exe"
)

REM ============================================================================
REM Preflight
REM ============================================================================
if not exist "%APP_EXE%" (
    echo ERROR: seal.exe not found at
    echo   %APP_DIR%\seal.exe
    echo.
    echo Build it first:
    echo   build.bat                full pipeline ^(format, configure, tidy, build, docs^)
    echo   build.bat --skip-tidy    the same without the blocking static-analysis step
    echo.
    echo Or build only the Release executable:
    echo   cmake --preset default
    echo   cmake --build build --config Release --target seal
    echo.
    pause
    exit /b 1
)

REM The build tree records the vcpkg triplet that configured it. A dynamic build needs its Qt
REM DLLs, the qwindows platform plugin and qt.conf deployed beside the exe; a static build has
REM all of that linked in and needs none of it. Reading the cache rather than sniffing for
REM Qt6Core.dll matters here, because a tree switched from one linkage to the other keeps the
REM previous build's DLLs lying around, and they look exactly like a healthy deployment.
set "LINKAGE=Unknown"
for /f "tokens=2 delims==" %%t in ('findstr /b /c:"VCPKG_TARGET_TRIPLET:" "%BUILD_DIR%\CMakeCache.txt" 2^>nul') do (
    echo %%t | findstr /i "static" >nul && set "LINKAGE=Static" || set "LINKAGE=Dynamic"
)

if "%LINKAGE%"=="Dynamic" (
    if not exist "%APP_DIR%\platforms\qwindows.dll" (
        echo WARNING: platforms\qwindows.dll is missing next to seal.exe.
        echo          This tree is configured dynamic, so Qt loads its platform plugin from
        echo          there. Without it Qt calls qFatal inside the QGuiApplication constructor
        echo          and the process aborts before seal logs a single line. Re-run build.bat.
        echo.
    )
    if not exist "%APP_DIR%\qt.conf" (
        echo WARNING: qt.conf is missing next to seal.exe.
        echo          It points Qt's QML import path at the deployed qml\ folder; without it
        echo          the QML modules are not found and startup ends in app.qml.load.fail.
        echo.
    )
)

REM build.bat and run.bat share one build tree, so an executable from before the last source
REM edit is easy to end up with - and a stale run looks exactly like a fix that did not work.
REM qml\ counts as source here: qt_add_qml_module compiles every .qml into the binary, so
REM editing one changes nothing until the next build. The check degrades to silence when
REM powershell is unavailable.
set "STALE="
for /f %%R in ('powershell -NoProfile -Command "$e=(Get-Item '%APP_EXE%').LastWriteTime;$n=[datetime]::MinValue;foreach($f in Get-ChildItem '%REPO_ROOT%\src','%REPO_ROOT%\qml' -File -Recurse -ErrorAction SilentlyContinue){if($f.LastWriteTime -gt $n){$n=$f.LastWriteTime}};$c=Get-Item '%REPO_ROOT%\CMakeLists.txt' -ErrorAction SilentlyContinue;if($c -and $c.LastWriteTime -gt $n){$n=$c.LastWriteTime};[int]($n -gt $e)"') do set "STALE=%%R"
if "%STALE%"=="1" (
    echo WARNING: src\, qml\ or CMakeLists.txt is newer than seal.exe - this build is stale.
    echo          Run build.bat to rebuild, or carry on to run the older executable.
    echo.
)

if not exist "%APP_DIR%\seal-browser.exe" (
    echo WARNING: seal-browser.exe not found next to seal.exe.
    echo          The browser companion is enabled by default but has no native-messaging
    echo          host to talk to, and install-browser-extension refuses the install with
    echo          reason=host_exe_missing. Both binaries must share one directory.
    echo.
)

REM Report which vault seal is most likely to auto-load. This is the launcher's best guess at
REM the cascade seal walks, not a promise: seal skips candidates that lack vault magic.
set "VAULT_FOUND="
set "VAULT_WHERE="
for /f "delims=" %%v in ('dir /b /a-d "%APP_DIR%\*.seal" 2^>nul') do (
    if not defined VAULT_FOUND (
        set "VAULT_FOUND=%%v"
        set "VAULT_WHERE=beside the executable"
    )
)
if not defined VAULT_FOUND (
    for /f "delims=" %%v in ('dir /b /a-d "%USERPROFILE%\*.seal" 2^>nul') do (
        if not defined VAULT_FOUND (
            set "VAULT_FOUND=%%v"
            set "VAULT_WHERE=in your user profile"
        )
    )
)
if not defined VAULT_FOUND (
    echo INFO: no .seal vault found beside the executable or in your user profile.
    echo       seal will open a file picker instead of auto-loading one.
    echo.
)

REM ============================================================================
REM Launch
REM ============================================================================
echo Executable:           %APP_EXE%
echo Working directory:    %APP_DIR%
echo Linkage:              %LINKAGE%
if defined VAULT_FOUND (
    echo Vault candidate:      !VAULT_FOUND! ^(!VAULT_WHERE!^)
)
echo.
echo   Watch for event=app.qml.load.ok - that line means the window is up. A QML failure
echo   logs event=app.qml.load.fail instead and exits 1.
echo   Ctrl+Click a field in another window to fill it. The vault auto-locks after an idle
echo   timeout and on Windows session lock.
echo.
echo ----------------------------------------------------------------------------

cd /d "%APP_DIR%"
"%APP_EXE%"
set "APP_RC=%ERRORLEVEL%"

REM ============================================================================
REM Summary
REM ============================================================================
echo ----------------------------------------------------------------------------
if not "%APP_RC%"=="0" goto :app_failed

echo.
echo ============================================================================
echo                            SEAL EXITED CLEANLY
echo ============================================================================

endlocal
exit /b 0

REM ============================================================================
REM Reached only by GOTO from the summary
REM ============================================================================
:app_failed
echo.
echo ============================================================================
echo                       SEAL EXITED WITH CODE %APP_RC%
echo ============================================================================
echo.
if "%APP_RC%"=="1" (
    echo   Exit code 1 is a controlled refusal. The reason is in the scrollback above:
    echo     event=app.qml.load.fail          a QML file failed to load or bind
    echo     reason=remote_session_detected   seal refuses to run in a remote session
    echo.
)
if "%APP_RC%"=="57005" (
    echo   Exit code 57005 ^(0xDEAD^) is the anti-debug kill - a debugger was attached.
    echo.
)
echo   seal writes no log file, so the scrollback above is the whole record. A run that
echo   aborts without printing any seal line at all is usually a missing Qt DLL or platform
echo   plugin: that fails in the Windows loader, before main gets to say anything.
echo.
pause

REM endlocal discards APP_RC, so the exit code has to be expanded on the same line -
REM the whole line is parsed before endlocal runs. A separate 'exit /b %APP_RC%' after
REM endlocal expands to nothing and reports success for a failed run.
endlocal & exit /b %APP_RC%
