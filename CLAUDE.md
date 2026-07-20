# CLAUDE.md

## Rules

Ask when unclear. If intent, architecture, or requirements are ambiguous, ask before coding.

Flag uncertainty. If an approach, dependency, or technical detail is uncertain, say so before proceeding.

Challenge bad direction. If my request conflicts with settled practice or likely long-term maintainability, point it out and suggest a better path.

End with omissions. After each task, state what you changed and what you intentionally did not do.

## Documentation

Document the code using ASD-STE100-inspired Simplified Technical English: use short, direct sentences, one term per concept, active voice, explicit conditions, and avoid idioms, unnecessary synonyms, or ambiguous wording. Focus documentation on intent, constraints, side effects, and non-obvious behavior;

## Project

`seal` is a Windows-only C++23 credential manager: AES-256-GCM vault + Qt6/QML GUI + streaming CLI +
browser autofill (Chromium native messaging) + Win32 auto-type. No telemetry, no network. It refuses
to run under a debugger (self-`TerminateProcess`, exit `57005`/`0xDEAD`) or in an RDP session, and
`CMakeLists.txt` `FATAL_ERROR`s on non-Windows.

## Commands

Everything is Windows/MSVC. There is no debug configuration in practice (both vcpkg overlay triplets
set `VCPKG_BUILD_TYPE release`, so no debug Qt/OpenSSL exists) — build Release.

```bat
:: full local pipeline: clang-format -i -> cmake configure -> clang-tidy -> Release build -> docs
build.bat                    :: only flags: --static, --skip-tidy, --help (anything else exits 1)

:: incremental, without the .bat wrapper
cmake --preset default       :: presets: default | static | ci | compile-db
cmake --build build --config Release --target seal          :: GUI/CLI exe
cmake --build build --config Release --target seal_tests    :: test binary
cmake --build build --config Release --target seal_browser  :: native-messaging host (seal-browser.exe)

:: tests (GoogleTest, ~395 cases / ~26 s)
ctest --test-dir build -C Release --output-on-failure
build\bin\Release\seal_tests.exe --gtest_filter=UrlBindingTest.*
build\bin\Release\seal_tests.exe --gtest_filter=CryptoTest.BasicRoundtrip
build\bin\Release\seal_tests.exe --gtest_list_tests
ctest --test-dir build -C Release -R "^UrlBindingTest\." --output-on-failure

:: run the GUI
run.bat                      :: or: build\bin\Release\seal.exe

:: lint / format
clang-format -i src\Vault.cpp
clang-tidy --quiet --header-filter="[/\\]Vault\.hpp$" -p build-cdb src\Vault.cpp
cmake --preset compile-db    :: (re)generate the build-cdb/ Ninja sidecar; never *build* this preset

:: docs (order matters; README's version of this is wrong)
doxide build && python scripts\_promote_subgroups.py && python scripts\_clean_docs.py && mkdocs build
```

Command gotchas:

- **`test.bat` ends in `pause`** and hangs forever in a non-interactive shell. Use `ctest` or the exe.
  It also calls the *full* `build.bat` (format + tidy + docs) if `build\CMakeCache.txt` is missing.
- **`build.bat` deletes `build/CMakeCache.txt` on every run** (toolset pinning), forcing a full
  reconfigure. It also hardcodes the VS 2022 **Community** vcvars path and hard-pins MSVC toolset
  `v143,version=14.43` (14.44 ICEs on Qt6), with `VCPKG_MAX_CONCURRENCY=1` and `/MP1` — cold builds
  are very slow.
- `default` and `static` presets share `binaryDir=build` and `build/vcpkg_installed`, so switching
  **evicts the other triplet's Qt tree**. After a `--static` build, clang-tidy/clangd fail with
  `'QObject' file not found` until you re-run `cmake --preset default` (or `compile-db`).
  `build.bat --static` silently skips clang-tidy for this reason.
- `build-cdb/` is a Ninja sidecar compile DB (the VS generator ignores `CMAKE_EXPORT_COMPILE_COMMANDS`).
  `build.bat` regenerates it only when it is *absent*, so it goes stale silently.
- Invoking `cmake --preset default` yourself needs both `VCPKG_ROOT` **and** `VCPKG_BUILDTREES_ROOT`
  in the environment; `build.bat` sets the latter itself.

## Architecture

### `USE_QT_UI` is the layering, not directories

`src/` is flat. The Qt/QML layer is exactly the set of TUs gated behind `#ifdef USE_QT_UI`. The
`seal` target defines it; **`seal_tests` does not and links no Qt**. Consequences:

- 24 of 43 `src/*.cpp` (AppViewModel, FillController, TypeController, StagingController, VaultModel,
  BrowserBridge, QmlMain, CliDispatch/CliHandler, Uia\* probes, WindowChrome/WindowController, …) plus
  all of `host/browser/` are **never compiled by `seal_tests`**. A green `ctest` proves nothing about
  them. Build the `seal` target to compile-check that layer. CI mirrors this: the `tests` workflow
  builds only `seal_tests`; the `build` workflow is what catches Qt/QML compile breaks.
- The crypto/vault core is Qt-*optional*, not Qt-free — `Vault.cpp`/`Cryptography.cpp` include
  `<QtCore/QString>` inside `#ifdef USE_QT_UI` purely for structured logging.
- Pure-logic header-only policy code is the escape hatch and is where new testable logic belongs:
  `AutoStagePolicy.hpp`, `UrlBinding.hpp`, `ProtectedFolderPolicy.hpp`, `SignerUtils.hpp`,
  `ProcessPin.hpp`, `AutoLockPolicy.hpp`, `PublicSuffixTable.hpp`, `SecureString.hpp`,
  `LockedAllocator.hpp`.

### Source-scan tests

Because Qt-gated code cannot be linked, invariants over it are pinned by **reading source files as
text at test runtime** via the `SEAL_SOURCE_DIR` compile definition
(`tests/test_ui_secret_boundaries.cpp` is the big one; `BridgeSourceScanTest` in
`tests/test_process_pin.cpp` is the other). They scan C++, QML, JavaScript and `CMakeLists.txt` itself.

**Renaming a symbol, changing a log string, or editing a QML/JS line can break a test that never
compiles that code.** Examples: every `Q_INVOKABLE` in `BridgeViewModel.hpp` must have a literal
`Bridge.<name>(` call site in `qml/`; dropping `ExitProcess(0)` from `host/browser/main.cpp` fails the
suite; reason tokens such as `reason=pin_failed` are grepped by name.

### Composition root and the C++ to QML surface

`QmlMain.cpp::RunQMLMode` is the whole DI story: every object is a **stack local, and declaration
order is the ownership contract** (owners first, borrowers destruct first). Reordering reintroduces a
teardown use-after-free.

There are exactly **five context properties and zero registered QML types** (no `qmlRegister*`, no
`QML_ELEMENT`). Two names deliberately differ from their class:

| QML name | C++ type |
|---|---|
| `AppViewModel` | `seal::AppViewModel` (hub; also implements `IUiFeedback` + `IPasswordGate`) |
| `Fill` | `seal::TypeController` — **not** `FillController` |
| `Bridge` | `seal::BridgeViewModel` |
| `Cli` | `seal::CliPanelViewModel` (the embedded GUI terminal panel) |
| `WindowVM` | `seal::WindowController` (renamed to avoid QtQuick's `Window` type) |

`FillController`, `StagingController` and `AutoLockController` are owned collaborators and are
**never** exposed; tests enforce both the five-name set and their absence from `qml/`.

Any operation needing the master key must go through `AppViewModel::ensurePassword(action)`, which
either runs inline or enqueues onto the `IPasswordGate` FIFO and emits `passwordRequired()`. New vault
commands that skip this silently no-op when the vault is locked.

Background work goes through `AsyncRunner`; `QtConcurrent::run` decay-copies, so work bodies must be
**copyable** — capture secrets as `std::shared_ptr<SecureWide>`, never a moved `SecureWide`.

### QML module

QML is **compiled into the binary** (`qt_add_qml_module`, URI `seal`, resource
`:/qt/qml/seal/qml/...`); editing `qml/` next to the exe does nothing. Every new `.qml` must be
hand-added to the `QML_FILES` list in `CMakeLists.txt` — there is no glob. `Theme.qml` and
`Ambient.qml` are singletons needing *both* `pragma Singleton` and `QT_QML_SINGLETON_TYPE TRUE` in
CMake. Styling is centralised in `Theme.qml` (use `Theme.px(n)`; raw pixel numbers are off-scale
against `designScale: 1.35`). The Quick Controls style is pinned to `Basic` before `QGuiApplication`
construction and cannot be changed — static vcpkg ships broken configs for the other styles, which the
build deletes.

QML *syntax* errors fail the build via qmlcachegen; **type errors and bad bindings are runtime-only**
(`event=app.qml.load.fail`, exit 1). `qmllint` targets exist but nothing runs them and they are not
clean, so don't wire them into a gate casually. Verify QML changes by launching the app and watching
for `event=app.qml.load.ok`.

The frameless window's Win32 chrome is installed **lazily** by `WindowVM.updateWindowTheme(...)` in
`Component.onCompleted`, one time only. Dragging exists solely because QML `MouseArea`s call
`WindowVM.startWindowDrag()` — any new item covering the top 36 px strip kills window dragging.

### Vault format and crypto

- On disk: one **hex-encoded text line**. Frame = magic `SVH2` + version byte + BE record count, then
  per record `platformLen | platform packet | credLen | credential packet`. `.seal` is overloaded
  (vault and arbitrary encrypted files); `Vault::looksLikeVault()` disambiguates by decoding leading hex.
- Packet = `AAD(8) | salt(16) | IV(12) | ciphertext | tag(16)`. **Two different magics**: the frame
  magic is `SVH2`, the per-packet AAD magic is `seal`.
- KDF is scrypt N=2^16, r=8, p=1 (64 MiB), then AES-256-GCM. Params are self-describing in the
  GCM-authenticated AAD and cap-validated *before* derivation (512 MiB ceiling).
- **No derived-key cache** — every packet carries its own salt, so loading an N-record vault runs N
  scrypt derivations. This is why vault load is off-thread behind a loading overlay.
- Two-tier decryption: platform names decrypt at load (so the list renders), credentials stay sealed
  until `decryptCredentialOnDemand()`. Credential plaintext is `username\0password`.
- scrypt is fed **raw code-unit bytes** (`pwd.size() * sizeof(CharT)`), so a `wchar_t` and a `char`
  container holding the "same" password derive different keys. Every real path uses
  `basic_secure_string<wchar_t>`. The crypto templates are explicitly instantiated for exactly two
  types — a new container type yields a *link* error, not a compile error.
- `saveVault()` **never re-encrypts credential packets**; changing the master password requires
  `rekeyVault()` (atomic `ReplaceFileW` swap after reload-and-verify).
- `loadVaultIndex()` fails fast on the first bad decrypt on purpose (record count would otherwise leak
  by timing). Don't turn it into a best-effort loop.

### Secret memory discipline

`locked_allocator` lays out `[NOACCESS guard | locked header | payload + 0xD0 canary | NOACCESS guard]`,
`VirtualLock`ed, kept `PAGE_NOACCESS` at rest and flipped to RW only inside an `RWGuard`. Canary
corruption calls `__fastfail(1)` — a corrupted secure buffer crashes the process by design.

The master password lives in exactly one place: `CredentialSession` (owned by `CredentialWorkspace`),
DPAPI-encrypted in place between uses. Access is only through the RAII `session.unlock()` → `Access`
window, and callers must check `access.ok()`. `VaultRecord::platform` is deliberately a plain
`std::string` — locked memory is reserved for actual secrets; don't "fix" it. `VaultListModel` exposes
only fixed-width bullet masks to QML; there is no password role.

Lifetimes across the app use **borrowed pointer + monotonic generation counter**
(`CredentialWorkspace::generation()`), not `shared_ptr`. Which mutators bump it is a documented
contract in `CredentialWorkspace.hpp` — keep that table true.

### Autofill: *when* vs *what*

Two different components decide these.

**When** — manual: `AppViewModel` → `IFillControl` → `TypeController::armFor` → `FillController::arm`
installs global `WH_MOUSE_LL`/`WH_KEYBOARD_LL`; Ctrl+Click fires it. Zero-gesture: extension → bridge →
`NavSnapshot` → `StagingController` (~100 ms poll) → `resolveStageRecord()` (`AutoStagePolicy.hpp`,
pure) → `FillController::armAuto`; a plain click fires it.

**What** — five probes fused by `FusionDecider`: Tier-1 short-circuit at confidence ≥ 0.95 (if the
Tier-1 hits agree), else a weighted Tier-2 vote requiring margin ≥ 0.7. Weights are compile-time
constants in `FusionDecider.cpp`. **Rule M5: `browser_extension` may never decide alone** — an on-disk
probe must corroborate. The auto path uses `decideDetailed()` and has strictly more gates than manual,
all evaluated *before* any decrypt (fresh bridge entry, directional host binding, per-document visit
token, foreground and click windows both owned by the bridge-validated browser PID).

Only one `FillController` can exist (the hooks are global, reached via a static atomic singleton); hook
callbacks run on the installing thread, so shared state is `std::atomic` and changes marshal back to
the Qt event loop. `BrowserBridge` is a **member** of `FillController` and must be declared before
`BrowserBridgeProbe`, which holds a raw pointer to it.

### Browser bridge

Page → `content.js` → `background.js` (MV3 service worker) → `chrome.runtime.connectNative("com.seal.fill")`
over stdio → `seal-browser.exe` → named pipe `\\.\pipe\seal-fill-<64 hex>` → `BrowserBridge` in
`seal.exe`. Both wire hops use 4-byte LE length + UTF-8 JSON, 4096-byte cap.

- `seal-browser.exe` is a **dumb relay that parses no JSON**; all schema validation is in `seal.exe`
  (hand-rolled bounded JSON parser in `BridgeMessage.cpp`; no schema key accepts a nested value, so
  it never actually recurses). Its `BridgeParseError` tokens
  and the `reason=`/`sub_reason=` accept-gate tokens are a **stable telemetry contract** — never rename.
- The reverse channel carries one directive, `fill_username`, and **never a password**.
- The pipe name rotates per launch; its DACL has exactly one ACE for the current user SID. Peer
  identity is the **SPKI SHA-256 thumbprint** of the Authenticode signer (`SignerUtils.hpp`, shared
  with the host binary).
- `SEAL_REQUIRE_SIGNED_PEER` (CMake option, default **OFF**): unsigned dev builds have an empty signer
  identity and therefore **accept every peer**. Release builds must set it `ON` and sign both binaries
  with the same publisher key.
- Host-side failures are only visible in `%LOCALAPPDATA%\seal\bridge-host-last-exit.log` — Chrome
  swallows the host's stderr. Each gate has a distinct exit code (7–13, plus 2–6 for pipe/handshake).
- `seal::visitAuthorizes()` **fails open** by design; fail-closed behaviour lives in the callers, and
  the auto and manual call sites deliberately differ. Don't "simplify" them into one.
- Browser secret release requires `platformMatchesHostForSecretRelease`: the stored Service field must
  contain a dot, and `hostsMatch` is **directional** (a parent authorizes its subdomains, never the
  reverse; a public suffix authorizes nothing). A label like `GitHub` gets no browser binding at all.
- `src/PublicSuffixTable.hpp` is **generated** — edit `scripts/public_suffixes.txt` and re-run
  `python scripts/generate_public_suffix_table.py`. There is no runtime PSL fetch.
- Runtime toggles are QSettings under `HKCU\Software\seal\seal`. The GUI writes two:
  `bridge/enabled` (default true) and `bridge/autostage` (default false, opt-in). Two more are
  read by `StagingController` and are **hand-set only** - nothing in the app writes them:
  `bridge/navAutostagePerSite` (default false; when true a host must be allow-listed before it can
  stage) and `bridge/navAllow/<hostKey>` (default false; one exact host per entry, no subdomain
  wildcard). There are no bridge environment variables.
- Register with `seal.exe install-browser-extension`. The Chrome extension ID
  `dfjclelhkideboildnjihgildihjjmdo` is hardcoded in two places (the `allowed_origins` writer and the
  host's `argv[1]` origin gate) that must change in lockstep. **Firefox is not supported** — half-built.
- Extension debugging: flip the two separate `DEBUG_LOGS` booleans (`background.js` → service-worker
  console, `content.js` → page console). In-app: `Bridge.runBridgeDiagnose()`, then Ctrl+Click for a
  per-probe report.

### Three unrelated things called "CLI"

`CliModes.{hpp,cpp}` = real argv subcommands (Qt-free, compiled into `seal_tests`); `main.cpp`
`Mode::Cli` (`--cli`) = interactive console REPL; `CliDispatch`/`CliHandler` = the embedded terminal
panel inside the GUI (`USE_QT_UI`, driven by the `Cli` context property). `seal.exe` is
console-subsystem, so CLI subcommands must be invoked on the exe directly, not through `run.bat`, to
keep stdout pipe-clean.

## Conventions

**When `CONTRIBUTING.md` and `.clang-tidy` disagree, `.clang-tidy` and neighbouring code win.**
CONTRIBUTING's naming table is a stale generic template (it claims PascalCase functions/namespaces).
Enforced: `lower_case` namespaces, `camelBack` functions/methods/params/locals, `CamelCase` types,
`m_PascalCase` members, `s_` statics, `g_` globals, `k`-prefixed constexpr and global constants.
Plain-data structs use unprefixed `camelCase` fields (no `m_`). Also stale: README says C++20 /
CMake 3.10 — `CMakeLists.txt` (C++23, CMake 3.20) is authoritative.

**Doc comments.** `.hpp`: `/** */`, `///`, `///<` and Doxygen `@` commands. `.cpp`: **plain `//` only**
— no `///`, no `/** */`, no `@` commands (sole exception: a `// @author Alex (https://github.com/lextpf)`
line). Moving prose from a header into a source file means stripping the markup (`@p x` becomes
`` `x` ``). Header type blocks use a fixed tag order: kind tag, `@brief`, `@author`, `@ingroup`, blank
`*`, prose. `@author` is file/type-level only. Banned: `@file`, `@returns`, `@defgroup`, `@addtogroup`,
`@internal`, and the `//!` / `/*! */` variants. `@ingroup` values come from the fixed list in
`doxide.yml`. `qml/`, `host/browser/` and `tests/` are outside the Doxygen pipeline.

**Style.** `#pragma once` (never include guards). Include groups own-header / project / third-party /
std, blank-line separated — clang-format uses `IncludeBlocks: Preserve` and sorts only *within* a
group, so group order is the author's job. Allman braces, 4 spaces, 100 columns (hand-wrap comment
bodies), braces mandatory on every control-flow body, no `using namespace` in headers. Exceptions are
enabled (`/EHsc`) and warnings are *not* errors (`/WX-`) — a clean build is not a clean lint. ASCII and
Mermaid diagrams and invariant tables in headers are load-bearing house style: update them alongside
the behaviour rather than deleting them.

**Logging** is logfmt via `seal::diag::joinFields`, shaped
`event=<dotted.scope.phase> result=<start|ok|fail> [reason=<token>]`, across the categories in
`Logging.hpp`. Hostnames and paths are never logged raw (`pathSummary()` emits only kind/length/
extension; the bridge probe fingerprints hostnames with SHA-256).

**Generated / untracked.** `assets/` is entirely gitignored (licensed SVGs and font), so **every build
must succeed with an empty `assets/`** — reference assets only via `file(GLOB ...)` or `if(EXISTS ...)`,
never a literal CMake path. `docs/*` and `site/*` are generated and ignored except `docs/main.html` (the
hand-authored MkDocs theme override) and `site/.gitkeep`; `mkdocs.yml`'s `nav:` is hand-maintained.

**Line endings** are LF except `*.bat` / `*.cmd` / `*.ps1`, which are committed CRLF. Don't normalise them.

**Commits** in this repo are a gitmoji prefix plus a short imperative subject, straight on `main`, with
**no `Co-Authored-By` trailers** — match the log.

## CI

Three `windows-2022` workflows on push/PR to `main`. They do **not** use the CMake presets or the
`.bat` scripts — raw `cmake -G "Visual Studio 17 2022" -A x64` with the stock `x64-windows` triplet. A
clang-format gate runs first (formats `src/` and `tests/`, fails if `git diff --name-only` is
non-empty); note it does **not** cover `host/browser/*.cpp`, which drifts unformatted, and clang-tidy
runs only locally inside `build.bat`. `sonar-project.properties` still carries the project's old key
`lextpf_sage`.
