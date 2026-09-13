# CLAUDE.md

## Rules

1. Ask when unclear. If intent, architecture, or requirements are ambiguous, ask before coding.
2. Flag uncertainty. If an approach, dependency, or technical detail is uncertain, say so before proceeding.
3. Challenge bad direction. If my request conflicts with settled practice or likely long-term maintainability, point it out and suggest a better path.
4. End with omissions. After each task, state what you changed and what you intentionally did not do.

## Documentation

Four rules everywhere in comments and docstrings.

1. What, why, how, in that order, and only as much as is needed. In prose, never restate the signature; add units, ranges and nullability, or say nothing.
2. Sentence case. Capitalize sentence starts, command descriptions, and section titles after icons. Preserve the case of commands, identifiers, URLs, and icon shortcodes.
3. No archaeology. Do not write prose about the history of a class throughout the life cycle of this repository or what an earlier implementation did.
4. Concise. Short sentences, active voice, one idea each, one term per concept per file. A set of cases wants a table; a flow wants a diagram.

Document the code using ASD-STE100-inspired Simplified Technical English: use short, direct sentences, one term per concept, active voice, explicit conditions, and avoid idioms, unnecessary synonyms, or ambiguous wording. Focus documentation on intent, constraints, side effects, and non-obvious behavior;
Write for an engineer who knows the language but not this system.
Read [CONTRIBUTING.md](CONTRIBUTING.md) before writing or reviewing code documentation.

## Project

`seal` is a **Windows-only** (10/11, x64) AES-256-GCM credential manager and encryption utility:
C++23 + Qt6/QML + OpenSSL 3, built with CMake presets over vcpkg manifest mode. It hard-errors at
configure time on other platforms, and refuses to *run* in a remote session.

Three artifacts ship together and must stay in one directory:

| Artifact | Built from | Role |
|---|---|---|
| `seal.exe` | `src/` + `qml/` | GUI (QML) **and** the argv CLI - one binary, mode chosen in `main.cpp` |
| `seal-browser.exe` | `host/browser/` | Qt-free native-messaging relay; browser stdio <-> named pipe |
| `seal companion` | `extensions/browser/` | MV3 extension (unpacked, loaded by the user) |

## Commands

Everything runs from a normal shell; `build.bat` calls `vcvars64.bat` itself.

```powershell
.\build.bat                 # format -> configure -> clang-tidy -> Release build -> docs
.\build.bat --skip-tidy     # same, without the blocking lint gate (fastest full build)
.\build.bat --static        # /MT single-file build; skips tidy (see Gotchas)
.\run.bat                   # launch the Release GUI from its own directory
```

Faster inner loop (skips format, tidy and docs):

```powershell
cmake --preset default
cmake --build build --config Release --target seal          # GUI+CLI binary
cmake --build build --config Release --target seal_tests    # test binary only
```

Tests:

```powershell
ctest --test-dir build -C Release --output-on-failure       # use this in automation
build\bin\Release\seal_tests.exe --gtest_filter=VaultRoundtripTest.*          # one suite
build\bin\Release\seal_tests.exe --gtest_filter=FusionDeciderTest.Tier1ShortCircuitsAtThreshold
ctest --test-dir build -C Release -R DirectoryCryptoTest     # ctest-level filter
```

Lint one file the way the pipeline does (needs `build-cdb/`, see Gotchas):

```powershell
cmake --preset compile-db                                   # configure only, never built
clang-tidy --quiet --header-filter="[/\\]Vault\.hpp$" -p build-cdb src\Vault.cpp
```

Docs - four stages in this order; `_promote_subgroups.py` must precede `_clean_docs.py` because the
clean step rewrites links that promotion creates:

```powershell
doxide build ; python scripts\_promote_subgroups.py ; python scripts\_clean_docs.py ; mkdocs build
```

CLI surface of the built binary: `seal.exe --help` (`encrypt`/`decrypt`/`gen`/`shred`/`hash`/
`verify`/`wipe`/`rekey`/`list`/`get`/`import`/`export`/`install-browser-extension`, plus `-e`/`-d`
text modes, `-c` REPL, `-u` GUI).

## Architecture

### Startup and ownership

`main.cpp` parses argv into a `Mode` and either runs a CLI mode or calls `RunQMLMode`
(`QmlMain.cpp`). The composition contract documented in `QmlMain.hpp` is load-bearing:
**declaration order is destruction order**. Core objects (`CredentialWorkspace`, `AsyncRunner`,
`FillController`) are declared first so they outlive the ViewModels that borrow them, and
`QQmlApplicationEngine` is declared last so the QML tree dies before the objects it borrows.

Exactly **five** context properties form the entire C++ -> QML surface; no QML types are registered:

`AppViewModel` (command hub) · `Fill` (`TypeController`) · `Bridge` (`BridgeViewModel`) ·
`WindowVM` (`WindowController`) · `Cli` (`CliPanelViewModel`)

`WindowVM` is *not* named `Window` because that collides with QtQuick's type. QML binding mistakes
are invisible to both the compiler and `seal_tests`; they only surface in a runtime smoke test.

### Data and crypto layers

- `CredentialWorkspace` owns the record vector, the master-key `CredentialSession` and a generation
  counter; `VaultListModel` borrows the vector for QML, so the workspace must stay at one address.
- `Vault.cpp` implements the `.seal` file frame: hex text wrapping `magic "SVH2" | version | count`,
  then per record `platform packet + credential packet`, all lengths big-endian. Platform names are
  decrypted at load so the list can render; credential blobs stay sealed until accessed.
- `CryptoConfig.hpp` (`seal::cfg`) is the single source of packet framing: an 8-byte plaintext AAD
  header (`"seal"` magic + 4 KDF-parameter bytes) fed verbatim as GCM AAD, then salt(16) + IV(12) +
  ciphertext + tag(16). Every packet is self-describing, so KDF parameters come from the header
  rather than being assumed. Default scrypt costs 64 MiB **per packet**, so vault loads block - keep
  them off the UI thread.
- Secrets only ever live in `SecureString` / `secure_triplet16` over `LockedAllocator` (guard pages,
  `VirtualLock`, 0xD0 canary, `SecureZeroMemory` on release), with `ScopedDpapiUnprotect` opening
  DPAPI-wrapped regions for the narrowest possible scope.

### Autofill pipeline

Field classification fuses independent probes; no single signal can release a secret.

```
Win32StyleProbe ----+
UiaIsPasswordProbe -+--> FusionDecider --> Verdict (+tier-1/corroboration) --> FillController
UiaMetadataProbe ---+
BrowserBridgeProbe -+
```

`FusionDecider` short-circuits only on agreeing tier-1 hits (confidence >= 0.95), and the browser
bridge is explicitly forbidden from short-circuiting alone (M5), so a lying extension cannot force a
release; otherwise a weighted vote must clear a 0.7 margin. `StagingController` + `AutoStagePolicy`
implement zero-keystroke arming from navigation reports, gated per document by a visit token, so one
page load yields at most one username injection and one password fill.

### Browser bridge

`extensions/browser/{content,background}.js` -> `seal-browser.exe` (stdio native messaging) -> named
pipe `\\.\pipe\seal-fill-*` -> `BrowserBridge` inside `seal.exe`. The relay is deliberately dumb: it
forwards opaque frames and validates *nothing* about schema - `BridgeMessage.cpp` in `seal.exe` does
that. Peers authenticate by Authenticode signer identity (`SignerUtils.hpp`); with
`SEAL_REQUIRE_SIGNED_PEER=OFF` (default) an empty identity disables the check so unsigned dev builds
work, and the GUI shows an "Unsigned build" chip. `host/browser/main.cpp` documents its numbered exit
codes - read them before debugging a bridge failure. Only hostnames cross the pipe, never full URLs
or secrets, and `UrlBinding.hpp` plus the compiled-in Public Suffix snapshot decide which record may
bind to which host (public suffixes such as `co.uk` or `github.io` never authorize their tenants).

## Gotchas

- **`seal_tests` compiles only the Qt-free subset of `src/`.** Every `#ifdef USE_QT_UI` translation
  unit (`AppViewModel`, `FillController`, `StagingController`, `BrowserBridge`, `QmlMain`, ...) is
  absent from that target, so after touching one you must build the `seal` target - a green test run
  proves nothing about it. Some tests compensate by scanning sources as text through
  `SEAL_SOURCE_DIR` (`test_ui_secret_boundaries`, `test_credential_csv`, `test_process_pin`,
  `test_vault_rekey`); `test_ui_secret_boundaries` asserts no stored password can reach QML, so it
  catches MVVM-boundary regressions rather than compile errors.
- **`build.bat` wipes `build/CMakeCache.txt`** whenever the MSVC toolset is pinned, which is the
  default when 14.43 is installed. Any `-D` option from a manual configure - `SEAL_REQUIRE_SIGNED_PEER`
  above all - silently reverts to its default. Re-run `cmake --preset ... -D...` instead of
  `build.bat` when such an option matters.
- **`--static` skips clang-tidy on purpose.** `build-cdb/` is a Ninja sidecar that exists only to emit
  `compile_commands.json` (Visual Studio generators do not), and it shares `build/vcpkg_installed`
  with the default preset so vcpkg skips a full Qt6 rebuild. Regenerating it under the static triplet
  would replace dynamic Qt, so lint runs against the default build only.
- **`test.bat` never configures.** Without `build/CMakeCache.txt` it exits 1 and asks for
  `build.bat`. Use `ctest` or `seal_tests.exe` directly for automation.
- **`assets/` is gitignored in full** (Font Awesome Pro icons and the UI font are licensed). CI and
  any fresh clone build with an empty assets tree, so reference assets through `file(GLOB ...)` or
  `if(EXISTS ...)` in CMake - a literal asset path breaks CI. `docs/` and `site/` are generated and
  ignored as well, except the authored `docs/main.html` (MkDocs theme override) and `docs/qml.qdoc`
  (QDoc module overview).
- **GUI liveness signal:** `event=app.qml.load.ok` on stderr means the window is up;
  `app.qml.load.fail` exits 1. Exit code 1 is always a controlled refusal (QML failure, or
  `reason=remote_session_detected`); 57005 (0xDEAD) is the anti-debug kill. No log file is written -
  stderr is the whole record, in logfmt built by `Diagnostics.hpp`, which never emits raw paths or
  secrets.
- **Dynamic builds need their deployment tree.** `windeployqt` output plus `qt.conf` must sit beside
  `seal.exe`, and `seal-browser.exe` must share that directory or extension install refuses with
  `reason=host_exe_missing`. Launch from that directory (`run.bat` does this).
- **vcpkg is pinned and slow by necessity:** MSVC 14.43 (14.44 ICEs on Qt6 sources),
  `VCPKG_MAX_CONCURRENCY=1` (MSVC crashes building Qt6 in parallel), and a short
  `VCPKG_BUILDTREES_ROOT` (Qt6 paths overflow MAX_PATH). CI uses the separate `ci` preset with the
  stock `x64-windows` triplet so cached binaries are reused across PRs.
