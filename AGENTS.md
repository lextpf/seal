# Repository guidance

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

## Project and layout

seal is a Windows 10/11 x64 credential manager and encryption CLI, written in
C++23 with Qt6 QML/Quick, OpenSSL, and OpenCV. Windows security APIs are integral
to the design; the application does not support other platforms.

- `src/`: cryptography, vault/file operations, CLI, Qt view models, and native
  auto-fill. `main.cpp` dispatches modes; `QmlMain.cpp` composes GUI dependencies.
- `qml/`: views and reusable controls. Shared styling lives in `Theme.qml`.
- `host/browser/`: native messaging relay, built as target `seal_browser` and
  emitted as `seal-browser.exe` beside `seal.exe`.
- `extensions/browser/`: Chromium Manifest V3 companion. The Firefox manifest
  is a legacy draft and is not packaged.
- `tests/`: GoogleTest suites and fixtures; registration lives in
  `CMakeLists.txt`. Most tests exercise cores without Qt; some inspect UI source.
- `cmake/`, `CMakePresets.json`, `vcpkg.json`: toolchain and dependencies.
- `scripts/`, `doxide.yml`, `mkdocs.yml`: documentation generation and suffix data.
- `seal.qdocconf`, `docs/qml.qdoc`: standalone QML reference configuration and overview.

Read the relevant implementation and `CONTRIBUTING.md` before editing. Preserve
existing working-tree changes and keep edits scoped to the requested task.

## Build and validation

Run commands from the repository root in PowerShell. Prerequisites are Visual
Studio 2022 C++ tools, CMake 3.25+, and vcpkg. The local `default` and `static`
presets pin MSVC 14.43 through overlay triplets. Set `VCPKG_ROOT` to the installed
vcpkg directory and `VCPKG_BUILDTREES_ROOT` to a short writable path before a
direct configure, to avoid Qt build path limits. Use Release: local triplets
provide release-only dependencies.

On this workstation, run builds only with `build.bat --static --skip-tidy`
because of CPU instability. Keep compilation serial. Use a disposable source
copy for full pipeline validation to preserve the active cache and formatting.

```powershell
cmake --preset default
cmake --build --preset default
ctest --preset default
```

For an already configured tree, build only the needed targets and run relevant
tests. `ENABLE_TESTS` defaults to `ON`; CTest discovers GoogleTest cases.

```powershell
cmake --build build --config Release --target seal_tests
ctest --test-dir build -C Release --output-on-failure
# Add -R 'SuiteName' to select relevant CTest cases.
```

- `default` is the dynamic local build, `static` uses static Qt/CRT, and `ci`
  uses the stock `x64-windows` triplet. These share `build/`; inspect the existing
  cache before switching presets or changing toolchains.
- `compile-db` configures a Ninja sidecar in `build-cdb/` for clangd/clang-tidy;
  it consumes installed dynamic dependencies with manifest installation disabled.
  Its configure checks the main cache triplets and installed root. Do not use it
  over a static dependency tree. Follow `build.bat`; do not build the sidecar.
- `build.bat` is a full pipeline: it rewrites C/C++ files throughout `src/` with
  clang-format, can clear the CMake cache, configures, runs clang-tidy, builds
  Release, and generates one Material site. `--skip-tidy` skips the lint gate.
  Doxide and `scripts/requirements-docs.txt` are required for full batch builds.
- `test.bat` builds `seal_tests` and runs the test executable directly. It does
  not configure CMake: without `build/CMakeCache.txt` it exits 1 and asks for
  `build.bat`. The workstation build restriction still applies.
- `run.bat` launches the Release GUI and waits for exit. Invoke
  `build/bin/Release/seal.exe` directly for CLI arguments and pipes.

Choose validation for the changed behavior. Use existing suites and add
regression coverage for meaningful behavior changes, especially crypto, vault,
URL binding, bridge authentication, and secret exposure. QML is compiled into
the application: rebuild `seal` and check the affected flow for UI changes.
For extension JavaScript, run `node --check` on each changed script and verify
the affected companion flow when feasible. Report checks run and any limitations;
documentation-only edits do not need an application rebuild.

## Architecture and security boundaries

- Keep QML focused on presentation. Domain decisions and command routing belong
  in C++ view models/controllers. `QmlMain.cpp` exposes `AppViewModel`, `Fill`,
  `Bridge`, `WindowVM`, and `Cli` and constructs owners before borrowers.
- `CredentialWorkspace` owns vault records and `CredentialSession` is the sole
  long-lived master-key owner. Preserve their thread affinity and lifetime
  contracts. Refresh row mappings after mutations, including save-time deletion
  compaction; generation checks alone do not cover every index change.
- Use existing locked buffers, secure strings, and scoped access/DPAPI guards
  for secrets. Keep plaintext lifetimes short, check access failures, and retain
  wiping and memory protection. Workers receive owned secure clones; use
  `AsyncRunner` for cancellation and delivery on the receiver's thread.
- Stored passwords must not be exposed through QML models or edit metadata.
  Keep secrets out of logs, diagnostics, and embedded CLI transcripts. Preserve
  the clipboard's scrub lifecycle. Use synthetic credentials in tests.
- Preserve authenticated encryption, bounded parsing/framing, process-handle
  pinning, origin checks, and peer verification. Extension-driven browser release
  (staging, username injection, staged password fill) depends on a valid site
  binding; display labels and public suffixes cannot authorize arbitrary sites.
  Ctrl+Click typing is authorized by the user's record choice and gesture and
  applies no site binding. Inspect `UrlBinding.hpp`, `BrowserBridge.*`, and host
  checks when changing the extension/bridge protocol.
- Production requires `SEAL_REQUIRE_SIGNED_PEER=ON` and both executables signed
  with the same publisher key. The default is `OFF` for unsigned development.
  Running `build.bat` after a custom configure can clear that cache option.

## Editing conventions

- Follow `.clang-format`: four spaces, Allman braces, 100-column limit, and
  preserved comment wrapping. Format only touched C++ files unless broader
  formatting is part of the task. Use `#pragma once` in headers.
- `CONTRIBUTING.md` and `.clang-tidy` disagree on some naming rules. Match the
  surrounding subsystem and inspect the lint settings before adding names;
  avoid unrelated renames. Common core conventions are namespace `seal`,
  PascalCase types, camelCase methods, and `m_`-prefixed class members.
- Keep ownership explicit with RAII and narrow scopes. Document public contracts
  in source comments, including lifetime, failure, and secret-handling details.
- Respect `.gitattributes`: C++/CMake/JSON/YAML/Python use LF, batch files CRLF.
- Update explicit CMake source/test/QML lists when adding files. SVG resources
  are globbed at configure time; reconfigure after adding assets. Licensed icons
  and fonts in ignored `assets/` are supplied separately.

## Generated files and documentation

Edit API documentation in source comments and generator/configuration inputs.
`docs/` and `site/` are generated except for authored `docs/main.html` and `docs/qml.qdoc`.
`seal.qdocconf` configures the standalone QML reference; `docs/qml.qdoc` is its module overview.
QML contracts use native QDoc comments at their declarations; follow the QML section
in `CONTRIBUTING.md`. Run an already installed Qt 6 QDoc separately when needed:

```powershell
qdoc seal.qdocconf
```

QDoc reads the explicitly listed QML and `.qdoc` files and writes `build/qdoc/html/`.
Normal builds do not install or run QDoc. Do not add LLVM or Qt Tools to the
application dependency graph for documentation. Keep generated QDoc output out
of commits and application packaging.

The C++ documentation stage order is:

```powershell
doxide build
python scripts/_promote_subgroups.py
python scripts/_clean_docs.py
mkdocs build --clean
```

`src/PublicSuffixTable.hpp` is generated. Update `scripts/public_suffixes.txt`
or the generator template, then run
`python scripts/generate_public_suffix_table.py`. The application uses this
compiled snapshot without a runtime suffix-list fetch. Keep build output,
generated documentation, private assets, vault data, and signing material out
of changes intended for commit.
