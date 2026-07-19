# Repository Guidelines

## Rules

Ask when unclear. If intent, architecture, or requirements are ambiguous, ask before coding.

Flag uncertainty. If an approach, dependency, or technical detail is uncertain, say so before proceeding.

Challenge bad direction. If my request conflicts with settled practice or likely long-term maintainability, point it out and suggest a better path.

End with omissions. After each task, state what you changed and what you intentionally did not do.

## Documentation

Document the code using ASD-STE100-inspired Simplified Technical English: use short, direct sentences, one term per concept, active voice, explicit conditions, and avoid idioms, unnecessary synonyms, or ambiguous wording. Focus documentation on intent, constraints, side effects, and non-obvious behavior;

## Project Structure & Module Organization

`src/` contains the C++23 application, cryptography, vault, controllers, and view models; related `.hpp` and `.cpp` files stay paired. `qml/` contains the Qt Quick interface. Browser integration is split between the native-messaging host in `host/browser/` and the WebExtension in `extensions/browser/`. GoogleTest suites live in `tests/`, with shared helpers in `test_helpers.hpp` and sample data in `tests/fixtures/`. Build configuration is in `CMakeLists.txt`, `CMakePresets.json`, `cmake/`, and `vcpkg.json`; documentation tooling is under `scripts/`, `doxide.yml`, and `mkdocs.yml`. Treat `build/`, `build-cdb/`, and `site/` as generated output.

## Build, Test, and Development Commands

- `\.\build.bat` formats C++ sources, configures vcpkg/CMake, runs clang-tidy, builds Release, and generates documentation. Review formatting changes before committing.
- `\.\build.bat --skip-tidy` skips static analysis; `--static` produces the portable `/MT` build.
- `\.\test.bat` builds `seal_tests` and runs all GoogleTest cases.
- `cmake --workflow --preset default` runs the preset configure/build/test workflow when `VCPKG_ROOT` is set.
- `\.\run.bat` launches `build\bin\Release\seal.exe` with diagnostic output attached.

Development targets Windows 10/11 with Visual Studio 2022, MSVC v143, CMake, and vcpkg.

## Coding Style & Naming Conventions

Run `clang-format` and honor `.clang-tidy`. C++ uses four spaces, no tabs, Allman braces, and a 100-column limit. Match neighboring code: types and C++ filenames use `PascalCase`; functions, parameters, locals, and plain-struct fields use `camelCase`; class members use `m_PascalCase`; macros use `UPPER_SNAKE_CASE`. Prefer RAII, explicit ownership, early exits, and braces on every control-flow body. Follow `CONTRIBUTING.md` for documentation and API guidance.

## Testing Guidelines

Name suites `tests/test_<feature>.cpp` and cases as `TEST[_F](FeatureTest, Behavior)`. Add regression coverage for bug fixes and tests for parsing, serialization, state machines, security boundaries, and public API changes. There is no numeric coverage threshold; explain any non-trivial untested behavior in the PR. Use synthetic credentials and temporary directories—never real vaults, exports, certificates, or signing keys.

## Commit & Pull Request Guidelines

Recent commits use one category emoji plus a concise imperative subject, for example `🐛 Report SendInput failure` or `📝 Document release signing`. Keep commits and PRs focused. PR descriptions must state what changed, why, tradeoffs, and validation; link relevant issues and include screenshots or recordings for visible QML changes. Confirm formatting, Release build, and tests before requesting review.
