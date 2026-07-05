# Contributing Guide

This guide defines contribution standards for the project’s human authors, co-authors, and AI agents acting as contributing entities.

Formatting is enforced by `.clang-format`. Contributors should run the formatter instead of manually debating whitespace, wrapping, brace placement, pointer alignment, or similar layout rules.

---

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Build the project with `.\build.bat`.
4. Before submitting changes, format modified C++ files.

---

## Language & Build

|            Item | Standard                         |
|-----------------|----------------------------------|
|        Language | C++23 (`CMAKE_CXX_STANDARD 23`)  |
|        Compiler | MSVC 2022 (primary)              |
|    Build system | CMake 3.10+                      |
| Package manager | vcpkg                            |
|         Testing | Google Test with CTest discovery |

---

## Core Principle

Prefer code that is:

- easy to read
- easy to review
- easy to debug
- easy to extend safely

Consistency matters more than personal preference.

---

## What `clang-format` Already Covers

The repository formatter already defines the mechanical style for C++ source, including:

- indentation and tabs/spaces
- brace layout
- constructor initializer formatting
- pointer/reference alignment
- spacing around control statements
- include sorting behavior
- wrapping/alignment of arguments, parameters, and comments

Do not restate or fight these rules in review. Run the formatter and move on.

---

## Naming Conventions

| Element                          | Style                                       | Examples                                                  |
|----------------------------------|---------------------------------------------|-----------------------------------------------------------|
| Files                            | PascalCase                                  | `Logger.hpp`, `RingBuffer.cpp`                            |
| Classes                          | PascalCase                                  | `Logger`, `Texture`, `ResourceManager`                    |
| Structs (plain data)             | PascalCase                                  | `Color`, `Vec2`, `Particle`                               |
| Enums                            | PascalCase                                  | `enum class LogLevel`, `enum class BlendMode`             |
| Enum values                      | PascalCase                                  | `LogLevel::Warning`, `BlendMode::Additive`                |
| Functions / Methods              | PascalCase                                  | `LoadTexture()`, `Logger::Write()`                        |
| Namespaces                       | PascalCase                                  | `Rendering`, `MathUtils`                                  |
| Local variables                  | camelCase                                   | `itemCount`, `deltaTime`, `isReady`                       |
| Parameters                       | camelCase                                   | `int itemCount`, `const std::string& filePath`           |
| Class member variables           | `m_` + PascalCase                           | `m_Buffer`, `m_Window`, `m_ItemCount`                     |
| Struct fields (plain data)       | camelCase, no prefix                        | `position`, `velocity`, `lifetime`                        |
| Macros / constants               | UPPER_SNAKE_CASE                            | `MAX_RETRIES`, `DEFAULT_TIMEOUT`                          |
| File-local constants             | UPPER_SNAKE_CASE, in an anonymous namespace | `constexpr int MAX_CONNECTIONS = 64;`                     |
| Compile-time constants           | `static constexpr`                          | `static constexpr int MAX_ITEMS = 256;`                   |
| Type aliases                     | PascalCase via `using`                      | `using EntityId = std::uint32_t;`                         |
| Global mutable state             | avoided (no `g_` prefix)                    | prefer file-local `constexpr`; see **Scoping & Lifetime** |

### Struct fields (plain data)

Plain structs used as passive data holders (value types, POD aggregates) use **unprefixed `camelCase`** fields (no `m_`, no methods, no invariants):

```cpp
struct Particle
{
    Vec2 position{};       ///< Current world position.
    Vec2 velocity{};       ///< Units moved per second.
    float lifetime{1.0f};  ///< Seconds of life remaining.
};
```

The `m_` prefix is reserved for the private members of behavior-bearing **classes**; plain-data structs never use it.

### Prefer named data over positional data

Prefer small structs with named fields over `std::pair`, `std::tuple`, or multi-value conventions that rely on positional meaning.

Use tuples only when the meaning is already obvious and local.

---

## Source File Organization

### Header files

Every header starts with `#pragma once`. Do not use include guards.

```cpp
#pragma once
```

### Include order

Group includes in this order, separated by a blank line between groups:

1. Corresponding header (`.cpp` files only)
2. Project headers
3. External / third-party headers
4. Standard library headers

Keep includes minimal, explicit, and local to actual usage.

### Forward declarations

Prefer including the real dependency over relying on forward declarations.

Use forward declarations only when they provide a clear benefit, such as breaking a circular dependency or reducing heavy include cost in a stable interface.

Do not use forward declarations that make ownership, inheritance, or required type completeness unclear.

### Inline definitions

Only define functions inline when they are genuinely small and benefit from being in the header.

Long or non-trivial implementations belong in `.cpp` files.

---

## Scoping & Lifetime

### Namespaces

* Never use `using namespace` in header files.
* In `.cpp` files, limit `using` directives to narrow scopes.
* Prefer `using std::string;` over `using namespace std;` when local aliasing is helpful.

### Local variables

* Declare variables in the narrowest practical scope.
* Initialize variables when declared.
* Do not separate declaration from first meaningful value unless there is a clear reason.
* Prefer loop-local variables inside the loop statement.

### Internal linkage

Functions, constants, and helpers used only within one translation unit should have internal linkage.

Prefer an unnamed namespace in `.cpp` files for file-local helpers.

```cpp
namespace
{
    float ComputeWeight(float x)
    {
        return x * x;
    }
}
```

### Static and global storage

Avoid non-trivial global state.

Rules:

* prefer `constexpr` or `constinit` where applicable
* prefer function-local statics over namespace-scope mutable singletons
* objects with static storage duration should be trivially destructible unless there is a strong reason otherwise
* global strings should usually be string literals or `std::string_view`, not dynamically initialized `std::string`

---

## Control Flow

### Always use braces

Use braces for all control-flow bodies, even single statements.

This is a project rule even if formatting could make a one-liner look acceptable.

### Prefer early exits

Reduce nesting when possible:

* return early on invalid state
* continue early in loops
* keep the main path visually obvious

### Switch statements

* Prefer `enum class` over unscoped enums.
* Handle all enumerators explicitly when practical.
* Use `default` only when it is actually desired behavior, not as a way to suppress missing-case thinking.

---

## Classes & Types

### Struct vs. class

Use `struct` for passive data containers with public fields and no invariants.

Use `class` for types with invariants, encapsulation, ownership, or behavior.

### Constructors

* Avoid doing heavy work in constructors when failure is possible.
* Avoid virtual dispatch in constructors and destructors.
* If initialization can fail meaningfully, prefer a factory or an `Initialize()` step.

### Explicit conversions

Mark single-argument constructors and conversion operators `explicit` unless implicit conversion is clearly intended and beneficial.

Copy and move constructors are exempt.

```cpp
explicit Texture(const std::string& path);
```

### Copy/move behavior

Be explicit about ownership semantics.

A type should clearly communicate whether it is:

* copyable
* move-only
* neither copyable nor movable

Delete or default the relevant operations intentionally. Do not leave semantics ambiguous.

```cpp
Texture(Texture&& other) noexcept;
Texture& operator=(Texture&& other) noexcept;
Texture(const Texture&) = delete;
Texture& operator=(const Texture&) = delete;
```

### Operator overloading

Only overload operators when behavior is obvious, conventional, and unsurprising.

Do not overload operators with unusual semantics. Never overload:

* `&&`
* `||`
* `,`
* unary `&`

---

## Functions

### Prefer clear interfaces

* Prefer return values over output parameters.
* Keep parameter lists short and meaningful.
* Put inputs before outputs.
* Prefer strong, descriptive types over ambiguous booleans or loosely related parameter packs.

### Parameter guidance

* cheap input values: pass by value
* non-cheap input values: pass by `const T&`
* output or in/out values: pass by `T&`
* optional input: `const T*` or `std::optional<T>`
* optional output: `T*`

Use raw pointers to express optionality or non-ownership, not ownership transfer.

### Boolean parameters

Avoid multiple boolean parameters in one function signature.

This is hard to read:

```cpp
CreateWidget(true, false, true);
```

Prefer an options struct, enum flags, or separate functions when intent is not obvious.

### Function size

Keep functions focused.

A function that needs multiple screens, many nested branches, or several unrelated responsibilities should usually be split.

---

## Ownership & Resource Management

### Ownership must be obvious

Use types to communicate ownership.

* `std::unique_ptr` for exclusive ownership
* `std::shared_ptr` only when shared lifetime is genuinely required
* raw pointers and references for non-owning access
* references when null is not valid
* pointers when null is a meaningful state

### `std::shared_ptr` is not a default

Use `std::shared_ptr` only with clear justification. Shared ownership makes lifetime harder to reason about and can hide architecture problems.

Be especially careful about cycles.

### RAII first

Prefer RAII-based resource management over manual acquire/release patterns.

If a type owns a resource, make cleanup automatic and local to the type.

---

## Error Handling

### Choose one clear strategy per API

Use the most suitable mechanism for the layer:

* assertions for programmer errors and impossible states
* return values / `std::optional` / expected-style patterns for normal recoverable failure
* exceptions only where the project or subsystem explicitly uses them

Do not mix multiple error-handling strategies in the same small API without a good reason.

### Assertions

Use assertions to document invariants and programmer assumptions, not user-driven runtime conditions.

An assertion should mean: if this fails, the code is wrong.

---

## Comments & Documentation

Documentation comments are written for a **Doxygen-style documentation generator** (e.g. Doxygen or Doxide) that parses `@`-command Javadoc comments. The house style is deliberately **split between headers and sources**; follow it consistently, because a de-sync is easy to introduce. `clang-format` does **not** reflow comment text, so keep every comment body within the project's column limit yourself.

### The header/source split (the core rule)

|                       | `.hpp`                                                  | `.cpp`                                            |
|-----------------------|---------------------------------------------------------|---------------------------------------------------|
| Doc-comment styles    | `/** … */` blocks, `///` one-liners, `///<` trailing    | plain `//` only                                   |
| Doxygen commands      | yes (`@brief`, `@param`, `@ingroup`, …)                 | **no** — with a single exception: `@author`       |
| `@author`             | file/type-level, `[NAME] (https://github.com/[USER])`   | optional `// @author <Name> (<url>)` line         |

### General comment rule

Comment the reason, constraint, or non-obvious behavior. Do not comment what the code already says plainly. Preserve ASCII diagrams and worked-example traces in algorithm-heavy code — they are house style, not clutter.

Bad:

```cpp
count++; // Increment count
```

Better:

```cpp
count++; // Includes the sentinel slot reserved during parsing.
```

### Where documentation lives

* Header files: documentation for the public-facing API (types, functions, members).
* Source files: implementation notes for non-obvious logic.

---

### Header (`.hpp`) documentation

#### Block vs. one-line form

* A doc comment that spans **more than one line** is a Javadoc **block**: `/**` on its own line, a leading ` * ` on every continuation line, a bare ` *` for blank separator lines, and ` */` to close.
* A doc comment that fits on **one physical line** uses `///` (e.g. a lone `/// @brief …` above a simple declaration, or a group marker).
* Use only these two styles in headers. Do **not** use the `//!` or `/*! */` "bang" variants.

```cpp
/// @brief Reset the buffer to its empty state.
void Clear();

/**
 * @brief Resize the buffer, preserving existing contents.
 * @param newSize   Desired capacity, in elements.
 * @param zeroFill  Whether newly added slots are zero-initialized.
 */
void Resize(std::size_t newSize, bool zeroFill);
```

#### File / type header block

The block documenting a header's primary type (or namespace) uses a **fixed tag order**:

1. **Kind tag** — `@struct Name`, `@class Name`, or `@enum Name`. Present when the header defines one primary type; **omit** it for namespace / free-function headers, which lead with `@brief`.
2. `@brief` — a one-line summary ending in a period.
3. `@author [NAME] (https://github.com/[USER])` — the same attribution string everywhere. **File / type-level only**; never repeated on a function, method, or member.
4. `@ingroup <Module>` — one of the modules your project defines (see below).
5. a blank ` *`, then prose.

```cpp
/**
 * @struct Color
 * @brief 8-bit RGBA color.
 * @author [NAME] (https://github.com/[USER])
 * @ingroup <Module>
 *
 * Plain data struct: a flat aggregate with no invariants, usable directly as
 * a value type. Blending helpers live in the free functions in ColorMath.hpp.
 *
 * @see ColorMath
 */
```

A namespace / free-function header drops the kind tag and leads with `@brief`:

```cpp
/**
 * @brief Pure, dependency-free 2D vector math helpers.
 * @author [NAME] (https://github.com/[USER])
 * @ingroup <Module>
 *
 * Each function is a stateless free function operating on plain values, with
 * no global or GPU state.
 */
```

Do **not** use `@file` — leave file identity implicit.

#### Modules (`@ingroup`)

Every documented entity is grouped under a module with `@ingroup <Module>`. Modules are declared **once** — each as an `@addtogroup <Id> <Title>` block in a single group-definitions header — and every other file only *references* them with `@ingroup`. Never add a new `@addtogroup` outside that one header.

Choose the module by **subsystem role, not filename**: a rendering helper belongs to the rendering module even when its filename names the feature it serves rather than the module.

#### Function / method documentation

A `/** */` block: `@brief` first (it may reference `@p param` / `@ref Symbol`), a blank line, prose, then `@param` (name + description, continuation lines aligned under the description) and `@return`. **No `@author`.** The spelling is `@return`, never `@returns`.

```cpp
/**
 * @brief Linearly interpolate between @p a and @p b by @p t.
 *
 * @p t is clamped to [0, 1], so values outside that range saturate to the
 * nearest endpoint.
 *
 * @param a  Start value, returned when @p t is 0.
 * @param b  End value, returned when @p t is 1.
 * @param t  Blend factor in [0, 1].
 * @return   The interpolated value.
 */
float Lerp(float a, float b, float t);
```

#### Members and enum values

Document a struct field or enumerator **inline with a trailing `///<`** when the text fits on the member's line. `///<` is the **only** trailing style this guide uses — not `/**< */`, `//!<`, or `/*!< */`.

```cpp
struct Color
{
    std::uint8_t r{0};    ///< Red channel.
    std::uint8_t g{0};    ///< Green channel.
    std::uint8_t b{0};    ///< Blue channel.
    std::uint8_t a{255};  ///< Alpha channel (255 = opaque).
};

enum class LogLevel
{
    Debug,    ///< Verbose developer diagnostics.
    Info,     ///< Normal operational messages.
    Warning,  ///< Recoverable problems worth attention.
    Error     ///< Failures that abort the current operation.
};
```

When a field description is too long for a trailing `///<`, use **leading `///` lines** above the member instead. This is the one place a `///` comment may span multiple lines; never put a `/** */` block on an individual field or enumerator.

```cpp
/// Master enable flag. When false the renderer skips the entire post-processing
/// chain (blur, bloom, tone-mapping) and presents the raw scene texture
/// unmodified. Toggled at runtime from the developer console.
bool postProcessEnabled{true};
```

#### Grouping related members

Group members with a `@name` section fenced by `@{` … `@}`. The **opener** is either a `/** … @{ */` block (when it carries `@name`/`@brief`) or two one-line `/// @name` + `/// @{` lines. The **closer** is always a single physical line — `/// @}` (a one-line `/** @} */` is also acceptable). Never expand a closer into a multi-line block, and balance every `@{` with a `@}`.

```cpp
/**
 * @name Window state
 * @{
 */
Window* m_Window = nullptr;  ///< Owned OS window handle.
int m_Width = 1280;          ///< Client-area width, in pixels.
int m_Height = 720;          ///< Client-area height, in pixels.
bool m_Initialized = false;  ///< Whether creation succeeded (for safe teardown).
/// @}
```

#### Command vocabulary

Documentation commands to use where useful:

`@brief`, `@author`, `@ingroup` (plus `@addtogroup` in the group-definitions header only), `@struct` / `@class` / `@enum`, `@param`, `@return`, `@tparam`, `@pre` / `@post`, `@note` / `@warning`, `@p` / `@c` / `@ref` / `@see`, `@par <Title>`, `@name` / `@{` / `@}`, `@code` / `@endcode` (and `@code{.cpp}`), `@verbatim` / `@endverbatim` for ASCII diagrams, and LaTeX math `@f[ … @f]` / inline `@f$ … @f$`.

Do **not** use: `@file`, `@returns`, `@union`, `@short`, `@defgroup`, `@def`, `@fn`, `@var`, `@internal`.

---

### Source (`.cpp`) documentation

* **`//` line comments only.** No `/** */` blocks, no `///` (not even trailing `///<`), and no Doxygen commands (`@brief`, `@param`, `@return`, `@ingroup`, `@par`, `@note`, …).
* The **one exception** is an authorship line, written as a plain `// @author <Name> (<url>)` (e.g. `// @author [NAME] (https://github.com/[USER])`). Keep existing attributions as-is; don't rewrite them.
* When moving header prose into a `.cpp`, **strip the Doxygen markup**: `@p name` → `name` (or backtick-quote it: `` `name` ``), `@c Buffer{}` → plain `Buffer{}`, `@ref Foo` → `Foo`. Backtick-quoting an identifier is the house substitute for `@c` / `@p` inside `//` comments.
* A file-header contract block is optional: complex files (algorithms, pipelines) carry a top-of-file `//` summary — often with an ASCII diagram or worked example — while simpler files go straight from includes to code. Either way, add a one-line `//` intent comment above a function whenever its purpose isn't self-evident.

```cpp
// RingBuffer - fixed-capacity FIFO used by the audio mixer.
//
// @author [NAME] (https://github.com/[USER])
// Reads and writes advance independent cursors modulo the capacity. The
// buffer is treated as full when the write cursor sits one slot behind the
// read cursor, so exactly one slot is always reserved to tell full from empty.
```

```cpp
// Clamp the requested gain to [0, 1] before applying the fade curve.
void SetGain(Channel& channel, float gain)
```

### TODO comments

Use `TODO` only for real follow-up work, not vague reminders.

Make them specific and actionable:

```cpp
// TODO: Replace with a spatial hash once the element count exceeds 10k.
```

---

## API Design Preferences

### Prefer expressive types

Use enums, structs, aliases, and dedicated small types when they make interfaces clearer.

Prefer:

```cpp
struct LoadOptions
{
    bool allowCache;
    bool validateSchema;
};
```

over:

```cpp
bool Load(bool allowCache, bool validateSchema);
```

### Prefer compile-time guarantees

When a rule can be enforced by the type system, `constexpr`, `constinit`, or RAII, prefer that over comments and conventions.

### Avoid hidden work

Functions should not unexpectedly:

* allocate heavily
* block for long periods
* mutate unrelated global state
* transfer ownership invisibly

Make expensive or stateful behavior visible in the API.

---

## Testing

All non-trivial behavior changes should include tests or a clear reason why tests are not practical.

Add or update tests when you change:

* parsing logic
* math/transform code
* serialization
* state machines
* public APIs
* bug fixes with reproducible behavior

A bug fix without a regression test should be the exception, not the norm.

---

## Pull Requests

### Scope

Keep pull requests focused.

Do not mix unrelated refactors, formatting-only churn, feature work, and bug fixes in the same PR unless there is a strong reason.

### What to include

A good PR should explain:

* what changed
* why it changed
* any important tradeoffs
* how it was validated

### Reviewer expectations

Reviewers should prioritize:

* correctness
* maintainability
* API clarity
* architecture fit
* test coverage

Do not spend review time re-litigating rules that are already enforced automatically by tooling.

---

## AI-Assisted Contributions

AI assistance is allowed, but the contributor remains fully responsible for the submitted code.

If you use AI, you must still ensure that the result is:

* correct
* project-consistent
* buildable
* testable
* understandable by a human reviewer

Do not submit generated code you do not understand.

Pay extra attention to:

* hallucinated APIs
* incorrect ownership assumptions
* fake includes
* wrong engine/library types
* missing edge cases
* overly generic comments or documentation