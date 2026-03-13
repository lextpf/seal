# Contributing Guide

This guide defines contribution standards for the project's authors and co-authors, with or without AI assistance.

Formatting is enforced by `.clang-format`. Contributors should run the formatter instead of manually debating whitespace, wrapping, brace placement, pointer alignment, or similar layout rules.

---

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Build the project with `.\build.bat`.
4. Before submitting changes, format modified C++ files and run the test suite.

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

|                Element |          Style          | Examples                                 |
|------------------------|-------------------------|------------------------------------------|
|                  Files |       PascalCase        | `Renderer.h`, `Settings.cpp`             |
|      Classes / Structs |       PascalCase        | `Game`, `TierDefinition`                 |
|                  Enums |       PascalCase        | `enum class Direction`                   |
|            Enum values |       PascalCase        | `Direction::Up`                          |
|    Functions / Methods |       PascalCase        | `Initialize()`, `LoadFromFile()`         |
|             Namespaces |       PascalCase        | `Settings`, `Renderer`                   |
|        Local variables |        camelCase        | `deltaTime`, `tileX`                     |
|             Parameters |        camelCase        | `float distance`                         |
|       Member variables |    `m_` + PascalCase    | `m_Window`, `m_Width`                    |
|       Static variables |       `s_` prefix       | `s_Count`                                |
|       Global variables |       `g_` prefix       | `g_Device`                               |
|     Constants / Macros |    UPPER_SNAKE_CASE     | `MAX_DISTANCE`, `TWO_PI`                 |
| Compile-time constants |   `static constexpr`    | `static constexpr int SIZE = 16;`        |
|           Type aliases | PascalCase with `using` | `using IndexMap = std::unordered_map<>;` |

### Struct members

Plain structs used as passive data holders use `camelCase` with no prefix:

```cpp
struct Particle
{
    glm::vec2 startPosition;
    glm::vec2 moveDirection;
    float maxLifetime;
};
````

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

### General comment rule

Comment the reason, constraint, or non-obvious behavior.

Do not comment what the code already says plainly.

Bad:

```cpp
count++; // Increment count
```

Better:

```cpp
count++; // Includes the sentinel slot reserved during parsing.
```

### Where documentation lives

* Header files: documentation for public-facing APIs
* Source files: implementation notes for non-obvious logic only

### Public API documentation

Document public classes, enums, functions, and non-trivial members in headers.

Prefer concise, useful documentation over boilerplate.

Document:

* purpose
* important parameters
* return value when non-obvious
* preconditions/postconditions when relevant
* ownership or lifetime expectations when relevant

### Documentation style

Supported comment styles in headers:

```cpp
/** ... */
/*! ... */
/// ...
//! ...
```

Trailing member/enum docs:

```cpp
/**< ... */
/*!< ... */
///< ...
//!< ...
```

In `.cpp` files`, use `//` comments only.

### Doxide guidance

Use Markdown freely inside documentation comments.

Prefer these commands where useful:

* `@param`
* `@tparam`
* `@return`
* `@pre`
* `@post`
* `@throw`
* `@see`
* `@ingroup`

We still use `@brief`, `@class`, `@struct`, `@union`, `@enum`, and `@namespace` for readability and forward-compatibility.

Do not use: `@short`, `@file`, `@defgroup`, `@def`, `@fn`, `@var`, `@internal`.

### Enum/member documentation

Use trailing documentation for short enum/member notes:

```cpp
enum class ParticleStyle
{
    Stars,   ///< Twinkling star points
    Sparks,  ///< Fast, erratic fire-like sparks
    Wisps,   ///< Slow, flowing ethereal wisps
};
```

### TODO comments

Use `TODO` only for real follow-up work, not vague reminders.

Make them specific and actionable:

```cpp
// TODO: Replace with spatial hash once tile count exceeds 10k.
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
