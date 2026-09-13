# Contributing Guide

This guide defines contribution standards for the project's human authors, co-authors, and AI agents acting as contributing entities.

---

## Core Principle

Prefer code that is:

- easy to read
- easy to review
- easy to debug
- easy to extend safely

Consistency matters more than personal preference.

---

## Naming Conventions

| Element                          | Style                                       | Examples                                                  |
|----------------------------------|---------------------------------------------|-----------------------------------------------------------|
| Files                            | PascalCase                                  | `Logger.hpp`, `RingBuffer.cpp`                            |
| Classes                          | PascalCase                                  | `Logger`, `Texture`, `ResourceManager`                    |
| Structs                          | PascalCase                                  | `Color`, `Vec2`, `Particle`                               |
| Enums                            | PascalCase                                  | `enum class LogLevel`, `enum class BlendMode`             |
| Enum values                      | PascalCase                                  | `LogLevel::Warning`, `BlendMode::Additive`                |
| Functions / Methods              | PascalCase                                  | `LoadTexture()`, `Logger::Write()`                        |
| Namespaces                       | PascalCase                                  | `Rendering`, `MathUtils`                                  |
| Local variables                  | camelCase                                   | `itemCount`, `deltaTime`, `isReady`                       |
| Parameters                       | camelCase                                   | `int itemCount`, `const std::string& filePath`            |
| Class member variables           | `m_` + PascalCase                           | `m_Buffer`, `m_Window`, `m_ItemCount`                     |
| Struct fields                    | camelCase, no prefix                        | `position`, `velocity`, `lifetime`                        |
| Macros / constants               | UPPER_SNAKE_CASE                            | `MAX_RETRIES`, `DEFAULT_TIMEOUT`                          |
| File-local constants             | UPPER_SNAKE_CASE, in an anonymous namespace | `constexpr int MAX_CONNECTIONS = 64;`                     |
| Compile-time constants           | `static constexpr`                          | `static constexpr int MAX_ITEMS = 256;`                   |
| Type aliases                     | PascalCase via `using`                      | `using EntityId = std::uint32_t;`                         |
| Global mutable state             | avoided (no `g_` prefix)                    | prefer file-local `constexpr`; see **Scoping & Lifetime** |

### Struct fields

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

### Native QDoc for QML

QML reference comments use native QDoc syntax. This section takes precedence over
the shared carrier, annotation, and body-markup rules below for `.qml` declarations
and authored `.qdoc` inputs. Keep the same concise prose, sentence case, attribution,
100-column limit, and declaration placement.

Use `/*! ... */` with ` * ` continuation prefixes. A type block sits directly above the root
object and uses `\qmltype`, `\inqmlmodule`, and `\brief`. Put short member blocks directly
above declarations; QDoc derives property names and types from QML. Use an explicit
`\qmlproperty` for aliases.
Write attribution as an `Author:` sentence with a native QDoc link.
Use QDoc sections, tables, links, and code commands in these blocks.
Keep implementation notes as ordinary `//` comments.
See [Qt's QML documentation guide](https://doc.qt.io/qt-6/qtwritingstyle-qml.html) for the markup.

Add each documented QML file to `sources` in `seal.qdocconf`. `docs/qml.qdoc` declares the
`\qmlmodule`; keep its module name equal to the URI in `qt_add_qml_module` in `CMakeLists.txt`.
The configuration loads no Qt documentation indexes. Inherited Qt members are not in the
reference, and QDoc can report an unresolved base type such as `Button`.
See [Documentation](README.md#documentation) for the optional generation command.

### Universal documentation standard

All supported programming languages use the same documentation semantics,
annotation names, annotation order, prose style, section titles, tables, Material
icon shortcodes, and diagram conventions. Only the language-specific comment or
docstring delimiters change.

This is a repository house style for a **Doxygen-style documentation pipeline**.
Do not translate it into language-native documentation dialects such as C# XML
comments, Python `Args:` sections, Rust Markdown parameter headings, or JSDoc
`@returns`. Keep the shared annotations defined below.

Use sentence case in comments and docstrings, including command descriptions and
section titles after icons. Capitalize each new sentence. Preserve the case of
commands, identifiers, URLs, and icon shortcodes.

Keep every documentation line, including diagrams and tables, at or under 100
columns after its comment prefix is added.

### Core rule: The declaration/implementation split

Think in terms of the **canonical declaration** and the **implementation**, not in
terms of a particular filename extension.

| Target                                | Style              | Commands     | `@author`    |
|---------------------------------------|--------------------|--------------|--------------|
| Module/package/namespace/primary type | Structured block   | Yes          | Yes          |
| Callable at any visibility            | Structured block   | Yes          | Yes          |
| Field/property/variant/enum           | Short member docs  | Usually none | Usually none |
| Body note or noncanonical definition  | Plain line comment | No           | No           |

The canonical declaration is the one authoritative location for generated API
documentation. Do not duplicate the same contract on declarations, definitions,
implementations, overrides, partial types, generated bindings, or wrapper files.

Typical canonical locations are:

| Project shape           | Canonical documentation location                    |
|-------------------------|-----------------------------------------------------|
| C/C++ with headers      | Public header declaration                           |
| Header-only C/C++       | Header declaration                                  |
| Rust                    | Crate, module, trait, type, field, variant, or item |
| Java/Kotlin/C#/Swift    | Type or member declaration                          |
| JavaScript/TypeScript   | Exported declaration or canonical implementation    |
| Python                  | Module, class, function, or method docstring        |
| Go                      | Package, type, function, method, field, or value    |
| Script or configuration | Top-of-file contract or declared function/task      |

When a language has no header/source split, structured documentation goes directly
on the declaration and plain comments inside the body remain implementation notes.

### General comment rule

Comment the reason, invariant, constraint, ownership rule, failure behavior, unit,
or other non-obvious behavior. Do not restate syntax that the code already expresses
plainly.

Bad:

```text
count += 1  // Increment count.
```

Better:

```text
count += 1  // Includes the sentinel slot reserved during parsing.
```

Preserve useful ASCII diagrams, Mermaid diagrams, state-transition descriptions,
worked examples, formulas, and trace tables in algorithm-heavy code. They are part
of the house style, not clutter.

---

### Structured declaration documentation

#### Documentation carriers

Use the carrier native to the language while preserving the same annotation lines
and body layout.

| Language family | Overview/declaration carrier                     | Implementation |
|-----------------|--------------------------------------------------|----------------|
| C/C++           | `/** ... */`; declarations may use `///`, `///<` | `//`           |
| Javadoc-block   | `/** ... */`                                     | `//`           |
| Rust            | `/*! ... */` overview; `/** ... */` item         | `//`           |
| Python          | Module or member docstring                       | `#`            |
| Go/slash-line   | Consecutive `//` lines                           | `//`           |
| Hash-comment    | Consecutive `#` lines                            | `#`            |
| SQL/Lua         | Consecutive `--` lines                           | `--`           |
| HTML/XML        | `<!-- ... -->` where meaningful                  | Plain comment  |

Javadoc-block languages include Java, Kotlin, C#, JavaScript, TypeScript, QML,
and other languages whose configured parser accepts Javadoc-style blocks.
Hash-comment languages include Shell, PowerShell, CMake, YAML, and TOML.

A structured block uses one delimiter line, one content prefix per line, a bare
content prefix for blank separators, and one closing delimiter line.

```cpp
/**
 * @brief Reset the buffer to its empty state.
 */
```

For languages without a ` * ` continuation prefix, keep the same logical blank lines
and annotation order without adding decorative asterisks.

```python
"""
@brief Reset the buffer to its empty state.
"""
```

Do not force `///`, `/** */`, or trailing `///<` into a language whose documentation
parser does not associate that form with the declaration. The carrier may change;
the annotations and their meaning must not.

##### C and C++ adapter

For a split header/source API, structured public documentation lives in the header
and implementation notes live in the source file.

A documentation comment spanning more than one physical line uses a Javadoc block:
`/**` on its own line, ` * ` on every content line, a bare ` *` for a blank line,
and ` */` on its own line. A true one-line declaration comment uses `///` only for
entities that do not require a full function block.

Use trailing `///<` only for a short field or enumerator description. Do not use
`/**< */`, `//!<`, or `/*!< */`. Do not use `//!` or `/*! ... */` in C or C++.

##### Rust adapter

Use `/*! ... */` for a crate or module overview and `/** ... */` for an item, field,
or variant. Put each delimiter on its own line, start each content line with ` * `,
and use a bare ` *` for a blank line. This also applies to a one-line summary.

Do not use `///` or `//!` in Rust. Use plain `//` for implementation notes.

##### Docstring and line-comment adapters

Python uses the module, class, function, or method docstring that the runtime and
documentation parser associate with the declaration. Do not add decorative `*`
characters inside a docstring.

Line-comment languages repeat their ordinary comment prefix on every documentation
line. A blank documentation line contains only the prefix. Structured blocks are
distinguished from implementation comments by their placement and annotations.

#### Kind tags

Use a kind tag only when it truthfully matches the declared entity:

| Entity               | Annotation        |
|----------------------|-------------------|
| Class                | `@class Name`     |
| Struct               | `@struct Name`    |
| Union                | `@union Name`     |
| Enum                 | `@enum Name`      |
| Namespace            | `@namespace Name` |
| Interface            | `@interface Name` |
And more...

Do not invent a replacement tag for traits, protocols, records, packages, crates, or modules.
Let the declaration identify their language-specific kind and begin the block with `@brief`
when none of the supported kind tags is an exact match use best fit or leave empty.

Do **not** use `@file`! File identity remains implicit.

#### Module or type block

The block for a module, namespace, package, crate, or primary type uses this fixed
order:

1. Optional kind tag: `@class`, `@struct`, `@enum`, or `@namespace`...
2. `@brief` with one plain-text sentence ending in a period.
3. `@author [NAME] (<https://github.com/[USER]>)`.
4. Optional `@ingroup <Module>` when grouping is valid for the generated navigation.
5. A blank documentation line.
6. Explanatory prose, sections, tables, diagrams, invariants, and examples.
   Use Material format for sections.
7. Optional `@note`, `@warning`, and `@see` entries.

Wrap author URLs in angle brackets inside parentheses: `(<https://github.com/[USER]>)`.

`@author` should be repeated on a function, method,
constructor, property, field, variant, or enum value.
It is not top-level since multiple authors can contribute to one file.

```cpp
/**
 * @class AppViewModel
 * @brief QML-facing coordinator for application commands and non-secret UI state.
 * @author [NAME] (<https://github.com/[USER]>)
 * @ingroup ViewModel
 *
 * Coordinates the application core and controller collaborators for the QML view
 * layer. Command methods may accept secrets, but no observable property exposes one.
 *
 * ### :material-shield-lock: Security invariants
 *
 * | Invariant                                  | Enforcement                      |
 * |--------------------------------------------|----------------------------------|
 * | Secrets never become observable properties | Commands accept transient values |
 * | Models expose non-secret state only        | Roles omit secret-bearing fields |
 *
 * @see CliPanelViewModel
 */
```

A module or package whose language has no exact `@namespace` equivalent starts with
`@brief` rather than using a misleading kind tag.

```python
"""
@brief Authentication-domain services and immutable public result types.
@author [NAME] (<https://github.com/[USER]>)
@ingroup Authentication

The module owns orchestration only. Cryptographic primitives remain in the crypto
package and persistence remains behind repository interfaces.

### :material-notes: Usage notes

This function is designed strictly for [insert primary purpose]
"""
```

#### Function, method, and callable documentation

If no separate declaration exists, attach the block to the definition.
Otherwise, document the declaration and do not duplicate its contract on the definition.
Plain comments and one-line summaries do not replace this block. The required `@fn`
signature is metadata; the rule against restating the signature applies to prose.

Use this order, with parameter and return entries where applicable:

1. `@fn` signature of the function.
2. `@brief` with one plain-text sentence ending in a period.
3. `@author [NAME] (<https://github.com/[USER]>)`.
4. A blank documentation line.
5. Explanatory prose, sections, tables, diagrams, invariants, and examples.
   Use Material format for sections.
6. `@tparam` entries in declaration order.
7. `@param` entries in declaration order.
8. `@return` when the callable produces a meaningful result.
9. Optional `@pre` and `@post` entries.
10. Optional `@note`, `@warning`, and `@see` entries.

Use `@return`, never `@returns`. Do not add `@return` to constructors, destructors,
procedures, or callables whose language-level return is only an implementation
artifact.

Keep the brief line plain text. Do not put `@p`, `@c`, `@ref`, Markdown links, or
square-bracket ranges in it. Put identifiers and ranges in the prose, `@param`, or
`@return` text instead.

```cpp
/**
 * @fn float Lerp(float a, float b, float t)
 * @brief Linearly interpolate between two values.
 * @author [NAME] (<https://github.com/[USER]>)
 *
 * The factor @p t is clamped to [0, 1], so an out-of-range value saturates to
 * the nearest endpoint.
 *
 * ### :material-lock-outline: Thread safety
 *
 * Calls share no mutable state. Concurrent calls need no synchronization.
 *
 * @param a  Start value, returned when @p t is 0.
 * @param b  End value, returned when @p t is 1.
 * @param t  Blend factor in [0, 1].
 * @return   The interpolated value.
 */
float Lerp(float a, float b, float t);
```

The same annotations remain unchanged in a Python docstring:

```python
def lerp(a: float, b: float, t: float) -> float:
    """
    @fn lerp(a: float, b: float, t: float) -> float
    @brief Linearly interpolate between two values.
    @author [NAME] (<https://github.com/[USER]>)

    The factor @p t is clamped to [0, 1], so an out-of-range value saturates to
    the nearest endpoint.

    ### :material-lock-outline: Thread safety

    Calls share no mutable state. Concurrent calls need no synchronization.

    @param a  Start value, returned when @p t is 0.
    @param b  End value, returned when @p t is 1.
    @param t  Blend factor in [0, 1].
    @return   The interpolated value.
    """
```

The same annotations also remain unchanged in a line-comment language:

```go
// @fn Lerp(a, b, t float64) float64
// @brief Linearly interpolate between two values.
// @author [NAME] (<https://github.com/[USER]>)
//
// The factor t is clamped to [0, 1], so an out-of-range value saturates to the
// nearest endpoint.
//
// ### :material-lock-outline: Thread safety
//
// Calls share no mutable state. Concurrent calls need no synchronization.
//
// @param a  Start value, returned when t is 0.
// @param b  End value, returned when t is 1.
// @param t  Blend factor in [0, 1].
// @return   The interpolated value.
func Lerp(a, b, t float64) float64 {
    // Implementation omitted.
    return 0
}
```

#### Fields, properties, variants, and enum values

Keep declaration-level member documentation short and local.

When the language and documentation parser support trailing documentation, use
`///<` and no other trailing form.

```cpp
std::uint8_t alpha{255};  ///< Alpha channel (255 = opaque).
```

When trailing documentation is unsupported, use the shortest leading declaration
documentation form accepted by that language. Do not turn a simple field description
into a large block. Put long explanations, cross-field invariants, and state-machine
rules in the enclosing type documentation instead.

```typescript
/**
 * @brief Master switch for the post-processing pipeline.
 */
postProcessEnabled: boolean;
```

For languages that cannot reliably attach field comments, document the fields in a
Markdown table in the enclosing type block.

#### Grouping related declarations

Use an ordinary section comment to group related members. Do not use documentation
member-group commands.

```cpp
// Window state
Window* m_Window = nullptr;  ///< Owned OS window handle.
int m_Width = 1280;          ///< Client-area width, in pixels.
int m_Height = 720;          ///< Client-area height, in pixels.
```

---

### Sections, tables, icons, code, math, and diagrams

Section titles and visual documentation are language-independent body content. Keep
them when moving documentation between languages.

Use `### :material-icon-name: Section title` for named prose sections in every
language. Use sentence case in section titles and a valid Material for MkDocs
icon shortcode. Keep a blank documentation line before and after each heading.

Add sections when distinct contracts or a longer explanation need navigation.
Useful subjects include ownership, thread safety, security invariants, failure
handling, and data flow. Keep short, single-topic comments as plain prose. Add only
the context needed to explain the contract; do not add text just to fill a section.

The documentation scripts preserve authored section icons and add icons only to
complete generated headings. Icon insertion leaves code examples unchanged.
MkDocs renders C++ icons; the Rust HTML postprocessor uses the same installed
Material SVG assets. Check icon names against that set and verify the generated HTML.

````cpp
/**
 * @brief Coordinate authenticated browser-fill requests.
 *
 * ### :material-transit-connection-variant: Data flow
 *
 * ```mermaid
 * flowchart LR
 *     Browser --> Host
 *     Host --> Bridge
 *     Bridge --> Core
 * ```
 */
````

#### Strict table source formatting

Every Markdown table must be aligned in the source, not merely valid after rendering.
Apply the rule to ordinary Markdown and to tables inside every documentation carrier.

* Put one space between each cell boundary and its content.
* Pad every non-separator cell so the vertical pipes align in every row.
* Fill each separator cell with hyphens across the complete padded column width.
* Preserve the language comment prefix before every row, such as ` * `, `// `, or `# `.
* Keep table rows within the 100-column limit, including the comment prefix. Shorten
  wording or split a wide table instead of wrapping one logical row.
* Never emit compact or ragged forms such as `|---|---|` or rows with drifting pipes.

Use this form:

```cpp
/**
 * @brief Describe how entries become active.
 *
 * | Value         | Inclusion rule                        |
 * |---------------|---------------------------------------|
 * | `Required`    | Always.                               |
 * | `Plugin`      | Plugin selection or file-entry flags. |
 * | `Conditional` | Matching conditional pattern.         |
 */
```

The same alignment rule applies after another carrier prefix:

```go
// | Value         | Inclusion rule                        |
// |---------------|---------------------------------------|
// | `Required`    | Always.                               |
// | `Plugin`      | Plugin selection or file-entry flags. |
// | `Conditional` | Matching conditional pattern.         |
```

Use:

| Content         | House form                                   |
|-----------------|----------------------------------------------|
| Section title   | `### :material-icon-name: Section title`     |
| Table           | Source-aligned Markdown table                |
| Mermaid diagram | Fenced `mermaid` block                       |
| ASCII diagram   | `@verbatim` and `@endverbatim`               |
| Code sample     | `@code{.language}` and `@endcode`            |
| Display math    | `$$ ... $$`                                  |

Do not remove a useful diagram merely because the implementation language changes.
Adapt identifiers and syntax, but preserve the documented relationship or flow.

---

### Shared annotation vocabulary

Use these annotations where useful in every supported language:

`@fn`, `@brief`, `@author`, `@ingroup`, `@struct`, `@class`, `@enum`, `@namespace`,
`@param`, `@return`, `@tparam`, `@pre`, `@post`, `@note`, `@warning`, `@p`,
`@c`, `@see`, `@code`, `@endcode`, `@verbatim`, and `@endverbatim`.

Do not translate them to language-native alternatives. In particular:

| Avoid                            | Use                    |
|----------------------------------|------------------------|
| `@returns`                       | `@return`              |
| Python `Args:` or `Returns:`     | `@param` and `@return` |
| C# `<summary>` / `<param>`       | `@brief` and `@param`  |
| Rust `# Arguments` / `# Returns` | `@param` and `@return` |
| JSDoc `@returns`                 | `@return`              |

Do **not** use: `@file`, `@returns`, `@short`, `@defgroup`,
`@addtogroup`, `@def`, `@var`, `@internal`, `@{`, `@}`, or the LaTeX forms `@f[ ... @f]` and `@f$ ... @f$`.

For a language-specific entity that has no supported kind tag, omit the kind tag.
Do not use an inaccurate tag merely to force uniformity.

### Documentation-backend compatibility

The following rules apply to every language.
They are backend constraints, not C++ rules.

#### Brief-line restrictions

The `@brief` line, or the first prose line when `@brief` is omitted, must contain
plain text only. Do not place `@p`, `@c`, `@ref`, or square brackets on that line,
prose following the `@brief` line may use `@p`, `@c`, `@ref`, or square brackets.

#### Identifier commands and punctuation

`@p` and `@c` consume the next whitespace-delimited token, including punctuation.
Use them only when whitespace follows the identifier.

Write:

```text
The caller owns `roll`.
```

Do not write:

```text
The caller owns @p roll.
```

Use backticks whenever `.`, `,`, `;`, `:`, or `)` immediately follows the
identifier.

#### Member grouping

Do not use `@name`, `@{`, or `@}` member groups.
Do not use ordinary section comments either.

Comments of this style are not allowed:

```text
// ==============================
// Section
// ==============================
```

```text
// -- Section ------------------
```

#### Section headings

Use `### :material-icon-name: Section title` for named prose sections so the same
heading, icon, table, and diagram markup works in all languages.

Rust unsafe API contracts use `### :material-shield-lock: **Safety**`. Clippy requires
the exact `Safety` text as a separate Markdown text event. The emphasis keeps that
text separate from the icon while preserving the shared section format. Keep the
safety lint enabled; use sentence case for other section titles.

---

### Implementation documentation

Implementation comments use the language's ordinary line-comment syntax only.
Do not use structured documentation delimiters or commands for notes inside a body.
A nested function declaration still requires its own full block.

When moving declaration prose into an implementation comment, strip annotation
markup:

| Declaration documentation | Implementation comment         |
|---------------------------|--------------------------------|
| `@p name`                 | `name` or `` `name` ``         |
| `@c Buffer{}`             | `Buffer{}` or `` `Buffer{}` `` |
| `@see Parser`             | `Parser`                       |

A complex implementation file may begin with a plain contract summary, worked trace,
or ASCII diagram. A simple file may begin directly with imports/includes and code.

```cpp
// RingBuffer is the fixed-capacity FIFO used by the audio mixer.
// Reads and writes advance independent cursors modulo the capacity. One slot is
// reserved so equal cursors unambiguously mean empty rather than full.
```

Add a short intent comment above non-obvious steps inside a function body.

```cpp
// Clamp the requested gain before evaluating the nonlinear fade curve.
gain = std::clamp(gain, 0.0f, 1.0f);
```

### TODO comments

Use `TODO` only for real follow-up work. State the required change and, when useful,
the condition that makes it necessary.

```cpp
// TODO: Replace the linear scan with a spatial hash above 10,000 elements.
```

Do not use vague reminders such as `TODO: Improve`, `TODO: Clean up`, or
`TODO: Revisit later`.

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
