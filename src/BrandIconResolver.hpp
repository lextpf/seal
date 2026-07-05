#pragma once

/**
 * @brief Look up brand icons by free-form platform name.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * Records in the vault carry a free-form platform label (`"GitHub"`,
 * `"Twitter, Inc."`, `"google.com"`, `"My Personal X account"`). The
 * UI wants to show the matching brand SVG next to each record. This
 * header turns the label into an SVG asset slug through a tiny
 * three-stage pipeline:
 *
 * ## :material-vector-link: Resolution Pipeline
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * flowchart LR
 *     classDef step fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
 *     classDef out fill:#1e4a3a,stroke:#22c55e,color:#e2e8f0
 *     classDef miss fill:#4a3520,stroke:#f59e0b,color:#e2e8f0
 *
 *     LBL([platformName]):::step
 *     NORM[normalizeSlug:<br/>strip non-alnum,<br/>lowercase]:::step
 *     DIRECT{direct match in<br/>asset index?}:::step
 *     ALIAS{alias table hit?<br/>e.g. x -> x-twitter}:::step
 *     TLD{strip trailing TLD<br/>+ retry?}:::step
 *     OK([asset slug]):::out
 *     NONE([empty]):::miss
 *
 *     LBL --> NORM --> DIRECT
 *     DIRECT -->|yes| OK
 *     DIRECT -->|no| ALIAS
 *     ALIAS -->|yes| OK
 *     ALIAS -->|no| TLD
 *     TLD -->|yes| OK
 *     TLD -->|no| NONE
 * ```
 *
 * @note **Predicate-based asset probe.** @ref resolveBrandIconSlug
 *       takes a `lookupAsset` closure rather than reading the
 *       filesystem itself. This keeps the pure-C++ resolution logic
 *       independent of Qt resources so the unit tests in
 *       `tests/test_brand_icon_resolver.cpp` can stub the asset
 *       index without standing up a `QResource` tree. The Qt
 *       wrapper @ref resolveBrandIconPath fills in the predicate
 *       with a `QDirIterator` over the compiled-in asset set.
 */

#include <functional>
#include <string>

#ifdef USE_QT_UI
#include <QString>
#endif

namespace seal
{
namespace brand
{

/**
 * @brief Normalize a free-form platform name to a lower-case alphanumeric slug.
 * @ingroup BrandIcon
 *
 * Drops every character that isn't `[a-z0-9]`. Used as the first stage of
 * brand-icon resolution and as the canonical key shape for the asset index.
 *
 * @param platformName Free-form platform string (e.g. `"GitHub"`, `"Twitter, Inc."`).
 * @return Normalized slug (e.g. `"github"`, `"twitterinc"`). Empty when the input
 *         contains no alphanumeric characters.
 */
std::string normalizeSlug(const std::string& platformName);

/**
 * @brief Resolve a platform name to a brand-asset slug (without the `.svg` suffix).
 * @ingroup BrandIcon
 *
 * Applies, in order:
 *   1. `normalizeSlug` on the input
 *   2. Direct match against the supplied asset index
 *   3. Curated alias table (e.g. `"x"` -> `"x-twitter"`, `"signal"` -> `"signal-messenger"`)
 *   4. Trailing-TLD strip (`"github.com"` -> `"github"`) then direct/alias retry
 *   5. Per-token retry for multi-word labels (`"Twitter, Inc."` -> `"twitter"`,
 *      which then aliases to `"x-twitter"`)
 *
 * The caller supplies a `lookupAsset` predicate that maps a normalized slug to
 * the real asset filename (with hyphens preserved). This lets the pure-C++ slice
 * stay independent of Qt resources for unit testing.
 *
 * @param platformName Free-form platform string.
 * @param lookupAsset  Closure: given a normalized slug, returns the real asset
 *                     filename (without `.svg`) when present, or empty string.
 * @return Real asset slug (with hyphens, e.g. `"x-twitter"`) on success;
 *         empty string when no asset matches.
 */
std::string resolveBrandIconSlug(const std::string& platformName,
                                 const std::function<std::string(const std::string&)>& lookupAsset);

#ifdef USE_QT_UI
/**
 * @brief Resolve a platform name to a qrc path under `assets/brands/`.
 * @ingroup BrandIcon
 *
 * Convenience wrapper that uses the application's compiled-in asset set as the
 * lookup source. The asset index is built once on first call by enumerating
 * SVG files under `:/qt/qml/seal/assets/brands/` via `QDirIterator`, then cached.
 *
 * @param platformName Free-form platform string.
 * @return `qrc:/qt/qml/seal/assets/brands/<slug>.svg` on match, empty `QString` on miss.
 */
QString resolveBrandIconPath(const QString& platformName);
#endif

}  // namespace brand
}  // namespace seal
