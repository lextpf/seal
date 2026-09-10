#pragma once

/**
 * @brief Resolve platform labels to bundled brand icons.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * ### :material-vector-link: Resolution
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
 *     TLD{strip trailing TLD,<br/>retry direct + alias?}:::step
 *     TOKEN{per-token retry,<br/>direct + alias?}:::step
 *     OK([asset slug]):::out
 *     NONE([empty]):::miss
 *
 *     LBL --> NORM --> DIRECT
 *     DIRECT -->|yes| OK
 *     DIRECT -->|no| ALIAS
 *     ALIAS -->|yes| OK
 *     ALIAS -->|no| TLD
 *     TLD -->|yes| OK
 *     TLD -->|no| TOKEN
 *     TOKEN -->|yes| OK
 *     TOKEN -->|no| NONE
 * ```
 *
 * The lookup callback keeps slug resolution independent of Qt resources.
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
 * @fn std::string normalizeSlug(const std::string& platformName)
 * @brief Keep lowercase alphanumeric bytes; discard punctuation and spacing.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup BrandIcon
 *
 * Uses the C locale: non-ASCII bytes are discarded in the default locale.
 * `github.com` becomes `githubcom`; `Twitter, Inc.` becomes `twitterinc`.
 *
 * @return Normalized index key; empty when no alphanumeric byte remains.
 */
std::string normalizeSlug(const std::string& platformName);

/**
 * @fn std::string resolveBrandIconSlug(const std::string& platformName, const
 *     std::function<std::string(const std::string&)>& lookupAsset)
 * @brief Return the first matching asset slug from the resolution pipeline.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup BrandIcon
 *
 * Probes use normalized keys, including aliases: `x-twitter` is probed as
 * `xtwitter`. Returned asset names retain hyphens and omit `.svg`.
 *
 * Suffix stripping tries `com`, `io`, `net`, `org`, `app`, `tld`, `tv`, `ai` only
 * when the slug is longer. It is not hostname parsing: `Cash App` retries as
 * `cash`. Per-token fallback maps `Twitter, Inc.` through `twitter` to
 * `x-twitter`; a token equal to the joined slug is skipped.
 *
 * Each candidate costs one lookup, plus an alias lookup after a direct miss.
 * Input without alphanumeric bytes costs none.
 *
 * @param lookupAsset Callable mapping normalized keys to asset slugs; empty means
 *                    miss. Keep it cheap and free of side effects.
 * @return Empty when no candidate matches.
 * @pre The callback is callable; no empty check is made.
 */
std::string resolveBrandIconSlug(const std::string& platformName,
                                 const std::function<std::string(const std::string&)>& lookupAsset);

#ifdef USE_QT_UI
/**
 * @fn QString resolveBrandIconPath(const QString& platformName)
 * @brief Resolve against the compiled SVG resource index.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup BrandIcon
 *
 * First use enumerates files directly under `:/qt/qml/seal/assets/brands` once,
 * with thread-safe initialization. Keep filenames ASCII and distinct after
 * normalization: `x-twitter.svg` maps `xtwitter` to `x-twitter`; later collisions win.
 *
 * @return `qrc:/qt/qml/seal/assets/brands/<slug>.svg`, or empty on a miss or absent assets.
 */
QString resolveBrandIconPath(const QString& platformName);
#endif

}  // namespace brand
}  // namespace seal
