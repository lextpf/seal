#pragma once

/**
 * @brief Look up brand icons by free-form platform name.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * Records carry a free-form platform label (`"GitHub"`, `"Twitter, Inc."`,
 * `"google.com"`, `"My Personal X account"`) and the UI shows the matching
 * brand SVG beside each one. This header turns the label into an SVG asset
 * slug: normalize the label, then try four lookups in order and stop at the
 * first hit.
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
 * @note @ref resolveBrandIconSlug takes a `lookupAsset` closure instead of
 *       reading the filesystem, so the resolution logic stays independent of
 *       Qt resources and `tests/test_brand_icon_resolver.cpp` can stub the
 *       asset index without a `QResource` tree. The Qt wrapper
 *       @ref resolveBrandIconPath supplies the predicate over the compiled-in
 *       asset set.
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
 * Keeps the alphanumeric bytes, lower-cased, and drops everything else: spaces,
 * punctuation, dots, hyphens, and (in the default C locale) every non-ASCII
 * byte. Nothing is inserted, so the dots of a host disappear without splitting
 * it: `"github.com"` becomes `"githubcom"`, not `"github"`. This is the
 * canonical key shape for the asset index, so an index key never holds a hyphen
 * even when the asset filename does.
 *
 * @param platformName Free-form platform string, such as `"Twitter, Inc."`.
 * @return Normalized slug, such as `"twitterinc"`. Empty when the input holds no
 *         alphanumeric character.
 */
std::string normalizeSlug(const std::string& platformName);

/**
 * @brief Resolve a platform name to a brand-asset slug (without the `.svg` suffix).
 * @ingroup BrandIcon
 *
 * Applies, in order, and returns the first hit:
 *   1. Join the input's alphanumeric tokens - the string `normalizeSlug`
 *      produces
 *   2. Direct match of the joined slug against the supplied asset index
 *   3. Curated alias table (e.g. `"x"` -> `"x-twitter"`, `"signal"` -> `"signal-messenger"`)
 *   4. Trailing-TLD strip (`"github.com"` -> `"github"`) then direct/alias retry
 *   5. Per-token retry for multi-word labels (`"Twitter, Inc."` -> `"twitter"`,
 *      which then aliases to `"x-twitter"`). A token equal to the joined slug
 *      is skipped, so a single-word label adds no probe here.
 *
 * @par Slug shape the predicate sees
 * Every probe is a normalized slug: lower-case, alphanumeric only, never a
 * hyphen or a dot. Alias targets are re-normalized before the probe, so the
 * alias `"x-twitter"` is looked up as `"xtwitter"`. An index keyed by raw
 * filenames will therefore never match.
 *
 * @par Trailing-TLD strip
 * Step 4 strips a fixed suffix (`com`, `io`, `net`, `org`, `app`, `tld`, `tv`,
 * `ai`) off the joined slug, and only when the slug is longer than the suffix.
 * It parses no hostname, so a brand whose slug ends in one of those groups is
 * stripped too: `"Cash App"` joins to `"cashapp"` and retries as `"cash"`. A
 * wrong strip is harmless: the failed retry falls through to the next
 * candidate.
 *
 * @par Cost
 * One predicate call per candidate, plus a second call for the alias target
 * when the candidate is in the alias table and the direct probe missed. Keep
 * the predicate cheap and free of side effects. A label with no alphanumeric
 * character costs no call at all.
 *
 * @pre @p lookupAsset is callable; it is invoked without an empty check.
 * @param platformName Free-form platform string.
 * @param lookupAsset  Maps a normalized slug to the real asset filename
 *                     (without `.svg`), or returns an empty string on a miss.
 * @return Real asset slug, hyphens included (`"x-twitter"`), or an empty string
 *         when no candidate matches or @p platformName has no alphanumeric
 *         character.
 */
std::string resolveBrandIconSlug(const std::string& platformName,
                                 const std::function<std::string(const std::string&)>& lookupAsset);

#ifdef USE_QT_UI
/**
 * @brief Resolve a platform name to a qrc path under `assets/brands/`.
 * @ingroup BrandIcon
 *
 * Wraps @ref resolveBrandIconSlug with the compiled-in asset set as the lookup
 * source.
 *
 * @par Index build
 * Built once on first call by enumerating `*.svg` directly under
 * `:/qt/qml/seal/assets/brands` (no recursion), then cached for the process
 * lifetime. `std::call_once` guards construction, so concurrent first calls are
 * safe. The index is never rebuilt, so a brand SVG added later is not seen.
 *
 * @par Keys
 * Each entry maps the file base name, reduced to its lower-case letters and
 * digits, to that base name: `x-twitter.svg` is indexed as
 * `xtwitter` -> `x-twitter`. Two files that reduce to the same key collide and
 * the later one wins, so keep brand filenames distinct after normalization.
 * Keep brand filenames ASCII as well: the index key keeps every Unicode letter
 * or digit, but every probe comes from @ref normalizeSlug, which keeps ASCII
 * alphanumerics only, so a non-ASCII base name is indexed under a key no
 * platform label can produce and that icon never resolves.
 *
 * @par Empty asset tree
 * Brand assets are optional at build time. With none in the resource tree the
 * index is empty and every call returns an empty `QString`; the account chip
 * draws its monogram circle instead of a broken image.
 *
 * @param platformName Free-form platform string.
 * @return `qrc:/qt/qml/seal/assets/brands/<slug>.svg` on a match, empty
 *         `QString` on a miss.
 */
QString resolveBrandIconPath(const QString& platformName);
#endif

}  // namespace brand
}  // namespace seal
