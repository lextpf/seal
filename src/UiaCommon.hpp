#pragma once

/**
 * @brief Shared UIA primitives used by every UIA-backed probe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * UiaIsPasswordProbe and UiaMetadataProbe (including the latter's
 * form-context fallback path) all walk the same UIA tree with the same
 * depth / node-count budgets, look at the same string properties, and
 * need the same BSTR <-> QString plumbing. This header is the single
 * source for those primitives so behaviour can be tuned in one place.
 *
 * ## :material-tree: Tree-walk budgets
 *
 * - **kMaxUiaAncestorDepth** - ancestor walk stops at 8 levels.
 *   Modern web login pages bury inputs ~3-5 deep; 8 covers the long
 *   tail without letting a pathological tree run away.
 * - **kMaxUiaDescendantDepth** - descendant DFS recursion cap (6).
 * - **kMaxUiaDescendantNodes** - hard cap of 64 inspected descendants
 *   per probe call. UIA queries can stall on heavyweight elements
 *   (large iframes, custom-control hosts); this is the failsafe that
 *   keeps the probe budget bounded even when the tree is hostile.
 *
 * @verbatim
 *   How the budgets bound the walk around the click's hit element:
 *
 *        ( up to kMaxUiaAncestorDepth = 8 parents; each parent is
 *          probed only while its rect still contains the click )
 *                              ^  ancestor walk
 *                              |
 *              +--------------------------------+
 *              |  UIA hit element under click   |  <- ElementFromPoint
 *              +--------------------------------+
 *                              |
 *                              v  descendant DFS
 *        ( kMaxUiaDescendantDepth = 6 levels deep, at most
 *          kMaxUiaDescendantNodes = 64 nodes inspected in total )
 * @endverbatim
 *
 * ## :material-magnify: Hint observation
 *
 * @ref UiaHintObservation distinguishes three states:
 *   - Observed = false: no UIA data was readable for this element.
 *     The probe should fall through to another signal.
 *   - Observed = true, Matched = false: UIA was readable but the
 *     element is NOT what we were looking for. This is a confident
 *     negative.
 *   - Observed = true, Matched = true: positive identification with a
 *     specific source (Name / HelpText / metadata label).
 *
 * @note The three-state shape lets a caller tell "no UIA data" apart
 *       from a confident negative; searchDescendantsForPassword threads
 *       that distinction out via its observedAny out-parameter. That
 *       signal is currently advisory - UiaMetadataProbe runs its
 *       form-context fallback regardless - so it is not yet a
 *       suppression gate.
 */

#ifdef USE_QT_UI

#include <QtCore/QString>

#include <UIAutomation.h>
#include <vector>

namespace seal
{

/**
 * @brief Maximum number of ancestor levels walked when searching for a password field.
 * @ingroup FillController
 */
inline constexpr int kMaxUiaAncestorDepth = 8;

/**
 * @brief Maximum recursion depth for the bounded descendant DFS.
 * @ingroup FillController
 */
inline constexpr int kMaxUiaDescendantDepth = 6;

/**
 * @brief Hard cap on the number of descendant nodes inspected per probe.
 * @ingroup FillController
 */
inline constexpr int kMaxUiaDescendantNodes = 64;

/**
 * @brief Outcome of inspecting one UIA element for a password / username hint.
 * @ingroup FillController
 *
 * m_Observed becomes true when *any* hint source was readable (so the caller
 * can tell "no UIA data at all" from "UIA data present but negative");
 * m_Matched becomes true only when the observation positively identifies the
 * field type.
 *
 * @par State combinations (m_Observed / m_Matched)
 * | m_Observed | m_Matched | Meaning                                              |
 * |------------|-----------|------------------------------------------------------|
 * | false      | false     | No UIA data readable; fall through to next signal.   |
 * | true       | false     | UIA readable but not the target: confident negative. |
 * | true       | true      | Positive match; m_Source names the property.         |
 */
struct UiaHintObservation
{
    bool m_Observed = false;  ///< True if any hint property was readable for this element.
    bool m_Matched = false;   ///< True if a positive hint matched the queried field type.
    QString m_Source;         ///< Property that produced the match (e.g. "Name", "HelpText").
    QString m_MatchedText;    ///< Original property value that triggered the match.
};

/**
 * @brief Pairs a UIA property id with a short, log-safe label.
 * @ingroup FillController
 *
 * Used to drive the metadata hint scan in a single table-driven loop so the
 * password and username scans share the same property set in the same order.
 */
struct StringPropertyProbe
{
    PROPERTYID m_PropertyId = 0;  ///< UIA property id (e.g. UIA_NamePropertyId).
    const char* m_Label = "";     ///< Static log-safe label (e.g. "Name").
};

/**
 * @brief Convert a UIA BSTR to a QString and release the BSTR.
 * @param text Raw BSTR returned by a UIA property accessor; may be null.
 * @return UTF-16 QString copy (empty when text is null).
 * @ingroup FillController
 */
QString takeBstr(BSTR text);

/**
 * @brief Read a UIA string property and return it as a QString.
 * @param element UIA element to query; may be null (returns empty).
 * @param propertyId UIA property id (must be a string-typed property).
 * @return QString value or empty when the property is absent or non-string.
 * @ingroup FillController
 */
QString currentStringProperty(IUIAutomationElement* element, PROPERTYID propertyId);

/**
 * @brief Test whether rawText contains any localized password keyword.
 * @param rawText Original (cased) string from a UIA property.
 * @return True when at least one entry from the multilingual password-hint
 *         table appears as a substring (after lowercasing and trimming).
 * @ingroup FillController
 */
bool containsPasswordHint(const QString& rawText);

/**
 * @brief Test whether rawText contains any localized username keyword.
 * @param rawText Original (cased) string from a UIA property.
 * @return True when at least one entry from the multilingual username-hint
 *         table appears as a substring (after lowercasing and trimming).
 * @ingroup FillController
 */
bool containsUsernameHint(const QString& rawText);

/**
 * @brief Check whether element's UIA control type is plausibly editable.
 * @param element UIA element; must be non-null.
 * @return True for Edit, Custom, Pane and Document control types.
 * @ingroup FillController
 */
bool isEditLikeControlType(IUIAutomationElement* element);

/**
 * @brief Scan a UIA element's string properties for password hints.
 * @param element UIA element to inspect; may be null.
 * @param skipControlTypeGate When false (the default) the scan is skipped for
 *        non-edit-like control types; set true when the caller already knows
 *        element wraps an input.
 * @return Populated UiaHintObservation; m_Matched is true on first hit.
 * @ingroup FillController
 */
UiaHintObservation inspectPasswordHintMetadata(IUIAutomationElement* element,
                                               bool skipControlTypeGate = false);

/**
 * @brief Scan a UIA element's string properties for username hints.
 * @param element UIA element to inspect; may be null.
 * @param skipControlTypeGate When false (the default) the scan is skipped for
 *        non-edit-like control types; set true when the caller already knows
 *        element wraps an input.
 * @return Populated UiaHintObservation; m_Matched is true on first hit.
 * @ingroup FillController
 */
UiaHintObservation inspectUsernameHintMetadata(IUIAutomationElement* element,
                                               bool skipControlTypeGate = false);

/**
 * @brief Map a UIA CONTROLTYPEID to a short static string for logging.
 * @param controlType Raw UIA control type id.
 * @return Static C-string label ("Edit", "Button", ..., or "Unknown").
 * @ingroup FillController
 */
const char* controlTypeToString(CONTROLTYPEID controlType);

/**
 * @brief Half-open rectangle hit test (right/bottom are exclusive).
 * @ingroup FillController
 */
bool rectContainsPoint(const RECT& rect, LONG x, LONG y);

/**
 * @brief Fetch a UIA element's current bounding rectangle, rejecting empty rects.
 * @param element UIA element; may be null.
 * @param rect Output rectangle; only written on success.
 * @return True only when the call succeeded *and* the rectangle has area.
 * @ingroup FillController
 */
bool tryGetCurrentBoundingRect(IUIAutomationElement* element, RECT* rect);

/**
 * @brief Inspect a UIA element for password state via IsPassword / LegacyIAccessible / metadata.
 * @param element UIA element; may be null.
 * @param skipControlTypeGate Forwarded to the metadata fallback scan.
 * @return Populated UiaHintObservation. m_Source distinguishes "IsPassword"
 *         vs "LegacyState" vs a metadata label.
 * @ingroup FillController
 */
UiaHintObservation inspectElementPasswordState(IUIAutomationElement* element,
                                               bool skipControlTypeGate = false);

/**
 * @brief Inspect a UIA element for username metadata hints.
 * @param element UIA element; may be null.
 * @return Populated UiaHintObservation. Always permissive on control type
 *         (form-context callers may receive non-Edit wrappers).
 * @ingroup FillController
 */
UiaHintObservation inspectElementUsernameState(IUIAutomationElement* element);

/**
 * @brief Build a human-readable QString summary of a UIA element for logging.
 * @param element UIA element; may be null (returns "<null>").
 * @return One-line summary including control type, framework id, class, name, id, and rect.
 * @ingroup FillController
 */
QString describeAutomationElement(IUIAutomationElement* element);

/**
 * @brief Bounded DFS for a password-classified UIA descendant under root.
 * @param walker UIA tree walker.
 * @param root Subtree root (not inspected itself); must be non-null.
 * @param x Screen-space click X coordinate (used for bounding-rect filtering).
 * @param y Screen-space click Y coordinate.
 * @param depth Current recursion depth (caller passes 0).
 * @param nodesRemaining Per-probe descendant budget; decremented on every inspection.
 * @param observedAny Out parameter; set to true if any descendant produced an observation.
 * @return True when a positive password match was found.
 * @ingroup FillController
 */
bool searchDescendantsForPassword(IUIAutomationTreeWalker* walker,
                                  IUIAutomationElement* root,
                                  LONG x,
                                  LONG y,
                                  int depth,
                                  int& nodesRemaining,
                                  bool& observedAny);

/**
 * @brief Walk up from start looking for a plausible form-like container.
 * @param walker UIA tree walker.
 * @param start Element to start walking from.
 * @return AddRef'd form ancestor (caller releases) or nullptr when no form found.
 * @ingroup FillController
 *
 * A "form-like" ancestor has at least two direct Edit/Custom children and a
 * bounding rectangle smaller than half the primary monitor area (the half-
 * monitor cap prevents landing on \<body\> for short pages).
 */
IUIAutomationElement* findFormAncestor(IUIAutomationTreeWalker* walker,
                                       IUIAutomationElement* start);

/**
 * @brief Bounded DFS collecting Edit/Custom inputs under root.
 * @param walker UIA tree walker.
 * @param root Subtree root; must be non-null.
 * @param out Destination vector; each pushed element is AddRef'd, caller must release.
 * @ingroup FillController
 */
void enumerateFormInputs(IUIAutomationTreeWalker* walker,
                         IUIAutomationElement* root,
                         std::vector<IUIAutomationElement*>& out);

}  // namespace seal

#endif  // USE_QT_UI
