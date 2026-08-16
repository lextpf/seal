#pragma once

/**
 * @brief Shared UIA primitives used by every UIA-backed probe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * UiaIsPasswordProbe and UiaMetadataProbe (including the latter's
 * form-context path) read the same string properties, apply the same keyword
 * tables and need the same BSTR to QString plumbing. This header is the
 * single source for those primitives, so behaviour is tuned in one place.
 *
 * ## :material-tree: Tree-walk budgets
 *
 * - **kMaxUiaAncestorDepth** - the ancestor walk in UiaMetadataProbe visits
 *   at most 8 levels. Web login pages bury inputs 3 to 5 levels deep; 8
 *   covers the long tail without letting a pathological tree run away.
 * - **kMaxUiaDescendantDepth** - recursion cap (6) for
 *   @ref searchDescendantsForPassword.
 * - **kMaxUiaDescendantNodes** - budget of 64 inspected descendants. The
 *   caller owns the counter and passes it by reference, so the cap is per
 *   call, not per process. UIA queries can stall on heavyweight elements
 *   (large iframes, custom-control hosts); this keeps the walk bounded even
 *   when the tree is hostile.
 *
 * @warning These three constants do not govern the form-context helpers.
 *          @ref findFormAncestor and @ref enumerateFormInputs use their own
 *          file-local caps in UiaCommon.cpp (12 ancestor levels, 32
 *          collected inputs, 6 descendant levels). Changing a constant here
 *          leaves that path untouched.
 *
 * @verbatim
 *   How the budgets bound the walk around the click's hit element:
 *
 *        ( up to kMaxUiaAncestorDepth = 8 parents. A parent whose rect
 *          is readable but excludes the click is skipped, and the walk
 *          still continues upward and still spends that level. )
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
 * @ref UiaHintObservation separates "no UIA data was readable" from a
 * confident negative and from a positive match; its own block carries the
 * state table.
 *
 * @note The three-state shape lets a caller tell "no UIA data" apart from a
 *       confident negative. @ref searchDescendantsForPassword threads that
 *       distinction out through its @p observedAny out-parameter, but no
 *       caller acts on it: UiaMetadataProbe passes a local flag, never reads
 *       it back, and runs its form-context fallback either way. Treat
 *       @c m_Observed as reporting, not as a suppression gate.
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
 * @struct UiaHintObservation
 * @brief Outcome of inspecting one UIA element for a password / username hint.
 * @ingroup FillController
 *
 * m_Observed becomes true when any hint source was readable, so the caller can tell "no UIA data
 * at all" from "UIA data present but negative". m_Matched becomes true only when the observation
 * positively identifies the field type.
 *
 * @par State combinations (m_Observed / m_Matched)
 * | m_Observed | m_Matched | Meaning                                              |
 * |------------|-----------|------------------------------------------------------|
 * | false      | false     | No UIA data readable; fall through to next signal.   |
 * | true       | false     | UIA readable but not the target: confident negative. |
 * | true       | true      | Positive match; m_Source names the property.         |
 *
 * @note Only @ref inspectElementPasswordState can report the middle row. The
 *       metadata scans (@ref inspectPasswordHintMetadata,
 *       @ref inspectUsernameHintMetadata, and therefore
 *       @ref inspectElementUsernameState) set m_Observed only together with
 *       m_Matched, so for them "no match" and "nothing readable" are the
 *       same result.
 *
 * @note m_Source and m_MatchedText are meaningful only when m_Matched is
 *       true. @ref inspectElementPasswordState can return an unmatched
 *       observation that still carries m_Source "IsPassword" from the
 *       property read that reported false.
 */
struct UiaHintObservation
{
    bool m_Observed = false;  ///< True if any hint property was readable for this element.
    bool m_Matched = false;   ///< True if a positive hint matched the queried field type.
    QString m_Source;         ///< Property that produced the match (e.g. "Name", "HelpText").
    QString m_MatchedText;    ///< Original property value that triggered the match.
};

/**
 * @struct StringPropertyProbe
 * @brief Pairs a UIA property id with a short, log-safe label.
 * @ingroup FillController
 *
 * Drives the metadata hint scan as one table-driven loop, so the password and username scans
 * share the same property set in the same order.
 */
struct StringPropertyProbe
{
    PROPERTYID m_PropertyId = 0;  ///< UIA property id (e.g. UIA_NamePropertyId).
    const char* m_Label = "";     ///< Static log-safe label (e.g. "Name").
};

/**
 * @brief Convert a UIA BSTR to a QString and release the BSTR.
 *
 * Takes ownership: @p text is freed with @c SysFreeString before the call
 * returns, so the caller must not use it afterwards and must not free it a
 * second time. A null @p text frees nothing.
 *
 * @param text Raw BSTR returned by a UIA property accessor; may be null.
 * @return UTF-16 QString copy, empty when @p text is null.
 * @ingroup FillController
 */
QString takeBstr(BSTR text);

/**
 * @brief Read a UIA string property and return it as a QString.
 *
 * Accepts @c VT_BSTR and @c VT_BSTR|VT_BYREF; every other variant type
 * yields an empty string. The VARIANT is always cleared, so no path leaks,
 * including a failed accessor.
 *
 * @param element UIA element to query; may be null (returns empty).
 * @param propertyId UIA property id. A property that is not string-typed
 *                   yields an empty string, not an error.
 * @return QString value, or empty when the element is null, the accessor
 *         failed, or the property is absent or not a string.
 * @ingroup FillController
 */
QString currentStringProperty(IUIAutomationElement* element, PROPERTYID propertyId);

/**
 * @brief Test whether rawText contains any password keyword.
 *
 * The comparison trims @p rawText, lowercases it, then tests each table
 * entry as a plain substring. The table holds six ASCII entries covering
 * English and German only ("password", "passwd", "passcode", "pwd",
 * "passwort", "kennwort"); no other language is recognised.
 *
 * @param rawText Original (cased) string from a UIA property.
 * @return True when at least one table entry appears as a substring. An
 *         empty or whitespace-only string returns false.
 * @ingroup FillController
 */
bool containsPasswordHint(const QString& rawText);

/**
 * @brief Test whether rawText contains any username keyword.
 *
 * Same trim / lowercase / substring rule as @ref containsPasswordHint. The
 * table holds 15 ASCII entries, English and German only: the user-stem
 * compounds "username", "user-name", "userid" and "user-id", plus the
 * standalone terms "email", "e-mail", "login", "account", "benutzer",
 * "benutzername", "nutzer", "konto", "kennung", "anmelden" and "anmeldung".
 * Bare "user" is deliberately absent because it matches user-agent and similar
 * strings. The standalone terms match anywhere in a property value, so a
 * container named "account-menu" also matches. That is one reason the metadata
 * probe built on this scan carries Tier-2 weight only.
 *
 * @param rawText Original (cased) string from a UIA property.
 * @return True when at least one table entry appears as a substring. An
 *         empty or whitespace-only string returns false.
 * @ingroup FillController
 */
bool containsUsernameHint(const QString& rawText);

/**
 * @brief Check whether element's UIA control type is plausibly editable.
 * @pre @p element is not null; the function dereferences it without a null
 *      check.
 * @param element UIA element.
 * @return True for Edit, Custom, Pane and Document control types. False for
 *         every other type and also when the control-type accessor fails, so
 *         a provider that cannot answer is treated as not editable.
 * @ingroup FillController
 */
bool isEditLikeControlType(IUIAutomationElement* element);

/**
 * @brief Scan a UIA element's string properties for password hints.
 *
 * Reads the shared nine-property table in fixed order - AutomationId, Name,
 * HelpText, FullDescription, LocalizedControlType, ClassName, ItemType,
 * AriaRole, AriaProperties - and stops at the first value that satisfies
 * @ref containsPasswordHint. Up to nine cross-process property reads happen
 * when nothing matches.
 *
 * @param element UIA element to inspect; may be null.
 * @param skipControlTypeGate True skips the edit-like control-type filter;
 *        pass it when the caller already knows the element wraps an input.
 * @return Populated UiaHintObservation. On a hit, m_Observed and m_Matched
 *         are both true, m_Source is the table label and m_MatchedText the
 *         raw property value. With no hit both flags stay false, even though
 *         properties were read: this function never reports a confident
 *         negative.
 * @ingroup FillController
 */
UiaHintObservation inspectPasswordHintMetadata(IUIAutomationElement* element,
                                               bool skipControlTypeGate = false);

/**
 * @brief Scan a UIA element's string properties for username hints.
 *
 * Same nine-property table and same first-match-wins order as
 * @ref inspectPasswordHintMetadata, tested with @ref containsUsernameHint.
 * The two scans are independent: an element can match both, and the caller
 * decides which one wins.
 *
 * @param element UIA element to inspect; may be null.
 * @param skipControlTypeGate True skips the edit-like control-type filter;
 *        pass it when the caller already knows the element wraps an input.
 * @return Populated UiaHintObservation; both flags stay false when nothing
 *         matched, as in @ref inspectPasswordHintMetadata.
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
 *
 * Coordinates are compared as given. The caller supplies screen-space values
 * from @ref tryGetCurrentBoundingRect and the raw click point, both in
 * physical pixels, so no DPI conversion happens here.
 *
 * @return True when x is in [left, right) and y is in [top, bottom). An
 *         inverted or zero-area rect always returns false.
 * @ingroup FillController
 */
bool rectContainsPoint(const RECT& rect, LONG x, LONG y);

/**
 * @brief Fetch a UIA element's current bounding rectangle, rejecting empty rects.
 *
 * Callers read a false result as "geometry unknown" and usually stay
 * permissive on it, because an off-screen or collapsed element and a
 * provider that cannot answer are indistinguishable here.
 *
 * @param element UIA element; may be null.
 * @param rect Output rectangle; may be null (returns false), and is written
 *             only when the function returns true.
 * @return True only when the call succeeded and the rectangle has area.
 * @ingroup FillController
 */
bool tryGetCurrentBoundingRect(IUIAutomationElement* element, RECT* rect);

/**
 * @brief Inspect a UIA element for password state via IsPassword / LegacyIAccessible / metadata.
 *
 * Runs three sources in order and returns at the first positive:
 * @c UIA_IsPasswordPropertyId, then the LegacyIAccessible pattern's
 * @c STATE_SYSTEM_PROTECTED bit, then @ref inspectPasswordHintMetadata. The
 * first two set m_Observed even when they report false, which is how a
 * caller tells "the provider says this is not a password field" apart from
 * "the provider answered nothing". Every COM interface acquired here is
 * released before the return.
 *
 * @param element UIA element; may be null.
 * @param skipControlTypeGate Forwarded to the metadata fallback scan only;
 *        the IsPassword and LegacyIAccessible reads ignore it.
 * @return Populated UiaHintObservation. On a match m_Source is "IsPassword",
 *         "LegacyState", or a metadata table label such as "Name". A caller
 *         that wants strictly Tier-1 evidence must test m_Source, because
 *         the metadata fallback runs unconditionally here: UiaIsPasswordProbe
 *         accepts only the first two labels, UiaMetadataProbe rejects
 *         exactly those two.
 * @ingroup FillController
 */
UiaHintObservation inspectElementPasswordState(IUIAutomationElement* element,
                                               bool skipControlTypeGate = false);

/**
 * @brief Inspect a UIA element for username metadata hints.
 *
 * UIA has no "is username" property, so this is a metadata keyword scan and
 * nothing else. The control-type gate is always skipped because
 * form-context callers pass wrappers that are not Edit elements.
 *
 * @param element UIA element; may be null.
 * @return Populated UiaHintObservation; m_Observed is set only together with
 *         m_Matched.
 * @ingroup FillController
 */
UiaHintObservation inspectElementUsernameState(IUIAutomationElement* element);

/**
 * @brief Build a human-readable QString summary of a UIA element for logging.
 *
 * Reads five string properties plus the control type and bounding rect, so
 * it is far from free; call it only on a path that is already logging. The
 * summary can contain page-controlled text (Name, AutomationId) and is not
 * sanitised here.
 *
 * @param element UIA element; may be null (returns "<null>").
 * @return One-line summary: control type with its localized name in
 *         parentheses, then framework id, class, name, automation id and
 *         rect. The rect field is "<none>" when the element has no usable
 *         rectangle.
 * @ingroup FillController
 */
QString describeAutomationElement(IUIAutomationElement* element);

/**
 * @brief Bounded DFS for a password-classified UIA descendant under root.
 *
 * Pre-order: inspect a child, recurse into it, then move to the next
 * sibling. The walk returns as soon as @ref inspectElementPasswordState
 * reports a match. A child whose rect is readable but does not contain
 * (@p x, @p y) is skipped entirely - neither inspected nor recursed into,
 * and it spends no budget. A child whose rect cannot be read is inspected,
 * so an element with no usable geometry is treated permissively.
 *
 * @param walker UIA tree walker; null returns false.
 * @param root Subtree root, never inspected itself; null returns false.
 * @param x Screen-space click X coordinate, used for bounding-rect filtering.
 * @param y Screen-space click Y coordinate.
 * @param depth Current recursion depth; the caller passes 0. Recursion stops
 *              once depth reaches @ref kMaxUiaDescendantDepth.
 * @param nodesRemaining Descendant budget shared by the whole walk, passed
 *                       by reference and decremented once per inspected
 *                       node. The caller seeds it with
 *                       @ref kMaxUiaDescendantNodes and can read the
 *                       remainder afterwards. At zero the walk unwinds.
 * @param observedAny In/out flag, OR-accumulated across the whole walk and
 *                    never cleared. Initialise it to false.
 * @return True when a positive password match was found. False covers both
 *         "searched and found nothing" and "budget or depth ran out";
 *         @p nodesRemaining and @p observedAny distinguish the two.
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
 *
 * A form-like ancestor has at least two direct Edit/Custom children and a
 * bounding rectangle no larger than half the primary monitor area (the cap
 * prevents landing on \<body\> for short pages). The walk visits at most 12
 * levels above @p start.
 *
 * The area cap aborts rather than skips: the first oversized parent ends the
 * search with nullptr, because every further ancestor is at least as large.
 * A parent whose rectangle cannot be read bypasses the cap and is still
 * tested for peers.
 *
 * @param walker UIA tree walker; null returns nullptr.
 * @param start Element to start walking from; null returns nullptr. It is
 *              never returned itself - the search begins at its parent.
 * @return AddRef'd form ancestor, or nullptr when no form was found. On a
 *         non-null return the caller owns one reference and must Release it.
 *         Nothing is left AddRef'd on the nullptr paths.
 * @ingroup FillController
 *
 * @note The cap uses @c SM_CXSCREEN and @c SM_CYSCREEN, so it is half the
 *       primary monitor even when the click is on a secondary monitor, and
 *       it is measured in physical pixels.
 */
IUIAutomationElement* findFormAncestor(IUIAutomationTreeWalker* walker,
                                       IUIAutomationElement* start);

/**
 * @brief Bounded DFS collecting Edit/Custom inputs under root.
 *
 * Iterative depth-first walk over @p root's subtree, capped at 6 levels
 * below @p root and 32 collected elements. Neither cap comes from the
 * kMaxUia* constants in this header. @p root itself is never collected.
 * Order is document order within the raw view, so peer indices line up with
 * on-screen order for a normal form.
 *
 * @param walker UIA tree walker; null returns with @p out untouched.
 * @param root Subtree root; null returns with @p out untouched.
 * @param out Destination vector. Elements are appended, not assigned, and
 *            the 32-element cap counts the whole vector including anything
 *            already in it. Each pushed element carries one reference that
 *            the caller must Release.
 * @ingroup FillController
 */
void enumerateFormInputs(IUIAutomationTreeWalker* walker,
                         IUIAutomationElement* root,
                         std::vector<IUIAutomationElement*>& out);

}  // namespace seal

#endif  // USE_QT_UI
