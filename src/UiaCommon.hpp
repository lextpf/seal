#pragma once

/**
 * @brief Share metadata scans and bounded UIA tree traversal.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Ancestor and descendant limits bound query counts, not provider response time.
 * Form helpers use separate caps: 12 ancestors, 6 descendant levels, 32 inputs.
 *
 * UiaHintObservation distinguishes unreadable data from explicit negatives.
 * m_Observed is diagnostic only; the metadata probe does not use it to suppress
 * form-context fallback.
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
 * @brief Distinguish positive hints, explicit negatives, and unavailable UIA data.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Only `inspectElementPasswordState` can report an observed negative. Metadata scans
 * set observed only on a match; readable non-matching text leaves both flags false.
 * Source and matched text describe a match. A negative IsPassword read may retain
 * that source label without matched text.
 *
 * | m_Observed | m_Matched | Meaning                                                    |
 * |------------|-----------|------------------------------------------------------------|
 * | False      | False     | No matching hint; explicit flags unavailable or unchecked. |
 * | True       | False     | Explicit flags read as false; no hint matched.             |
 * | True       | True      | Positive match; m_Source names the property.               |
 */
struct UiaHintObservation
{
    bool m_Observed = false;  ///< Explicit flag read succeeded, or a metadata hint matched.
    bool m_Matched = false;   ///< True if a positive hint matched the queried field type.
    QString m_Source;         ///< Property that produced the match (e.g. "Name", "HelpText").
    QString m_MatchedText;    ///< Original property value that triggered the match.
};

/**
 * @struct StringPropertyProbe
 * @brief Property ID and log-safe label shared by ordered metadata scans.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 */
struct StringPropertyProbe
{
    PROPERTYID m_PropertyId = 0;  ///< UIA property id (e.g. UIA_NamePropertyId).
    const char* m_Label = "";     ///< Static log-safe label (e.g. "Name").
};

/**
 * @fn QString takeBstr(BSTR text)
 * @brief Copy a BSTR to QString and free the BSTR before return.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * @param text Nullable; ownership transfers to this call.
 * @return Empty for null input.
 */
QString takeBstr(BSTR text);

/**
 * @fn QString currentStringProperty(IUIAutomationElement* element, PROPERTYID propertyId)
 * @brief Copy a BSTR or by-reference BSTR property and clear its VARIANT.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * @return Empty for null elements, failed reads, absent values, or other types.
 */
QString currentStringProperty(IUIAutomationElement* element, PROPERTYID propertyId);

/**
 * @fn bool containsPasswordHint(const QString& rawText)
 * @brief Match English or German password keywords by lowercase substring.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Trims whitespace; empty input returns false.
 */
bool containsPasswordHint(const QString& rawText);

/**
 * @fn bool containsUsernameHint(const QString& rawText)
 * @brief Match English or German username keywords by lowercase substring.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Bare user is excluded to avoid user-agent. Broader terms such as account still
 * match containers such as account-menu, so this remains tier-2 evidence.
 * Empty or whitespace-only input returns false.
 */
bool containsUsernameHint(const QString& rawText);

/**
 * @fn bool isEditLikeControlType(IUIAutomationElement* element)
 * @brief Accept Edit, Custom, Pane, and Document control types.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * @return False for other types or accessor failure.
 * @pre Element is non-null.
 */
bool isEditLikeControlType(IUIAutomationElement* element);

/**
 * @fn UiaHintObservation inspectPasswordHintMetadata(IUIAutomationElement* element, bool
 *     skipControlTypeGate = false)
 * @brief Return the first password hint from the shared nine-property scan.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Reads AutomationId, Name, HelpText, FullDescription, LocalizedControlType,
 * ClassName, ItemType, AriaRole, and AriaProperties in that order.
 *
 * @param element Nullable.
 * @param skipControlTypeGate True if the caller already established an input wrapper.
 * @return Both flags true with source and raw text on a hit; both false otherwise.
 */
UiaHintObservation inspectPasswordHintMetadata(IUIAutomationElement* element,
                                               bool skipControlTypeGate = false);

/**
 * @fn UiaHintObservation inspectUsernameHintMetadata(IUIAutomationElement* element, bool
 *     skipControlTypeGate = false)
 * @brief Apply the shared metadata scan to username hints.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Independent of password scanning; both can match and the caller resolves priority.
 *
 * @param element Nullable.
 * @param skipControlTypeGate True if the caller already established an input wrapper.
 * @return Both flags false when no hint matches.
 * @see inspectPasswordHintMetadata
 */
UiaHintObservation inspectUsernameHintMetadata(IUIAutomationElement* element,
                                               bool skipControlTypeGate = false);

/**
 * @fn const char* controlTypeToString(CONTROLTYPEID controlType)
 * @brief Static control-type log label; Unknown for unrecognized IDs.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 */
const char* controlTypeToString(CONTROLTYPEID controlType);

/**
 * @fn bool rectContainsPoint(const RECT& rect, LONG x, LONG y)
 * @brief Test a rectangle with exclusive right and bottom edges.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Coordinates are physical screen pixels without DPI conversion.
 *
 * @return False for inverted or zero-area rectangles.
 */
bool rectContainsPoint(const RECT& rect, LONG x, LONG y);

/**
 * @fn bool tryGetCurrentBoundingRect(IUIAutomationElement* element, RECT* rect)
 * @brief Read a non-empty bounding rectangle.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * False means geometry is unknown; callers may remain permissive.
 *
 * @param element Nullable.
 * @param rect Nullable; written only on success.
 * @return False for null arguments, failed reads, or empty geometry.
 */
bool tryGetCurrentBoundingRect(IUIAutomationElement* element, RECT* rect);

/**
 * @fn UiaHintObservation inspectElementPasswordState(IUIAutomationElement* element, bool
 *     skipControlTypeGate = false)
 * @brief Check IsPassword, LegacyIAccessible protected state, then metadata.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Returns the first positive. Explicit flag reads set observed even when false.
 * All acquired COM references are released before return.
 *
 * @param element Nullable.
 * @param skipControlTypeGate Applies only to the metadata fallback.
 * @return Source IsPassword or LegacyState for explicit flags; otherwise a
 *         metadata label. Tier-1 callers must reject metadata sources.
 */
UiaHintObservation inspectElementPasswordState(IUIAutomationElement* element,
                                               bool skipControlTypeGate = false);

/**
 * @fn UiaHintObservation inspectElementUsernameState(IUIAutomationElement* element)
 * @brief Scan username metadata without filtering control types.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Form callers may supply wrappers rather than Edit elements.
 *
 * @param element Nullable.
 * @return Observed is true only with a match.
 */
UiaHintObservation inspectElementUsernameState(IUIAutomationElement* element);

/**
 * @fn QString describeAutomationElement(IUIAutomationElement* element)
 * @brief Format UIA properties and geometry for diagnostics.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Reads five string properties, control type, and bounds. Call only when logging.
 * Contains unsanitized page-controlled text.
 *
 * @param element Nullable; null returns <null>.
 * @return Geometry is <none> when unavailable.
 */
QString describeAutomationElement(IUIAutomationElement* element);

/**
 * @fn bool searchDescendantsForPassword(IUIAutomationTreeWalker* walker, IUIAutomationElement*
 *     root, LONG x, LONG y, int depth, int& nodesRemaining, bool& observedAny)
 * @brief Search descendants in pre-order for a password hint.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Skip a node and its subtree without spending budget if readable bounds exclude
 * the click. Unknown bounds remain eligible. Root itself is not inspected.
 *
 * @param walker Null returns false.
 * @param root Null returns false.
 * @param x Physical screen pixels.
 * @param y Physical screen pixels.
 * @param depth Start at 0; stops at kMaxUiaDescendantDepth.
 * @param nodesRemaining Seed with kMaxUiaDescendantNodes; decremented per inspected node.
 * @param observedAny Initialize false; accumulates observations without clearing.
 * @return False for no match or exhausted limits; inspect remaining budget and observations.
 */
bool searchDescendantsForPassword(IUIAutomationTreeWalker* walker,
                                  IUIAutomationElement* root,
                                  LONG x,
                                  LONG y,
                                  int depth,
                                  int& nodesRemaining,
                                  bool& observedAny);

/**
 * @fn IUIAutomationElement* findFormAncestor(IUIAutomationTreeWalker* walker, IUIAutomationElement*
 *     start)
 * @brief Find an ancestor with two direct Edit/Custom children.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Searches at most 12 parents. Aborts at the first readable area larger than half
 * the primary monitor, measured in physical pixels even on secondary monitors.
 * Unreadable bounds bypass the cap.
 *
 * @param walker Null returns nullptr.
 * @param start Null returns nullptr; start itself is never returned.
 * @return Caller-owned AddRef'd ancestor; release it. Returns `nullptr` if none qualifies.
 */
IUIAutomationElement* findFormAncestor(IUIAutomationTreeWalker* walker,
                                       IUIAutomationElement* start);

/**
 * @fn void enumerateFormInputs(IUIAutomationTreeWalker* walker, IUIAutomationElement* root,
 *     std::vector<IUIAutomationElement*>& out)
 * @brief Append Edit/Custom descendants in raw-view document order.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Excludes root; caps traversal at 6 levels and the entire output vector at
 * 32 entries. These limits are independent of kMaxUia constants.
 *
 * @param walker Null leaves out unchanged.
 * @param root Null leaves out unchanged.
 * @param out Caller must release each appended reference.
 */
void enumerateFormInputs(IUIAutomationTreeWalker* walker,
                         IUIAutomationElement* root,
                         std::vector<IUIAutomationElement*>& out);

}  // namespace seal

#endif  // USE_QT_UI
