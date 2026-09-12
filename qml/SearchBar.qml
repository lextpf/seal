import QtQuick
import QtQuick.Controls

/*!
 * \qmltype SearchBar
 * \inqmlmodule seal
 * \brief Collect service-name search input with a short delay.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Each text change restarts a 200 ms timer, including programmatic assignments
 * and clearing. The timer emits the current text unchanged; the owner applies
 * the filter through AppViewModel and supplies the resulting row count.
 *
 * Unloading a vault disables input and clears non-empty text. This schedules an
 * empty filter request so the next vault does not inherit the previous search.
 * Whitespace-only input hides the match count but is still emitted.
 */
TextField {
    id: root
    /*!
     * Number of visible rows after filtering; the owner supplies this value.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property int resultCount: 0
    /*!
     * Enable input; changing to false also clears non-empty search text.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool vaultLoaded: true
    /*!
     * True when input contains non-whitespace text; controls search feedback only.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool filtering: text.trim().length > 0
    /*!
     * Reserve the match-count label only at widths of at least 320 logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool showResultLabel: width >= 320
    /*!
     * Match count with singular wording for one row; the label is hidden without a filter.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property string resultLabel: resultCount === 1 ? "1 match" : resultCount + " matches"

    /*!
     * \brief Request a filter update after 200 ms without a text change.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * The \a text value is not trimmed. An empty value requests all rows.
     */
    signal searchRequested(string text)

    // Restart the delay for every text change, including clearing and owner assignments.
    Timer {
        id: _debounce
        interval: 200
        onTriggered: root.searchRequested(root.text)
    }
    onTextChanged: _debounce.restart()
    // Clear a stale search when the vault closes.
    onVaultLoadedChanged: if (!vaultLoaded && text.length > 0) text = ""

    enabled: vaultLoaded
    placeholderText: vaultLoaded ? "Search service names" : "Load a vault to search"
    placeholderTextColor: Theme.textPlaceholder
    color: Theme.textPrimary
    font.family: Theme.fontFamily
    font.pixelSize: Theme.fontSizeLarge
    selectByMouse: true
    selectionColor: Theme.btnGradBot
    selectedTextColor: Theme.textOnAccent

    // Reserve text padding for both overlays.
    leftPadding: searchIcon.width + 24
    rightPadding: 16
                + (clearBtn.visible ? clearBtn.width + 16 : 0)
                + (resultText.visible ? resultText.implicitWidth + 10 : 0)
    topPadding: 10
    bottomPadding: 10

    SvgIcon {
        id: searchIcon
        source: Theme.iconSearch
        width: Theme.iconSizeMedium
        height: Theme.iconSizeMedium
        color: !root.enabled ? Theme.textDisabled
             : root.activeFocus ? Theme.accent
             : root.filtering ? Theme.textSecondary
             : searchHover.hovered ? Theme.textSubtle
             : Theme.textPlaceholder
        anchors.left: parent.left
        anchors.leftMargin: 12
        anchors.verticalCenter: parent.verticalCenter

        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
    }

    Text {
        id: resultText
        visible: root.filtering && root.showResultLabel
        opacity: visible ? 1 : 0
        text: root.resultLabel
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontSizeSmall
        font.weight: Font.DemiBold
        color: root.activeFocus ? Theme.textSecondary : Theme.textMuted
        anchors.right: clearBtn.visible ? clearBtn.left : parent.right
        anchors.rightMargin: clearBtn.visible ? 8 : 16
        anchors.verticalCenter: parent.verticalCenter
        verticalAlignment: Text.AlignVCenter
        Behavior on opacity { NumberAnimation { duration: 120 } }
        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
    }

    // Negative margin enlarges the hit area only.
    SvgIcon {
        id: clearBtn
        source: Theme.iconXmark
        width: Theme.iconSizeSmall
        height: Theme.iconSizeSmall
        color: clearArea.containsMouse ? Theme.textSecondary : Theme.textMuted
        anchors.right: parent.right
        anchors.rightMargin: 10
        anchors.verticalCenter: parent.verticalCenter
        visible: root.enabled && root.text.length > 0
        opacity: visible ? 1 : 0

        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        Behavior on opacity { NumberAnimation { duration: 120 } }

        MouseArea {
            id: clearArea
            anchors.fill: parent
            anchors.margins: -6
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: { root.text = ""; root.forceActiveFocus(); }
        }
    }

    HoverHandler {
        id: searchHover
        cursorShape: root.enabled ? Qt.IBeamCursor : Qt.ArrowCursor
    }

    // State precedence: disabled, focused, hovered, idle.
    background: Rectangle {
        implicitHeight: 40
        radius: Theme.radiusMedium
        color: !root.enabled ? Theme.bgInputGlass
             : root.activeFocus ? Theme.bgInputGlassFocus
             : searchHover.hovered ? Theme.bgInputGlassHover
             : Theme.bgInputGlass
        opacity: root.enabled ? 1.0 : 0.55
        border.width: Theme.strokeRegular
        border.color: !root.enabled ? Theme.borderSubtle
                    : root.activeFocus ? Theme.borderFocus
                    : searchHover.hovered ? (Theme.dark ? Theme.borderHighlight : Theme.borderMedium)
                    : (Theme.dark ? Theme.borderMedium : Theme.borderSubtle)
        clip: true

        Rectangle {
            width: parent.width * 0.72
            height: parent.height * 1.4
            radius: height / 2
            x: parent.width * 0.06
            y: -height * 0.45
            color: Theme.surfaceGlow
            opacity: !root.enabled ? 0.08 : root.activeFocus ? 0.32 : searchHover.hovered ? 0.16 : 0.03
            Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
        }

        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: Theme.radiusMedium
            anchors.rightMargin: Theme.radiusMedium
            height: Theme.strokeDivider
            color: Theme.surfaceHighlight
            opacity: !root.enabled ? 0.22 : root.activeFocus ? 0.48 : searchHover.hovered ? 0.26 : Theme.dark ? 0.14 : 0.12
            Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
        }

        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }
    }
}
