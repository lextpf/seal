import QtQuick
import QtQuick.Controls

// Live search field. Typing here instantly updates Backend.searchFilter, which
// triggers VaultListModel::setFilter() in C++ to re-filter the visible rows.
// The model uses case-insensitive substring matching against platform names.
//
// Layout: [search icon] [text input] [match count text] [X clear button]
// The count label and clear button appear only when the field has text.

TextField {
    id: root
    property int resultCount: 0
    property bool vaultLoaded: true
    readonly property bool filtering: text.trim().length > 0
    readonly property string resultLabel: resultCount === 1 ? "1 match" : resultCount + " matches"

    // Debounced search signal. Fires 200 ms after the last keystroke so C++
    // model filtering is not triggered on every single character typed.
    signal searchRequested(string text)

    Timer {
        id: _debounce
        interval: 200
        onTriggered: root.searchRequested(root.text)
    }
    onTextChanged: _debounce.restart()
    onVaultLoadedChanged: if (!vaultLoaded && text.length > 0) text = ""

    enabled: vaultLoaded
    placeholderText: vaultLoaded ? "Search services, usernames, or passwords"
                                 : "Load a vault or add an account to enable search"
    placeholderTextColor: Theme.textPlaceholder
    color: Theme.textPrimary
    font.family: Theme.fontFamily
    font.pixelSize: Theme.fontSizeLarge
    selectByMouse: true
    selectionColor: Theme.btnGradBot
    selectedTextColor: Theme.textOnAccent

    // Padding reserves space for search icon (left) plus count label and clear button (right).
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
        visible: root.filtering
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

    // Clear button. -6 margin expands hit area without enlarging the icon.
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
            // Clear text and re-focus so the user can immediately start a new search.
            onClicked: { root.text = ""; root.forceActiveFocus(); }
        }
    }

    // IBeamCursor on hover signals editable text.
    HoverHandler {
        id: searchHover
        cursorShape: root.enabled ? Qt.IBeamCursor : Qt.ArrowCursor
    }

    // Three-state border: focused > hovered > idle.
    background: Rectangle {
        implicitHeight: 44
        radius: Theme.radiusLarge
        color: !root.enabled ? Theme.bgCard : root.activeFocus ? Theme.bgInputFocus : Theme.bgCard
        border.width: 1
        border.color: !root.enabled ? (Theme.dark ? Theme.borderMedium : Theme.borderSubtle)
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
            height: 1
            color: Theme.surfaceHighlight
            opacity: !root.enabled ? 0.22 : root.activeFocus ? 0.48 : searchHover.hovered ? 0.26 : Theme.dark ? 0.14 : 0.12
            Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
        }

        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }
    }
}
