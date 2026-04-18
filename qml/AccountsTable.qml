import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

// Vault credentials table.
//
// Uses a custom column header + bare ListView rather than Qt's TableView because
// TableView doesn't support per-row selection glow, zebra striping, or custom
// empty-state placeholders without heavy workarounds. The trade-off is manually
// matching column widths between header and delegate, but with only three fixed
// columns this is straightforward.
//
// The model is a VaultListModel (QAbstractListModel subclass) that exposes
// platform, maskedUsername, maskedPassword, and recordIndex roles. Filtering
// is handled inside the model (C++ side) so the ListView just renders what it gets.

Rectangle {
    id: root

    property var model              // VaultListModel instance from Backend
    property int selectedRow: -1    // Visual index of the selected row (-1 = none)
    property bool searchActive: false  // True when the search bar has text
    property bool vaultLoaded: false   // Controls which empty-state placeholder shows
    property bool isCompact: false     // Compact mode: scroll to top and hide scrollbar
    readonly property bool showNoResultsState: listView.count === 0 && root.searchActive && root.vaultLoaded
    readonly property bool showNoVaultState: listView.count === 0 && !root.vaultLoaded
    readonly property bool showEmptyVaultState: listView.count === 0 && root.vaultLoaded && !root.searchActive

    signal rowClicked(int row)
    signal addAccountRequested()
    signal clearSearchRequested()

    component EmptyStatePanel: Rectangle {
        id: panel
        property string titleText: ""
        property string messageText: ""
        property string iconSource: ""
        property color tone: Theme.accent
        property real maximumPanelWidth: Theme.px(440)
        default property alias actions: actionRow.data

        width: parent ? Math.min(parent.width - 40, maximumPanelWidth) : maximumPanelWidth
        implicitHeight: contentColumn.implicitHeight + 48
        radius: Theme.radiusLarge
        gradient: Gradient {
            GradientStop { position: 0; color: Theme.bgInput }
            GradientStop { position: 1; color: Theme.bgCardEnd }
        }
        border.width: 1
        border.color: Theme.borderMedium
        clip: true

        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: 1
            color: Theme.surfaceHighlight
            opacity: 0.75
        }

        Rectangle {
            width: parent.width * 0.62
            height: parent.height * 0.90
            radius: width / 2
            anchors.horizontalCenter: parent.horizontalCenter
            y: -height * 0.38
            color: Qt.rgba(panel.tone.r, panel.tone.g, panel.tone.b, Theme.dark ? 0.12 : 0.08)
        }

        Column {
            id: contentColumn
            width: parent.width - 48
            anchors.centerIn: parent
            spacing: 12

            Rectangle {
                width: 46
                height: 46
                radius: width / 2
                anchors.horizontalCenter: parent.horizontalCenter
                color: "transparent"

                SvgIcon {
                    anchors.centerIn: parent
                    source: panel.iconSource
                    width: Theme.px(18)
                    height: Theme.px(18)
                    color: panel.tone
                }
            }

            Text {
                width: parent.width
                text: panel.titleText
                font.family: Theme.fontFamily
                font.pixelSize: Theme.px(18)
                font.weight: Font.DemiBold
                color: Theme.textPrimary
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            Text {
                width: parent.width
                text: panel.messageText
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.textSecondary
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            Row {
                id: actionRow
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter
            }
        }
    }

    radius: Theme.radiusLarge
    // Top-to-bottom gradient simulates overhead lighting for card depth.
    gradient: Gradient {
        GradientStop { position: 0; color: Theme.bgCard }
        GradientStop { position: 1; color: Theme.bgCardEnd }
    }
    border.width: 1
    border.color: Theme.dark ? Theme.borderMedium : Theme.borderSubtle
    clip: true

    Rectangle {
        width: parent.width * 0.40
        height: parent.height * 0.30
        radius: width / 2
        x: parent.width * 0.56
        y: -height * 0.35
        color: Theme.surfaceGlow
        opacity: 0.20
    }

    Rectangle {
        width: parent.width * 0.36
        height: parent.height * 0.26
        radius: width / 2
        x: parent.width * -0.06
        y: parent.height * 0.62
        color: Theme.surfaceGlow
        opacity: 0.10
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Inset the header by 1 px so the outer shell border stays visible.
        // A bottom fill strip squares off the lower corners where it meets the rows.
        Rectangle {
            Layout.fillWidth: true
            Layout.topMargin: 1
            Layout.leftMargin: 1
            Layout.rightMargin: 1
            implicitHeight: 44
            gradient: Gradient {
                GradientStop { position: 0.0;  color: Theme.bgTableHeaderEdge }
                GradientStop { position: 0.07; color: Theme.bgTableHeaderTop }
                GradientStop { position: 1;    color: Theme.bgTableHeaderEnd }
            }
            radius: Theme.radiusLarge
            clip: true

            // Masks bottom rounded corners.
            Rectangle {
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                height: Theme.radiusLarge
                color: "transparent"
                gradient: Gradient {
                    GradientStop { position: 0; color: Theme.bgTableHeaderEnd }
                    GradientStop { position: 1; color: Theme.bgTableHeaderEnd }
                }
            }

            // Bottom border
            Rectangle {
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                height: 1
                color: Theme.borderSubtle
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 14
                anchors.rightMargin: 14
                spacing: 0

                Row {
                    Layout.preferredWidth: 200
                    spacing: 6

                    SvgIcon {
                        source: Theme.iconService
                        width: Theme.iconSizeSmall
                        height: Theme.iconSizeSmall
                        color: Theme.accent
                        anchors.verticalCenter: parent.verticalCenter
                    }
                    Text {
                        text: "SERVICE"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeSmall
                        font.bold: true
                        font.letterSpacing: 1.0
                        color: Theme.accent
                    }
                }
                Row {
                    Layout.preferredWidth: 200
                    spacing: 6

                    SvgIcon {
                        source: Theme.iconUsername
                        width: Theme.iconSizeSmall
                        height: Theme.iconSizeSmall
                        color: Theme.accent2
                        anchors.verticalCenter: parent.verticalCenter
                    }
                    Text {
                        text: "USERNAME"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeSmall
                        font.bold: true
                        font.letterSpacing: 1.0
                        color: Theme.accent2
                    }
                }
                Row {
                    Layout.fillWidth: true
                    spacing: 6

                    SvgIcon {
                        source: Theme.iconPassword
                        width: Theme.iconSizeSmall
                        height: Theme.iconSizeSmall
                        color: Theme.accent3
                        anchors.verticalCenter: parent.verticalCenter
                    }
                    Text {
                        text: "PASSWORD"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeSmall
                        font.bold: true
                        font.letterSpacing: 1.0
                        color: Theme.accent3
                    }
                }
            }
        }

        ListView {
            id: listView
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: 1
            Layout.rightMargin: 1
            Layout.bottomMargin: 1
            model: root.model
            clip: true
            // No elastic overscroll on desktop.
            boundsBehavior: Flickable.StopAtBounds
            interactive: !root.isCompact

            // Thin floating scrollbar thumb, no track background.
            ScrollBar.vertical: ScrollBar {
                id: vScrollBar
                policy: root.isCompact || listView.contentHeight <= listView.height ? ScrollBar.AlwaysOff : ScrollBar.AsNeeded
                contentItem: Rectangle {
                    implicitWidth: 6
                    radius: 3
                    color: vScrollBar.hovered || vScrollBar.pressed ? Theme.scrollThumbHover : Theme.scrollThumb
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
                background: Item {}
            }

            // Snap to top when entering compact mode.
            onInteractiveChanged: if (!interactive) positionViewAtBeginning()

            // Each delegate receives `selected` from the parent's binding; clicking
            // a row emits rowClicked(index) which Main.qml handles with toggle logic
            // (clicking the same row again deselects it).
            delegate: AccountRow {
                width: listView.width
                selected: root.selectedRow === index
                onClicked: root.rowClicked(index)
            }

            // Empty state placeholders. Two variants:
            // 1. Search active but no matches: "No accounts found" with filter icon
            // 2. No vault loaded / no accounts: "No accounts loaded" with shield icon
            // Only one is visible at a time based on searchActive and vaultLoaded flags.
            Column {
                anchors.centerIn: parent
                visible: root.showNoResultsState
                spacing: 10

                SvgIcon {
                    source: Theme.iconFilterSlash
                    width: Theme.px(32)
                    height: Theme.px(32)
                    color: Theme.accentMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "No accounts match this search"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLarge
                    font.weight: Font.Medium
                    color: Theme.textMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "Try a broader term or clear the filter to see every credential again."
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textDisabled
                    anchors.horizontalCenter: parent.horizontalCenter
                }
            }

            Column {
                anchors.centerIn: parent
                visible: root.showNoVaultState
                spacing: 10

                SvgIcon {
                    source: Theme.iconShieldHalved
                    width: Theme.px(32)
                    height: Theme.px(32)
                    color: Theme.accentMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "Load a vault to get started"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLarge
                    font.weight: Font.Medium
                    color: Theme.textMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "Open an existing .seal vault or create your first credential locally."
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textDisabled
                    anchors.horizontalCenter: parent.horizontalCenter
                }
            }

            EmptyStatePanel {
                anchors.centerIn: parent
                visible: root.showEmptyVaultState
                iconSource: Theme.iconPlus
                tone: Theme.accent2
                titleText: "This vault is ready for its first account"
                messageText: "Add a credential and the table, search, and autofill tools will activate."
            }
        }
    }
}
