import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

// Vault credentials table. Custom header + ListView for full control over
// row rendering (selection glow, zebra striping, masked display).

Rectangle {
    id: root

    property var model
    property int selectedRow: -1
    property bool searchActive: false
    property bool vaultLoaded: false

    signal rowClicked(int row)

    radius: Theme.radiusLarge
    // Card gradient for "lit from above" depth.
    gradient: Gradient {
        GradientStop { position: 0; color: Theme.bgCard }
        GradientStop { position: 1; color: Theme.bgCardEnd }
    }
    border.width: 1
    border.color: Theme.borderSubtle
    clip: true

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Header with rounded top corners only (bottom corners masked by overlay).
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 44
            gradient: Gradient {
                GradientStop { position: 0; color: Theme.bgTableHeaderTop }
                GradientStop { position: 1; color: Theme.bgTableHeaderEnd }
            }
            radius: Theme.radiusLarge

            // Masks bottom rounded corners
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
                        color: Theme.accent
                        anchors.verticalCenter: parent.verticalCenter
                    }
                    Text {
                        text: "USERNAME"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeSmall
                        font.bold: true
                        font.letterSpacing: 1.0
                        color: Theme.accent
                    }
                }
                Row {
                    Layout.fillWidth: true
                    spacing: 6

                    SvgIcon {
                        source: Theme.iconPassword
                        width: Theme.iconSizeSmall
                        height: Theme.iconSizeSmall
                        color: Theme.accent
                        anchors.verticalCenter: parent.verticalCenter
                    }
                    Text {
                        text: "PASSWORD"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeSmall
                        font.bold: true
                        font.letterSpacing: 1.0
                        color: Theme.accent
                    }
                }
            }
        }

        ListView {
            id: listView
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: root.model
            clip: true
            // No elastic overscroll on desktop.
            boundsBehavior: Flickable.StopAtBounds

            // Thin floating scrollbar thumb, no track background.
            ScrollBar.vertical: ScrollBar {
                id: vScrollBar
                policy: ScrollBar.AsNeeded
                contentItem: Rectangle {
                    implicitWidth: 6
                    radius: 3
                    color: vScrollBar.hovered || vScrollBar.pressed ? Theme.scrollThumbHover : Theme.scrollThumb
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
                background: Item {}
            }

            // Selection state passed in from parent.
            delegate: AccountRow {
                width: listView.width
                selected: root.selectedRow === index
                onClicked: root.rowClicked(index)
            }

            // Empty state - no search results
            Column {
                anchors.centerIn: parent
                visible: listView.count === 0 && root.searchActive && root.vaultLoaded
                spacing: 10

                SvgIcon {
                    source: Theme.iconFilterSlash
                    width: Theme.px(32)
                    height: Theme.px(32)
                    color: Theme.accentMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "No accounts found"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLarge
                    font.weight: Font.Medium
                    color: Theme.textMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "Try a different search term"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textDisabled
                    anchors.horizontalCenter: parent.horizontalCenter
                }
            }

            // Empty state - no vault loaded
            Column {
                anchors.centerIn: parent
                visible: listView.count === 0 && !root.searchActive
                spacing: 10

                SvgIcon {
                    source: Theme.iconShieldHalved
                    width: Theme.px(32)
                    height: Theme.px(32)
                    color: Theme.accentMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "No accounts loaded"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLarge
                    font.weight: Font.Medium
                    color: Theme.textMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "Load a vault or add a new account to get started"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textDisabled
                    anchors.horizontalCenter: parent.horizontalCenter
                }
            }
        }
    }
}
