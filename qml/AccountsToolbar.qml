import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    property int accountCount: 0
    property bool isCompact: false

    readonly property var sortLabels: ["A-Z", "Z-A", "Grouped by brand"]

    implicitHeight: 32
    gradient: Gradient {
        GradientStop { position: 0; color: Theme.bgTableHeaderTop }
        GradientStop { position: 1; color: Theme.bgTableHeaderEnd }
    }
    radius: Theme.radiusLarge
    clip: true

    Rectangle {
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: Theme.radiusLarge
        gradient: Gradient {
            GradientStop { position: 0; color: Theme.bgTableHeaderEnd }
            GradientStop { position: 1; color: Theme.bgTableHeaderEnd }
        }
    }

    Rectangle {
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: 1
        color: Theme.borderSubtle
    }

    component DropdownButton: Item {
        id: ddRoot
        property var labels: []
        property int currentIndex: 0
        property string labelPrefix: ""
        signal indexChosen(int newIndex)

        implicitWidth: ddContent.implicitWidth + 22
        implicitHeight: 22

        Rectangle {
            anchors.fill: parent
            radius: 4
            color: ddHover.containsMouse || menuPopup.opened
                   ? Theme.bgHover
                   : "transparent"
            border.width: 1
            border.color: menuPopup.opened
                          ? Theme.borderBright
                          : ddHover.containsMouse
                            ? Theme.borderMedium
                            : Theme.borderSubtle

            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }
        }

        Row {
            id: ddContent
            anchors.centerIn: parent
            spacing: 4

            Text {
                text: ddRoot.labelPrefix + (ddRoot.labels[ddRoot.currentIndex] || "")
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                color: menuPopup.opened || ddHover.containsMouse
                       ? Theme.textPrimary
                       : Theme.textSecondary
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }

            SvgIcon {
                source: Theme.iconChevronDown
                width: Theme.px(9)
                height: Theme.px(9)
                color: menuPopup.opened || ddHover.containsMouse
                       ? Theme.textPrimary
                       : Theme.textMuted
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
        }

        MouseArea {
            id: ddHover
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                if (menuPopup.opened) menuPopup.close();
                else menuPopup.open();
            }
        }

        Menu {
            id: menuPopup
            y: ddRoot.height + 2
            x: 0

            background: Rectangle {
                implicitWidth: 160
                color: Theme.bgDialog
                border.width: 1
                border.color: Theme.borderMedium
                radius: Theme.radiusMedium
            }

            Repeater {
                model: ddRoot.labels
                MenuItem {
                    id: menuItem
                    text: modelData
                    height: 26
                    contentItem: Text {
                        text: menuItem.text
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeSmall
                        font.weight: ddRoot.currentIndex === index ? Font.DemiBold : Font.Medium
                        color: ddRoot.currentIndex === index
                               ? Theme.accent
                               : (menuItem.hovered ? Theme.textPrimary : Theme.textSecondary)
                        verticalAlignment: Text.AlignVCenter
                        leftPadding: 10
                    }
                    background: Rectangle {
                        color: menuItem.hovered ? Theme.bgHover : "transparent"
                        topLeftRadius: index === 0 ? Theme.radiusMedium : 0
                        topRightRadius: index === 0 ? Theme.radiusMedium : 0
                        bottomLeftRadius: index === ddRoot.labels.length - 1 ? Theme.radiusMedium : 0
                        bottomRightRadius: index === ddRoot.labels.length - 1 ? Theme.radiusMedium : 0
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }
                    onTriggered: ddRoot.indexChosen(index)
                }
            }
        }
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 14
        anchors.rightMargin: 14
        spacing: 10

        Text {
            text: root.accountCount + (root.accountCount === 1 ? " ACCOUNT" : " ACCOUNTS")
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            font.weight: Font.DemiBold
            font.letterSpacing: 1.0
            color: Theme.textMuted
        }

        Item { Layout.fillWidth: true }

        DropdownButton {
            labels: root.sortLabels
            labelPrefix: "Sort: "
            currentIndex: Theme.sortMode
            visible: !root.isCompact
            onIndexChosen: function(newIndex) { Theme.sortMode = newIndex; }
        }
    }
}
