import QtQuick
import QtQuick.Layouts

// Bottom status bar. Spans the full window width (sits outside the inner
// content margins) to create a clear visual boundary.
//
// Layout: [status text] ... [vault pill] [count pill] [fill-armed pill]
//
// Capsules keep the footer readable at a glance while preserving a low visual
// weight when the app is idle.

Rectangle {
    id: root

    property string statusText: "Ready"
    property bool fillArmed: false
    property string vaultFileName: ""
    property int accountCount: 0

    implicitHeight: 36
    gradient: Gradient {
        GradientStop { position: 0; color: Theme.bgFooterTop }
        GradientStop { position: 1; color: Theme.bgFooterEnd }
    }

    // Top border.
    Rectangle {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: 1
        color: Theme.borderDim
    }

    component StatusPill: Rectangle {
        id: pill
        property alias iconSource: pillIcon.source
        property string label: ""
        property color iconColor: Theme.textIcon
        property bool strong: false
        property int maxLabelWidth: 220
        readonly property int labelWidth: Math.min(maxLabelWidth, pillLabel.implicitWidth)

        implicitHeight: 24
        implicitWidth: pillRow.implicitWidth + 20
        radius: implicitHeight / 2
        clip: true
        gradient: Gradient {
            GradientStop { position: 0; color: pill.strong ? Theme.statusChipStrongTop : Theme.statusChipTop }
            GradientStop { position: 1; color: pill.strong ? Theme.statusChipStrongEnd : Theme.statusChipEnd }
        }
        border.width: 1
        border.color: pill.strong ? Theme.statusChipStrongBorder : Theme.statusChipBorder

        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: 1
            color: Theme.surfaceHighlight
            opacity: pill.strong ? 0.55 : 0.40
        }

        Row {
            id: pillRow
            anchors.centerIn: parent
            spacing: 6

            SvgIcon {
                id: pillIcon
                width: Theme.iconSizeSmall
                height: Theme.iconSizeSmall
                color: pill.iconColor
                anchors.verticalCenter: parent.verticalCenter
            }

            Text {
                id: pillLabel
                width: pill.labelWidth
                text: pill.label
                elide: Text.ElideMiddle
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.DemiBold
                color: pill.strong ? Theme.statusChipStrongText : Theme.statusChipText
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 20
        anchors.rightMargin: 20
        spacing: 16

        Row {
            spacing: 8

            Rectangle {
                width: 6
                height: 6
                radius: 3
                color: root.fillArmed ? Theme.fillArmedDot : Theme.textDisabled
                anchors.verticalCenter: parent.verticalCenter
                opacity: root.fillArmed ? 1.0 : 0.65
            }

            Text {
                text: root.statusText
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                color: Theme.textSubtle
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        Item { Layout.fillWidth: true }

        StatusPill {
            visible: root.vaultFileName !== ""
            iconSource: Theme.iconLock
            iconColor: Theme.accent2Dim
            label: root.vaultFileName
            maxLabelWidth: 220
        }

        StatusPill {
            visible: root.accountCount > 0
            iconSource: Theme.iconUsername
            iconColor: Theme.accent
            label: root.accountCount + (root.accountCount === 1 ? " account" : " accounts")
            maxLabelWidth: 132
        }

        StatusPill {
            visible: root.fillArmed
            strong: true
            iconSource: Theme.iconCrosshairs
            iconColor: Theme.fillArmedDot
            label: "Fill armed"
            maxLabelWidth: 100
        }
    }
}
