import QtQuick
import QtQuick.Layouts

// Bottom status bar. Full-width, outside content margins.

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

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 20
        anchors.rightMargin: 20
        spacing: 16

        // Status text
        Text {
            text: root.statusText
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            font.weight: Font.Medium
            color: Theme.textSubtle
        }

        Item { Layout.fillWidth: true }

        // Vault filename
        Text {
            visible: root.vaultFileName !== ""
            text: root.vaultFileName
            font.family: Theme.fontMono
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.textMuted
        }

        // Pipe separator, hidden when either side is absent.
        Text {
            visible: root.vaultFileName !== "" && root.accountCount > 0
            text: "|"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.textDisabled
        }

        // Account count
        Text {
            visible: root.accountCount > 0
            text: root.accountCount + (root.accountCount === 1 ? " account" : " accounts")
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.textMuted
        }

        // Pulsing orange dot when fill is armed.
        Rectangle {
            id: armedIndicator
            width: 8
            height: 8
            radius: 4
            color: Theme.fillArmedDot
            visible: root.fillArmed

            SequentialAnimation on opacity {
                running: armedIndicator.visible
                loops: Animation.Infinite
                NumberAnimation { to: 0.3; duration: 800; easing.type: Easing.InOutSine }
                NumberAnimation { to: 1.0; duration: 800; easing.type: Easing.InOutSine }
            }
        }
    }
}
