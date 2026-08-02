import QtQuick
import QtQuick.Layouts

// Bottom status strip, hidden in compact mode. Main pushes every value in as a plain
// property, so the footer holds no vault state of its own. The browser connection
// chips are the exception: BridgeSettings binds the Bridge context property itself.
Rectangle {
    id: root

    property string statusText: "Ready"
    property bool fillArmed: false
    property string vaultFileName: ""
    property int accountCount: 0
    property bool protectFolderEnabled: false
    readonly property bool narrowLayout: width > 0 && width < 1120
    readonly property bool condensedLayout: width > 0 && width < 900

    implicitHeight: condensedLayout ? 40 : 36
    clip: true
    gradient: Gradient {
        GradientStop { position: 0; color: Theme.bgFooterTop }
        GradientStop { position: 1; color: Theme.bgFooterEnd }
    }

    // Top border.
    Rectangle {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: Theme.strokeDivider
        color: Theme.borderDim
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: root.condensedLayout ? 12 : root.narrowLayout ? 16 : 20
        anchors.rightMargin: anchors.leftMargin
        spacing: root.condensedLayout ? 8 : root.narrowLayout ? 12 : 16

        // Status text
        Text {
            Layout.minimumWidth: 0
            Layout.maximumWidth: root.condensedLayout ? 120 : root.narrowLayout ? 180 : 320
            text: root.statusText
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            font.weight: Font.Medium
            color: Theme.textSubtle
            elide: Text.ElideRight
        }

        BridgeSettings {
            compact: root.condensedLayout
            Layout.alignment: Qt.AlignVCenter
        }

        // Reminder that folder protection is armed: the folder encrypts on exit.
        RowLayout {
            visible: root.protectFolderEnabled
            spacing: 5
            Layout.alignment: Qt.AlignVCenter

            SvgIcon {
                source: Theme.iconShieldHalved
                Layout.preferredWidth: Theme.px(12)
                Layout.preferredHeight: Theme.px(12)
                color: Theme.accent
            }

            Text {
                visible: !root.condensedLayout
                text: "Folder armed"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                color: Theme.accent
            }
        }

        Item { Layout.fillWidth: true }

        // Vault filename
        Text {
            Layout.minimumWidth: 0
            Layout.maximumWidth: 260
            visible: root.vaultFileName !== "" && !root.narrowLayout
            text: root.vaultFileName
            font.family: Theme.fontMono
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.dark
                   ? Theme.accent2Dim
                   : Theme.opaqueBlend(Theme.textPrimary, Theme.accent2Dim, 0.28)
            elide: Text.ElideMiddle
        }

        // Pipe separator, hidden when either side is absent.
        Text {
            visible: root.vaultFileName !== "" && root.accountCount > 0 && !root.narrowLayout
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
            color: Theme.dark ? Theme.textMuted : Theme.textSecondary
        }

        // Pulsing dot while a fill is armed, mirroring the ActionBar countdown.
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
