import QtQuick
import QtQuick.Layouts

/*!
 * \qmltype StatusFooter
 * \inqmlmodule seal
 * \brief Display workspace status, browser connections, and armed state.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Main supplies non-secret status and vault values. BridgeSettings reads the
 * Bridge context property directly and owns the connection controls.
 *
 * Below 1120 logical pixels, the footer hides the vault filename. Below 900,
 * it also hides browser and folder-protection labels. Status text elides to
 * fit the available width. The armed-fill dot remains visible while armed.
 */
Item {
    id: root

    /*!
     * Non-secret status message; elides on the right when space is limited.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string statusText: "Ready"
    /*!
     * Show the pulsing indicator for an armed fill.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool fillArmed: false
    /*!
     * Display name only; an empty value hides the filename.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string vaultFileName: ""
    /*!
     * Visible account count supplied by the owner; values below one hide the count.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property int accountCount: 0
    /*!
     * Show the armed-folder indicator.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool protectFolderEnabled: false
    /*!
     * Hide the filename below 1120 logical pixels; zero width is excluded.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool narrowLayout: width > 0 && width < 1120
    /*!
     * Hide secondary labels below 900 logical pixels; zero width is excluded.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool condensedLayout: width > 0 && width < 900

    implicitHeight: condensedLayout ? 40 : 36
    clip: true

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: root.condensedLayout ? 12 : root.narrowLayout ? 16 : 20
        anchors.rightMargin: anchors.leftMargin
        spacing: root.condensedLayout ? 8 : root.narrowLayout ? 12 : 16

        Text {
            Layout.minimumWidth: 0
            Layout.maximumWidth: root.condensedLayout ? 120 : root.narrowLayout ? 180 : 320
            text: root.statusText
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            font.weight: Font.Medium
            // Stronger light-mode text remains visible over a dark desktop.
            color: Theme.dark ? Theme.textSubtle : Theme.textSecondary
            elide: Text.ElideRight
        }

        BridgeSettings {
            compact: root.condensedLayout
            Layout.alignment: Qt.AlignVCenter
        }

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

        Text {
            Layout.minimumWidth: 0
            Layout.maximumWidth: 260
            visible: root.vaultFileName !== "" && !root.narrowLayout
            text: root.vaultFileName
            font.family: Theme.fontMono
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.dark
                   ? Theme.accent2Dim
                   : Theme.blend(Theme.textPrimary, Theme.accent2Dim, 0.28, 1.0)
            elide: Text.ElideMiddle
        }

        Text {
            visible: root.vaultFileName !== "" && root.accountCount > 0 && !root.narrowLayout
            text: "|"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.textDisabled
        }

        Text {
            visible: root.accountCount > 0
            text: root.accountCount + (root.accountCount === 1 ? " account" : " accounts")
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.dark ? Theme.textMuted : Theme.textSecondary
        }

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
