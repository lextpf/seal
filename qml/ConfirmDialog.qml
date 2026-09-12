import QtQuick
import QtQuick.Controls
import QtQuick.Effects
import QtQuick.Layouts

/*!
 * \qmltype ConfirmDialog
 * \inqmlmodule seal
 * \brief Present a modal confirmation with a shared dialog background.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * The default content provides Yes and No actions. No, Escape, and outside clicks
 * close the popup without confirmation. Yes emits \c confirmed() before closing.
 *
 * Main replaces \c contentItem for error and information popups. Those instances
 * retain the background and transitions but supply their own content and actions.
 */
Popup {
    id: root

    /*!
     * Heading used by the default content.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string title: "Confirm"
    /*!
     * Explanation below the heading. Long text wraps to the dialog width.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string message: ""
    /*!
     * Accent for the title icon, header wash, and corner decoration.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tone: Theme.btnDeleteText
    /*!
     * SVG resource for the title icon in the default content.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string titleIcon: Theme.iconTrash

    /*!
     * \brief Notify the caller that the Yes action was selected.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Handlers run before the default action closes the popup. The caller performs
     * the requested operation; this signal does not report its success.
     */
    signal confirmed()

    modal: true
    anchors.centerIn: parent
    width: 380
    padding: 0
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

    enter: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 175; easing.type: Easing.OutCubic }
            NumberAnimation { property: "scale"; from: 0.94; to: 1; duration: 190; easing.type: Easing.OutBack; easing.overshoot: 1.15 }
        }
    }
    exit: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 1; to: 0; duration: 130; easing.type: Easing.InCubic }
            NumberAnimation { property: "scale"; from: 1; to: 0.95; duration: 130; easing.type: Easing.InCubic }
        }
    }

    background: Rectangle {
        id: dialogBg
        color: Theme.bgDialog
        radius: Theme.radiusLarge
        border.width: Theme.strokeRegular
        border.color: Theme.borderMedium

        Item {
            anchors.fill: parent
            layer.enabled: true
            layer.smooth: true
            layer.effect: MultiEffect {
                maskEnabled: true
                maskSource: dialogShellMask
                autoPaddingEnabled: false
            }

            DialogBlobs { active: root.visible }

            Rectangle {
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                height: 50
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Qt.rgba(root.tone.r, root.tone.g, root.tone.b, 0.04) }
                    GradientStop { position: 1.0; color: Qt.rgba(root.tone.r, root.tone.g, root.tone.b, 0.0) }
                }
            }

            Rectangle {
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                height: Theme.strokeDivider
                color: Theme.dialogEdgeLight
                opacity: 0.20
            }

            Rectangle {
                width: 160
                height: 120
                radius: 80
                x: -28
                y: -54
                color: Qt.rgba(root.tone.r, root.tone.g, root.tone.b, 0.05)
            }
        }

        Rectangle {
            id: dialogShellMask
            anchors.fill: parent
            radius: parent.radius
            visible: false
            layer.enabled: true
            layer.smooth: true
            antialiasing: true
        }
    }

    Overlay.modal: Rectangle {
        color: Theme.bgOverlay
    }

    contentItem: ColumnLayout {
        spacing: 0

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 24
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: 10

            Item {
                Layout.alignment: Qt.AlignVCenter
                Layout.preferredWidth: Theme.px(28)
                Layout.preferredHeight: Theme.px(28)

                SvgIcon {
                    source: root.titleIcon
                    width: Theme.px(14)
                    height: Theme.px(14)
                    color: root.tone
                    anchors.centerIn: parent
                }
            }

            Text {
                Layout.fillWidth: true
                text: root.title
                font.family: Theme.fontFamily
                font.pixelSize: Theme.px(16)
                font.bold: true
                color: Theme.textPrimary
            }
        }

        Text {
            Layout.fillWidth: true
            Layout.topMargin: 12
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            text: root.message
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            color: Theme.textSecondary
            wrapMode: Text.WordWrap
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 24
            Layout.bottomMargin: 20
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: Theme.spacingSmall

            Item { Layout.fillWidth: true }

            Button {
                id: noButton
                text: "No"
                onClicked: root.close()

                HoverHandler { id: noHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Text {
                    text: parent.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    font.weight: Font.Medium
                    color: noButton.hovered ? Theme.textPrimary : Theme.textGhost
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
                background: Rectangle {
                    implicitWidth: 90
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    gradient: Gradient {
                        GradientStop { position: 0; color: noButton.pressed ? Theme.ghostBtnPressed : noButton.hovered ? Theme.ghostBtnHoverTop : Theme.ghostBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: noButton.pressed ? Theme.ghostBtnPressed : noButton.hovered ? Theme.ghostBtnHoverEnd : Theme.ghostBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: Theme.strokeRegular
                    border.color: noButton.pressed ? Theme.borderPressed
                                : noButton.hovered ? Theme.borderFocusHover
                                : Theme.borderSubtle
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: noRipple
                        baseColor: Qt.rgba(Theme.textPrimary.r, Theme.textPrimary.g, Theme.textPrimary.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: noRipple.trigger(noHover.point.position.x, noHover.point.position.y)
            }

            Button {
                id: yesButton
                text: "Yes"
                onClicked: {
                    root.confirmed();
                    root.close();
                }

                HoverHandler { id: yesHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Text {
                    text: parent.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    font.weight: Font.DemiBold
                    color: Theme.textOnAccent
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 90
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    gradient: Gradient {
                        GradientStop { position: 0; color: yesButton.pressed ? Theme.btnPressTop : yesButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: yesButton.pressed ? Theme.btnPressBot : yesButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: Theme.strokeRegular
                    border.color: yesButton.hovered ? Theme.borderBright : Theme.borderBtn
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: yesRipple
                        baseColor: Qt.rgba(Theme.textOnAccent.r, Theme.textOnAccent.g, Theme.textOnAccent.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: yesRipple.trigger(yesHover.point.position.x, yesHover.point.position.y)
            }
        }
    }
}
