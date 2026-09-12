import QtQuick
import QtQuick.Controls

/*!
 * \qmltype TintedButton
 * \inqmlmodule seal
 * \brief Present a shared workspace action with configurable colors.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Select colors from one Theme family to keep the background, outline, and text
 * consistent. Defaults follow the ghost palette when the theme changes.
 * Disabled buttons use the shared neutral palette and ignore custom colors.
 *
 * \section1 Color states
 *
 * \table
 * \header
 *     \li State
 *     \li Background
 *     \li Icon and label
 * \row
 *     \li Normal
 *     \li Gradient from \c tintTop to \c tintEnd.
 *     \li \c tintText.
 * \row
 *     \li Hovered
 *     \li Gradient from \c tintHoverTop to \c tintHoverEnd.
 *     \li \c tintTextHover.
 * \row
 *     \li Pressed
 *     \li Solid \c tintPressed color.
 *     \li Hover color if hovered; normal color otherwise.
 * \row
 *     \li Disabled
 *     \li Shared disabled gradient from Theme.
 *     \li Shared disabled text color from Theme.
 * \endtable
 *
 * Disabled colors take precedence over pressed and hovered colors. Pressing changes
 * the background but leaves text and outline selection dependent on hover state.
 * The outline derives from the tint colors and active theme unless overridden.
 */
Button {
    id: root
    /*!
     * SVG resource path. An empty string removes the icon and its label spacing.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string faIcon: ""
    /*!
     * Hide the label without clearing the inherited text property.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool iconOnly: false
    /*!
     * Top gradient color when enabled, unpressed, and not hovered.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintTop:         Theme.ghostBtnTop
    /*!
     * Bottom gradient color when enabled, unpressed, and not hovered.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintEnd:         Theme.ghostBtnEnd
    /*!
     * Top gradient color when enabled, hovered, and unpressed.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintHoverTop:    Theme.ghostBtnHoverTop
    /*!
     * Bottom gradient color when enabled, hovered, and unpressed.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintHoverEnd:    Theme.ghostBtnHoverEnd
    /*!
     * Solid background color when enabled and pressed.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintPressed:     Theme.ghostBtnPressed
    /*!
     * Icon and label color when enabled and not hovered, including while pressed.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintText:        Theme.textGhost
    /*!
     * Icon and label color when enabled and hovered, including while pressed.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintTextHover:   Theme.textPrimary

    /*!
     * Outline color when enabled and not hovered. The default follows the tint family.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintBorder: Theme.dark
        ? Qt.rgba(tintEnd.r, tintEnd.g, tintEnd.b, Math.min(tintEnd.a + 0.18, 1.0))
        : Theme.blend(tintText, tintEnd, 0.24, 0.50)
    /*!
     * Outline color when enabled and hovered. The default also depends on the theme.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color tintBorderHover: Theme.dark
        ? Theme.borderHover
        : Theme.blend(tintTextHover, tintHoverEnd, 0.24, 0.65)
    leftPadding: 14
    rightPadding: 14

    HoverHandler { id: btnHover; cursorShape: Qt.PointingHandCursor }

    contentItem: Row {
        spacing: (root.faIcon !== "" && !root.iconOnly) ? 6 : 0
        anchors.centerIn: parent
        SvgIcon {
            source: root.faIcon
            width: visible ? Theme.iconSizeMedium : 0
            height: Theme.iconSizeMedium
            color: !root.enabled ? Theme.textDisabled : root.hovered ? root.tintTextHover : root.tintText
            visible: root.faIcon !== ""
            anchors.verticalCenter: parent.verticalCenter
            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        }
        Text {
            text: root.text
            visible: !root.iconOnly
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            font.weight: Font.DemiBold
            color: !root.enabled ? Theme.textDisabled : root.hovered ? root.tintTextHover : root.tintText
            anchors.verticalCenter: parent.verticalCenter
            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        }
    }

    scale: pressed ? 0.97 : 1.0
    Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

    background: Rectangle {
        implicitWidth: 120
        implicitHeight: 40
        radius: Theme.radiusMedium
        clip: true
        gradient: Gradient {
            GradientStop { position: 0; color: !root.enabled ? Theme.btnDisabledTop : root.pressed ? root.tintPressed : root.hovered ? root.tintHoverTop : root.tintTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
            GradientStop { position: 1; color: !root.enabled ? Theme.btnDisabledBot : root.pressed ? root.tintPressed : root.hovered ? root.tintHoverEnd : root.tintEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
        }

        border.width: Theme.strokeRegular
        border.color: !root.enabled ? Theme.btnDisabledBorder
                    : root.hovered ? root.tintBorderHover
                    : root.tintBorder

        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

        RippleEffect {
            id: btnRipple
            baseColor: Qt.rgba(root.tintText.r, root.tintText.g, root.tintText.b, 0.30)
            cornerRadius: parent.radius
        }
    }
    onPressed: btnRipple.trigger(btnHover.point.position.x, btnHover.point.position.y)
}
