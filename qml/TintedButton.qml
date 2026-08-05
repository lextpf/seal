import QtQuick
import QtQuick.Controls

// The shared button for the ActionBar actions and the HeaderBar vault actions:
// gradient fill, optional leading icon, press ripple.
// A caller picks a role by assigning a Theme color family to the tint*
// properties (Theme.btnAdd*, Theme.btnDelete*, ...); the defaults are the
// ghost palette, so an unstyled TintedButton reads as a secondary action.
// Dialog buttons and the ActionBar Fill button hand-roll their own Button,
// because they carry states or sizes this component does not model (the armed
// countdown, the smaller dialog footprint).
Button {
    id: root
    property string faIcon: ""      // Icon qrc path; "" hides the icon and its spacing.
    property color tintTop:         Theme.ghostBtnTop
    property color tintEnd:         Theme.ghostBtnEnd
    property color tintHoverTop:    Theme.ghostBtnHoverTop
    property color tintHoverEnd:    Theme.ghostBtnHoverEnd
    property color tintPressed:     Theme.ghostBtnPressed
    property color tintText:        Theme.textGhost
    property color tintTextHover:   Theme.textPrimary
    property bool translucentSurface: false  // Set on glass buttons; see the disabled fills below.

    // Derived states. Dark mode drops alpha, light mode blends toward an opaque
    // color, because a light surface needs real contrast rather than more glass.
    property color tintTextDisabled: Theme.dark
        ? Qt.rgba(tintText.r, tintText.g, tintText.b, 0.32)
        : Theme.opaqueBlend(tintText, Theme.textDisabled, 0.30)
    property color tintBorder: Theme.dark
        ? Qt.rgba(tintEnd.r, tintEnd.g, tintEnd.b, Math.min(tintEnd.a + 0.18, 1.0))
        : Theme.opaqueBlend(tintText, tintEnd, 0.32)
    property color tintBorderHover: Theme.borderHover
    property color tintBorderDisabled: Theme.dark
        ? Theme.borderDim
        : Theme.opaqueBlend(tintBorder, Theme.borderDim, 0.36)
    leftPadding: 14
    rightPadding: 14

    // Disabled fills. A glass button keeps its source alpha so it stays
    // transparent; a semantic action button keeps its alpha in dark mode and fades
    // toward the opaque disabled color in light mode, instead of turning back into
    // a solid pill.
    readonly property color _disText: tintTextDisabled
    readonly property color _disTop: translucentSurface
        ? Qt.rgba(tintTop.r, tintTop.g, tintTop.b, tintTop.a * 0.45)
        : Theme.dark
          ? Qt.rgba(tintTop.r, tintTop.g, tintTop.b, tintTop.a * 0.35)
          : Theme.opaqueBlend(tintTop, Theme.btnDisabledTop, 0.50)
    readonly property color _disEnd: translucentSurface
        ? Qt.rgba(tintEnd.r, tintEnd.g, tintEnd.b, tintEnd.a * 0.45)
        : Theme.dark
          ? Qt.rgba(tintEnd.r, tintEnd.g, tintEnd.b, tintEnd.a * 0.35)
          : Theme.opaqueBlend(tintEnd, Theme.btnDisabledBot, 0.50)

    // Sets the cursor, and supplies the press point the ripple starts from.
    HoverHandler { id: btnHover; cursorShape: Qt.PointingHandCursor }

    contentItem: Row {
        spacing: root.faIcon !== "" ? 6 : 0
        anchors.centerIn: parent
        SvgIcon {
            source: root.faIcon
            width: visible ? Theme.iconSizeMedium : 0
            height: Theme.iconSizeMedium
            color: !root.enabled ? root._disText : root.hovered ? root.tintTextHover : root.tintText
            visible: root.faIcon !== ""
            anchors.verticalCenter: parent.verticalCenter
            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        }
        Text {
            text: root.text
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            font.weight: Font.DemiBold
            color: !root.enabled ? root._disText : root.hovered ? root.tintTextHover : root.tintText
            anchors.verticalCenter: parent.verticalCenter
            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        }
    }

    // Press squish: 0.97 scale with spring-back easing.
    scale: pressed ? 0.97 : 1.0
    Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

    background: Rectangle {
        implicitWidth: 120
        implicitHeight: 40
        radius: Theme.radiusMedium
        clip: true
        // Four-state gradient: disabled / normal / hovered / pressed.
        gradient: Gradient {
            GradientStop { position: 0; color: !root.enabled ? root._disTop : root.pressed ? root.tintPressed : root.hovered ? root.tintHoverTop : root.tintTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
            GradientStop { position: 1; color: !root.enabled ? root._disEnd : root.pressed ? root.tintPressed : root.hovered ? root.tintHoverEnd : root.tintEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
        }

        border.width: Theme.strokeRegular
        border.color: !root.enabled ? root.tintBorderDisabled
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
