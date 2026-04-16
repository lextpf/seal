import QtQuick
import QtQuick.Controls

// Shared parameterized button template used by ActionBar and HeaderBar.
//
// Each instance overrides the tint* properties to apply its semantic color.
// Disabled state is derived by reducing the tint alpha (same hue at lower
// opacity) rather than switching to a generic gray, so the button's identity
// remains recognizable.

Button {
    id: root
    property string faIcon: ""
    property color tintTop:         Theme.ghostBtnTop
    property color tintEnd:         Theme.ghostBtnEnd
    property color tintHoverTop:    Theme.ghostBtnHoverTop
    property color tintHoverEnd:    Theme.ghostBtnHoverEnd
    property color tintPressed:     Theme.ghostBtnPressed
    property color tintText:        Theme.textGhost
    property color tintTextHover:   Theme.textPrimary
    // Border derived from tint color with alpha boost to echo the button fill.
    readonly property color _tintBorder: Qt.rgba(tintEnd.r, tintEnd.g, tintEnd.b, Math.min(tintEnd.a + 0.18, 1.0))
    leftPadding: 14
    rightPadding: 14

    // Disabled: same hue at reduced opacity.
    readonly property color _disText:   Qt.rgba(tintText.r, tintText.g, tintText.b, 0.32)
    readonly property color _disTop:    Qt.rgba(tintTop.r, tintTop.g, tintTop.b, tintTop.a * 0.35)
    readonly property color _disEnd:    Qt.rgba(tintEnd.r, tintEnd.g, tintEnd.b, tintEnd.a * 0.35)

    HoverHandler { id: btnHover; cursorShape: Qt.PointingHandCursor }

    contentItem: Row {
        spacing: 6
        anchors.centerIn: parent
        SvgIcon {
            source: root.faIcon
            width: Theme.iconSizeMedium
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
        implicitHeight: 38
        radius: Theme.radiusMedium
        clip: true
        // Four-state gradient: disabled / normal / hovered / pressed.
        gradient: Gradient {
            GradientStop { position: 0; color: !root.enabled ? root._disTop : root.pressed ? root.tintPressed : root.hovered ? root.tintHoverTop : root.tintTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
            GradientStop { position: 1; color: !root.enabled ? root._disEnd : root.pressed ? root.tintPressed : root.hovered ? root.tintHoverEnd : root.tintEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
        }
        border.width: 1
        border.color: !root.enabled ? Theme.borderDim
                    : root.hovered ? Theme.borderHover
                    : root._tintBorder

        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

        RippleEffect {
            id: btnRipple
            baseColor: Qt.rgba(root.tintText.r, root.tintText.g, root.tintText.b, 0.30)
            cornerRadius: parent.radius
        }
    }
    onPressed: btnRipple.trigger(btnHover.point.position.x, btnHover.point.position.y)
}
