import QtQuick
import QtQuick.Effects

// Material Design-inspired ink ripple effect for button press feedback.
//
// How it works: a circle is placed at the press coordinates and scaled from
// 0 to 1 over 420ms. The fade-out starts 80ms later so the ripple is briefly
// fully visible at its maximum size before disappearing - this creates the
// characteristic "ink splash" feel. A rounded mask can be supplied so the
// ripple follows the button silhouette instead of clipping to a hard rectangle.
//
// Usage: embed as a child of a button's `background` Rectangle and call
// trigger(pressX, pressY) from the button's onPressed handler. The ripple
// renders behind the button's contentItem (text/icon) because it lives
// inside the background.

Item {
    id: ripple
    anchors.fill: parent
    clip: !ripple._useRoundedMask

    property color baseColor: Theme.rippleColor
    property real cx: 0
    property real cy: 0
    property real cornerRadius: 0
    readonly property bool _useRoundedMask: cornerRadius > 0
    // maxRadius uses the diagonal so the circle covers every corner of
    // the rectangular parent regardless of where the press originated.
    property real maxRadius: Math.sqrt(width * width + height * height)

    // Resets and restarts animation from the press point.
    function trigger(pressX, pressY) {
        cx = pressX; cy = pressY;
        circle.scale = 0; circle.opacity = 1;
        anim.restart();
    }

    Item {
        id: rippleSource
        anchors.fill: parent
        layer.enabled: ripple._useRoundedMask
        layer.smooth: true
        layer.effect: MultiEffect {
            maskEnabled: ripple._useRoundedMask
            maskSource: roundedMask
            autoPaddingEnabled: false
        }

        // Circle centered on (cx, cy), scaled from 0 to 1.
        Rectangle {
            id: circle
            x: ripple.cx - ripple.maxRadius
            y: ripple.cy - ripple.maxRadius
            width: ripple.maxRadius * 2
            height: ripple.maxRadius * 2
            radius: ripple.maxRadius
            color: ripple.baseColor
            scale: 0; opacity: 0
            antialiasing: true
        }
    }

    Rectangle {
        id: roundedMask
        anchors.fill: parent
        radius: ripple.cornerRadius
        visible: false
        layer.enabled: true
        layer.smooth: true
        antialiasing: true
    }

    // Fade starts 80ms after scale for a brief fully-visible moment.
    ParallelAnimation {
        id: anim
        NumberAnimation { target: circle; property: "scale"; to: 1.0; duration: 420; easing.type: Easing.OutCubic }
        SequentialAnimation {
            PauseAnimation { duration: 80 }
            NumberAnimation { target: circle; property: "opacity"; to: 0.0; duration: 340; easing.type: Easing.OutCubic }
        }
    }
}
