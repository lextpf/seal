import QtQuick
import QtQuick.Effects

Item {
    id: ripple
    anchors.fill: parent
    clip: !ripple._useRoundedMask

    property color baseColor: Theme.rippleColor
    property real cx: 0
    property real cy: 0
    property real cornerRadius: 0
    readonly property bool _useRoundedMask: cornerRadius > 0
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
