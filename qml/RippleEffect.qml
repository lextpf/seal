import QtQuick
import QtQuick.Effects

/*!
 * \qmltype RippleEffect
 * \inqmlmodule seal
 * \brief Animate a clipped ripple from a control press point.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Place the item inside a control background and call \c trigger with local coordinates.
 * A new trigger restarts the single ripple. The ripple expands over 420 ms and starts
 * fading after 80 ms. Positive corner radii use a rounded mask; other values use a clip.
 */
Item {
    id: ripple
    anchors.fill: parent
    clip: !ripple._useRoundedMask   // Square hosts clip; rounded hosts use a mask.

    /*!
     * Color and initial alpha of the ripple. Fading multiplies this alpha.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color baseColor: Theme.rippleColor
    /*!
     * Horizontal center in local logical pixels. Updated by each trigger.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property real cx: 0
    /*!
     * Vertical center in local logical pixels. Updated by each trigger.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property real cy: 0
    /*!
     * Mask radius in logical pixels. Set to the host radius; zero uses a square clip.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property real cornerRadius: 0
    readonly property bool _useRoundedMask: cornerRadius > 0
    /*!
     * Final radius in logical pixels. The default diagonal covers any in-bounds press.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property real maxRadius: Math.sqrt(width * width + height * height)

    /*!
     * \brief Restart the ripple at a press point.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * \a pressX and \a pressY are local logical-pixel coordinates. They are not clamped.
     * Reset scale and opacity before restarting the expansion and fade.
     */
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

    // Use as a mask source only; do not draw directly.
    Rectangle {
        id: roundedMask
        anchors.fill: parent
        radius: ripple.cornerRadius
        visible: false
        layer.enabled: true
        layer.smooth: true
        antialiasing: true
    }

    // Delay fading by 80 ms to keep the initial press visible.
    ParallelAnimation {
        id: anim
        NumberAnimation { target: circle; property: "scale"; to: 1.0; duration: 420; easing.type: Easing.OutCubic }
        SequentialAnimation {
            PauseAnimation { duration: 80 }
            NumberAnimation { target: circle; property: "opacity"; to: 0.0; duration: 340; easing.type: Easing.OutCubic }
        }
    }
}
