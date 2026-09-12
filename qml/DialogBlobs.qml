import QtQuick

/*!
 * \qmltype DialogBlobs
 * \inqmlmodule seal
 * \brief Draw shared decorative blobs and ripples behind dialog content.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * The item fills its parent at z = -1. The host supplies rounded clipping through
 * MultiEffect. Motion follows \c Ambient.tidePhase when active and
 * \c WindowVM.reduceMotion is false. Otherwise, blobs use their base positions
 * and ripples hide.
 */
Item {
    id: root
    anchors.fill: parent
    z: -1

    /*!
     * When false, stop motion and remove the shared phase dependency.
     * Bind to dialog visibility to avoid updates while hidden.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool active: true

    readonly property bool _moving: root.active && !WindowVM.reduceMotion
    readonly property real _tau: 2 * Math.PI

    // Base positions and motion amplitudes use logical pixels. Phase offsets use radians.
    // Integer frequencies keep each loop continuous when the shared phase wraps.
    component DialogBlob: Rectangle {
        id: blob
        property real baseX: 0
        property real baseY: 0
        property real swayAmp: Theme.px(6)
        property real bobAmp: Theme.px(8)
        property real breatheAmp: 0.05       // Scale varies by +/-5% around 1.
        property int freqX: 1
        property int freqY: 1
        property int freqS: 1
        property real phaseX: 0              // Offsets separate the blob movements.
        property real phaseY: 0
        property real phaseS: 0

        radius: width / 2
        antialiasing: true
        transformOrigin: Item.Center
        x: root._moving ? baseX + swayAmp * Math.sin(Ambient.tidePhase * freqX + phaseX) : baseX
        y: root._moving ? baseY + bobAmp * Math.sin(Ambient.tidePhase * freqY + phaseY) : baseY
        scale: root._moving ? 1.0 + breatheAmp * Math.sin(Ambient.tidePhase * freqS + phaseS) : 1.0
        opacity: root._moving
                 ? 0.88 + 0.12 * (0.5 + 0.5 * Math.sin(Ambient.tidePhase * freqS + phaseS))
                 : 1.0
        Behavior on color { ColorAnimation { duration: 350 } }
    }

    DialogBlob {
        width: 150; height: 150
        baseX: root.width * 0.62; baseY: root.height * -0.12
        color: Theme.dialogBlobColor2
        freqX: 1; freqY: 1; freqS: 1
        phaseX: 0.0; phaseY: 0.6; phaseS: 0.0
    }
    DialogBlob {
        width: 180; height: 180
        baseX: root.width * 0.04; baseY: root.height * 0.55
        color: Theme.dialogBlobColor3
        freqX: 2; freqY: 1; freqS: 2
        phaseX: 1.8; phaseY: 2.2; phaseS: 1.0
    }
    DialogBlob {
        width: 140; height: 140
        baseX: root.width * 0.72; baseY: root.height * 0.48
        color: Theme.dialogBlobColor1
        freqX: 1; freqY: 2; freqS: 1
        phaseX: 0.9; phaseY: 4.0; phaseS: 2.4
    }
    DialogBlob {
        width: 120; height: 120
        baseX: root.width * 0.38; baseY: root.height * 0.80
        color: Theme.dialogBlobColor2
        freqX: 2; freqY: 1; freqS: 1
        phaseX: 3.3; phaseY: 1.4; phaseS: 4.0
    }

    // Derive ripples from the shared clock: about 16.7 s per cycle, 8.3 s apart.
    // Select a new center and hue while invisible at the phase wrap.
    Repeater {
        model: 2
        Rectangle {
            id: dRipple
            readonly property real ph: root._moving
                ? ((Ambient.tidePhase / root._tau) * 3.0 + index / 2.0) % 1.0
                : 0.0
            property real lastPh: 0.0
            property real cx: (index * 0.5 + 0.3) % 1.0
            property real cy: (index * 0.35 + 0.25) % 1.0
            property var hues: [Theme.dialogBlobColor1, Theme.dialogBlobColor2, Theme.dialogBlobColor3]
            property color hue: hues[index % 3]
            readonly property real maxD: Math.hypot(root.width, root.height)

            onPhChanged: {
                if (ph < lastPh) {          // The ripple is invisible at the phase wrap.
                    cx = Math.random();
                    cy = Math.random();
                    hue = hues[Math.floor(Math.random() * 3)];
                }
                lastPh = ph;
            }

            visible: root._moving
            width: maxD * (0.05 + 0.95 * ph)
            height: width
            radius: width / 2
            x: root.width * cx - width / 2
            y: root.height * cy - height / 2
            color: "transparent"
            border.width: Math.max(Theme.px(1), Theme.px(6) * Math.exp(-6.0 * ph))
            border.color: hue
            opacity: Math.min(1.0, ph / 0.14) * Math.pow(1.0 - ph, 1.5) * (Theme.dark ? 0.05 : 0.09)
            antialiasing: true
        }
    }
}
