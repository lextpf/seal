import QtQuick
import QtQuick.Shapes

// Full-window loading cover shown while a vault is being decrypted or
// re-encrypted. Because that crypto runs on a worker thread (see
// AppViewModel::loadVaultFromPath / rekeyVault), the GUI event loop stays free
// and the spinner below animates smoothly for the whole wait.
//
// Visual model -- "conic blob-spectrum sonar": a dim scrim over the app, a faint
// drifting aurora (the app's three signature background-blob hues -- indigo,
// teal, magenta -- as soft radial glows) for atmospheric depth, then three
// crisp "sonar" rings that bloom out of the centre and dissolve, staggered so a
// new ripple is always leaving. Each ring is a GPU vector donut (the same
// Shape + ConicalGradient + OddEvenFill idiom as HeaderBar's narwhal sonar)
// whose stroke is a soft conic sweep of those same three hues, the conic angle
// rotating slowly so the rings shimmer through the spectrum as they expand. A
// bright, gently breathing core anchors the eye, and a quietly animated Inter
// caption sits beneath. The whole cover cross-fades on show/hide and fully
// unmounts when idle so it costs nothing -- and runs no animation -- between
// loads.
Item {
    id: root

    // --- Inputs -------------------------------------------------------------
    property bool running: false   ///< Drives visibility + animation.
    property string caption: ""    ///< Text beneath the spinner.

    // --- Tuning -------------------------------------------------------------
    // Largest radius a ripple reaches, in DPI-scaled px.
    readonly property real maxRadius: Theme.px(58)

    // The three signature blob hues, lifted to a saturation that READS on the
    // dim scrim (the background blobs themselves sit at ~7-8% alpha, far too
    // faint for a foreground spinner). Hue-matched to Theme.blobColor1/2/3:
    // indigo / blue-violet, teal / cyan, magenta / purple-pink.
    readonly property color hueIndigo:  Qt.rgba(0.42, 0.34, 0.95, 1.0)
    readonly property color hueTeal:    Qt.rgba(0.22, 0.74, 0.82, 1.0)
    readonly property color hueMagenta: Qt.rgba(0.82, 0.30, 0.74, 1.0)

    // Theme-aware GLOW (the soft halo behind the rings). The same translucent
    // disc reads oppositely on each surface: over the near-black dark scrim it
    // must EMIT light (bright, white-lifted hues) yet stay restrained or it
    // blows out, while over the near-white light surface a bright glow vanishes
    // -- there it has to be SATURATED and denser to show at all. So dark uses
    // luminous hues at a modest multiplier; light reuses the saturated ring hues
    // at a higher one.
    readonly property bool isDark: Theme.dark
    readonly property color glowIndigo:  isDark ? Qt.rgba(0.60, 0.54, 1.00, 1.0) : hueIndigo
    readonly property color glowTeal:    isDark ? Qt.rgba(0.50, 0.90, 0.98, 1.0) : hueTeal
    readonly property color glowMagenta: isDark ? Qt.rgba(0.98, 0.60, 0.92, 1.0) : hueMagenta
    readonly property real glowMul: isDark ? 0.25 : 1.6

    // Cross-fade the entire cover; unmount once fully faded so the looping
    // animations stop and no input is captured while idle.
    opacity: running ? 1.0 : 0.0
    visible: opacity > 0.001
    Behavior on opacity { NumberAnimation { duration: 220; easing.type: Easing.OutCubic } }

    // Swallow all pointer input to the UI underneath for the duration of the
    // operation. Invisible, so it never occludes the spinner.
    MouseArea {
        anchors.fill: parent
        enabled: root.visible
        hoverEnabled: true
        acceptedButtons: Qt.AllButtons
        preventStealing: true
        onWheel: function(wheel) { wheel.accepted = true }
    }

    // Strong scrim derived from the theme's deepest background: opaque enough to
    // firmly cover the app underneath (the content reads only as a faint ghost)
    // while still adapting to dark/light. Makes the colourful spinner pop.
    Rectangle {
        anchors.fill: parent
        color: Qt.rgba(Theme.bgDeep.r, Theme.bgDeep.g, Theme.bgDeep.b, 0.92)
    }

    Column {
        anchors.centerIn: parent
        spacing: Theme.spacingLarge + Theme.px(6)

        Item {
            id: spinner
            width: root.maxRadius * 2
            height: width
            anchors.horizontalCenter: parent.horizontalCenter

            readonly property real tau: 2.0 * Math.PI

            // --- Animation drivers, all gated on visibility so the spinner is
            // fully idle (no timers, no CPU) once the cover unmounts. ---

            // Ripple driver: a single phase in [0, 1) loops continuously; each
            // ring reads it at a fixed offset, so one animation yields evenly
            // staggered ripples.
            property real t: 0.0
            NumberAnimation on t {
                running: root.visible
                from: 0.0
                to: 1.0
                duration: 2600
                loops: Animation.Infinite
            }

            // Conic-sweep driver: the gradient angle, one slow full turn so the
            // ring colours shimmer through the blob spectrum as they grow. A
            // turn every 7 s keeps the motion calm, not spinny.
            property real sweep: 0.0
            NumberAnimation on sweep {
                running: root.visible
                from: 0.0
                to: 360.0
                duration: 7000
                loops: Animation.Infinite
            }

            // Gentle 0..1 breathing curve for the bright core's swell.
            property real breath: 0.0
            NumberAnimation on breath {
                running: root.visible
                from: 0.0
                to: 1.0
                duration: 2600
                loops: Animation.Infinite
            }
            readonly property real swell: 0.5 - 0.5 * Math.cos(breath * spinner.tau)

            // Dark-only luminous bloom: a soft near-white radial that lifts the
            // centre so the coloured glow reads as emitted light rather than a
            // muddy translucent disc over the near-black scrim. Hidden on light,
            // whose bright surface already supplies that brightening.
            Shape {
                id: bloom
                visible: root.isDark
                anchors.centerIn: parent
                width: Theme.px(150); height: width
                antialiasing: true
                preferredRendererType: Shape.CurveRenderer
                layer.enabled: true
                layer.samples: 4
                opacity: 0.85 + 0.15 * spinner.swell
                ShapePath {
                    strokeWidth: -1
                    fillGradient: RadialGradient {
                        centerX: bloom.width / 2
                        centerY: bloom.height / 2
                        centerRadius: bloom.width / 2
                        focalX: centerX
                        focalY: centerY
                        GradientStop { position: 0.0;  color: Qt.rgba(0.78, 0.84, 1.0, 0.26) }
                        GradientStop { position: 0.45; color: Qt.rgba(0.55, 0.66, 1.0, 0.07) }
                        GradientStop { position: 1.0;  color: Qt.rgba(0.55, 0.66, 1.0, 0.0) }
                    }
                    startX: bloom.width; startY: bloom.height / 2
                    PathArc { x: 0; y: bloom.height / 2; radiusX: bloom.width / 2; radiusY: bloom.height / 2 }
                    PathArc { x: bloom.width; y: bloom.height / 2; radiusX: bloom.width / 2; radiusY: bloom.height / 2 }
                }
            }

            // Aurora backdrop: three large radial glows in the blob hues, drifting
            // slowly on their own ellipses behind the rings for atmospheric depth.
            // Brightened on dark (glow* hues + glowMul) so they emit rather than
            // smudge; subtle on light.
            Repeater {
                model: [
                    { hue: root.glowIndigo,  off: 0.00, size: 170 },
                    { hue: root.glowTeal,    off: 0.37, size: 142 },
                    { hue: root.glowMagenta, off: 0.68, size: 152 }
                ]
                Shape {
                    id: aurora
                    readonly property real ph: (spinner.t + modelData.off) % 1.0
                    readonly property real ang: ph * spinner.tau
                    readonly property real breathe: 0.5 - 0.5 * Math.cos(ph * spinner.tau)
                    anchors.centerIn: parent
                    width: Theme.px(modelData.size)
                    height: width
                    antialiasing: true
                    preferredRendererType: Shape.CurveRenderer
                    layer.enabled: true
                    layer.samples: 4
                    opacity: (0.09 + breathe * 0.06) * root.glowMul
                    transform: Translate {
                        x: Math.cos(aurora.ang) * Theme.px(11)
                        y: Math.sin(aurora.ang) * Theme.px(7)
                    }
                    ShapePath {
                        strokeWidth: -1
                        fillGradient: RadialGradient {
                            centerX: aurora.width / 2
                            centerY: aurora.height / 2
                            centerRadius: aurora.width / 2
                            focalX: centerX
                            focalY: centerY
                            GradientStop { position: 0.0; color: Qt.rgba(modelData.hue.r, modelData.hue.g, modelData.hue.b, 0.90) }
                            GradientStop { position: 0.55; color: Qt.rgba(modelData.hue.r, modelData.hue.g, modelData.hue.b, 0.30) }
                            GradientStop { position: 1.0; color: Qt.rgba(modelData.hue.r, modelData.hue.g, modelData.hue.b, 0.0) }
                        }
                        startX: aurora.width; startY: aurora.height / 2
                        PathArc { x: 0; y: aurora.height / 2; radiusX: aurora.width / 2; radiusY: aurora.height / 2 }
                        PathArc { x: aurora.width; y: aurora.height / 2; radiusX: aurora.width / 2; radiusY: aurora.height / 2 }
                    }
                }
            }

            // Conic sonar ripples: three donut rings, each expanding from the
            // centre to maxRadius. Radius eases out (fast then slow) for a
            // natural ping; the stroke is a soft conic sweep of the three blob
            // hues, rotating with `sweep` and offset 120 deg per ring so the
            // three ripples never colour-align -- like overlapping light through
            // stained glass. Opacity follows a sine envelope so each ring blooms
            // from nothing at the centre and dissolves at the rim (no hard
            // fleck, no clipped edge). Drawn as GPU vector donuts (OddEvenFill).
            Repeater {
                model: 3
                Shape {
                    id: ring
                    readonly property real phase: (spinner.t + index / 3.0) % 1.0
                    readonly property real eased: 1.0 - Math.pow(1.0 - phase, 2.4)
                    readonly property real outerR: Math.max(1, eased * root.maxRadius)
                    // Stroke thins as the ring grows, like a real expanding wave.
                    readonly property real strokeW: Math.max(1.0, Theme.px(3.0) * (1.0 - 0.55 * phase))
                    readonly property real innerR: Math.max(0, outerR - strokeW)
                    readonly property real cx: width / 2
                    readonly property real cy: width / 2

                    anchors.centerIn: parent
                    width: spinner.width
                    height: width
                    opacity: Math.sin(phase * Math.PI) * 0.7
                    antialiasing: true
                    layer.enabled: true
                    layer.samples: 4
                    layer.smooth: true

                    ShapePath {
                        fillRule: ShapePath.OddEvenFill
                        strokeWidth: -1
                        fillGradient: ConicalGradient {
                            centerX: ring.cx
                            centerY: ring.cy
                            angle: spinner.sweep + index * 120
                            GradientStop { position: 0.00; color: root.hueIndigo }
                            GradientStop { position: 0.33; color: root.hueTeal }
                            GradientStop { position: 0.66; color: root.hueMagenta }
                            GradientStop { position: 1.00; color: root.hueIndigo }
                        }
                        startX: ring.cx + ring.outerR; startY: ring.cy
                        PathArc { x: ring.cx - ring.outerR; y: ring.cy; radiusX: ring.outerR; radiusY: ring.outerR }
                        PathArc { x: ring.cx + ring.outerR; y: ring.cy; radiusX: ring.outerR; radiusY: ring.outerR }
                        PathMove { x: ring.cx + ring.innerR; y: ring.cy }
                        PathArc { x: ring.cx - ring.innerR; y: ring.cy; radiusX: ring.innerR; radiusY: ring.innerR }
                        PathArc { x: ring.cx + ring.innerR; y: ring.cy; radiusX: ring.innerR; radiusY: ring.innerR }
                    }
                }
            }

            // Clean focal point: a single soft accent halo (one cohesive hue --
            // not a stack of clashing colours) drawn as a feathered radial, so
            // the centre reads as one intentional glowing point. Theme.accent is
            // theme-aware, keeping the focus cohesive in dark and light. The
            // colourful blob hues already live in the rings around it.
            Shape {
                id: focal
                anchors.centerIn: parent
                width: Theme.px(50); height: width
                antialiasing: true
                preferredRendererType: Shape.CurveRenderer
                layer.enabled: true
                layer.samples: 4
                opacity: (root.isDark ? 0.20 : 0.55) + 0.12 * spinner.swell
                ShapePath {
                    strokeWidth: -1
                    fillGradient: RadialGradient {
                        centerX: focal.width / 2
                        centerY: focal.height / 2
                        centerRadius: focal.width / 2
                        focalX: centerX
                        focalY: centerY
                        GradientStop { position: 0.0; color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.85) }
                        GradientStop { position: 0.5; color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.26) }
                        GradientStop { position: 1.0; color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.0) }
                    }
                    startX: focal.width; startY: focal.height / 2
                    PathArc { x: 0; y: focal.height / 2; radiusX: focal.width / 2; radiusY: focal.height / 2 }
                    PathArc { x: focal.width; y: focal.height / 2; radiusX: focal.width / 2; radiusY: focal.height / 2 }
                }
            }

            // Crisp breathing core -- the stable bright point the ripples emanate
            // from. A subtle scale swell adds calm life without competing.
            Rectangle {
                anchors.centerIn: parent
                width: Theme.px(7); height: width; radius: width / 2
                color: Theme.accentBright
                scale: 0.92 + 0.18 * spinner.swell
            }
        }

        // Caption with a gently animated trailing ellipsis. The C++ side sends a
        // string that may already carry trailing dots (e.g. "Decrypting
        // vault..."); we strip those and re-add an animated 0-3 dot cycle so the
        // label itself reads as "working". A fixed-width dots slot keeps the
        // base label from shifting as the dots fill in.
        Row {
            id: captionRow
            anchors.horizontalCenter: parent.horizontalCenter
            visible: root.caption.length > 0
            spacing: 0

            readonly property string baseText: root.caption.replace(/[.\s]+$/, "")
            property int dots: 0
            Timer {
                interval: 420
                running: root.visible && captionRow.baseText.length > 0
                repeat: true
                onTriggered: captionRow.dots = (captionRow.dots + 1) % 4
            }

            Text {
                id: capText
                text: captionRow.baseText
                // Bright primary text + bold weight so the label stands out
                // clearly against the strong scrim.
                color: Theme.textPrimary
                font.family: Theme.fontFamily
                font.pixelSize: Theme.px(13)
                font.letterSpacing: 1.4
                font.weight: Font.Bold
                renderType: Text.QtRendering
            }
            Text {
                // Reserve room for three dots so the base label never shifts;
                // the visible dots fill in left-to-right.
                width: dotsMetrics.implicitWidth
                text: "...".substring(0, captionRow.dots)
                color: Theme.textPrimary
                font: capText.font
                renderType: Text.QtRendering
            }
            Text { id: dotsMetrics; visible: false; text: "..."; font: capText.font }
        }
    }
}
