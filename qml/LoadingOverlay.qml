import QtQuick
import QtQuick.Shapes

/*!
 * \qmltype LoadingOverlay
 * \inqmlmodule seal
 * \brief Present startup, password entry, and cryptographic work states.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Main supplies state and verdicts, then fades the shell below this transparent cover.
 * The cover intercepts mouse and wheel input until dismissal. It permits native window
 * dragging during password entry, cryptographic work, and the success animation.
 *
 * \section1 Phases
 *
 * \table
 * \header
 *     \li Phase
 *     \li Presentation
 *     \li Set by
 * \row
 *     \li \c hidden
 *     \li Zero target opacity unless booting or fracturing.
 *     \li \c _sync and timers.
 * \row
 *     \li \c listening
 *     \li Password entry. Aurora appears during fracture.
 *     \li \c _sync and \c {breakSeal}.
 * \row
 *     \li \c sounding
 *     \li Cryptographic work with animated rings.
 *     \li \c {_sync}.
 * \row
 *     \li \c exiting
 *     \li Fade out without a verdict.
 *     \li \c {_sync}.
 * \row
 *     \li \c sealing
 *     \li Successful unlock animation.
 *     \li \c {sealSuccess}.
 * \row
 *     \li \c dismissing
 *     \li Final fade after success.
 *     \li Success animation.
 * \endtable
 *
 * Success starts only from sounding or exiting. The success sequence advances to
 * dismissing, then a 540 ms timer hides the cover. A 3800 ms watchdog hides it if the
 * success sequence does not complete. New listening or sounding input can replace a phase.
 *
 * Reduced motion stops continuous clocks and replaces moving verdict effects with fades.
 * Animation progress and opacity values use [0, 1]; verdict tint uses [-1, 1]. Geometry
 * uses logical pixels. Rotation angles use degrees.
 */
Item {
    id: root

    /*!
     * Password entry is active. Sounding takes priority when both inputs are true.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool listening: false
    /*!
     * Cryptographic work is active. Selects the animated ring presentation.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool sounding: false
    /*!
     * Status text below the animation. An empty string fades the caption out.
     * Trailing dots and whitespace are replaced by an animated ellipsis.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string caption: ""

    /*!
     * Current presentation state. Use the input properties and verdict methods to change it.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string phase: "hidden"

    /*!
     * True while the failure animation runs. Holds full cover opacity until completion.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool fracturing: false

    /*!
     * Hold full opacity until an input selects a phase or Main reports no startup vault.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool booting: true
    /*!
     * When true, apply opacity changes without animation. Main clears it after startup.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool snap: true

    onListeningChanged: root._sync()
    onSoundingChanged: root._sync()
    Component.onCompleted: root._sync()

    /*!
     * \brief Select a phase from the current activity inputs.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Sounding takes priority over listening and fracturing. Either activity input releases
     * the boot hold. With all inputs false, sounding becomes exiting; sealing and exiting
     * remain active; other phases become hidden.
     */
    function _sync() {
        // Release the boot hold once an activity phase controls opacity.
        if (booting && (sounding || listening))
            booting = false;
        if (sounding) {
            phase = "sounding";
        } else if (listening) {
            phase = "listening";
        } else if (fracturing) {
            phase = "listening";
        } else if (phase === "sounding") {
            phase = "exiting";
        } else if (phase !== "sealing" && phase !== "exiting") {
            phase = "hidden";
        }
        // The success and exit phases retain control until completion or another input.
    }

    /*!
     * \brief Start the successful unlock animation when work is ending.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Changes sounding or exiting to sealing. Other phases remain unchanged.
     * The phase handler starts the success animation and its watchdog.
     */
    function sealSuccess() {
        if (phase === "sounding" || phase === "exiting")
            phase = "sealing";
    }

    /*!
     * \brief Restart the failure animation and hold the cover visible.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Changes sounding, exiting, or hidden to listening. Other phases remain unchanged.
     * Sets fracturing until the animation completes; repeated calls restart the animation.
     */
    function breakSeal() {
        fracturing = true;
        if (phase === "sounding" || phase === "exiting" || phase === "hidden")
            phase = "listening";
        fractureAnim.restart();
    }

    onPhaseChanged: {
        if (phase === "sealing") {
            sealWatchdog.restart();
            sealAnim.restart();
        } else if (phase === "dismissing") {
            dismissTimer.restart();
        } else if (phase === "sounding") {
            verdict = 0.0;
        }
    }

    // Dismiss if the success animation fails to finish so the unlocked vault stays accessible.
    Timer {
        id: sealWatchdog
        interval: 3800
        onTriggered: if (root.phase === "sealing") root.phase = "hidden"
    }

    // Outlast the 440 ms dismissal fade.
    Timer {
        id: dismissTimer
        interval: 540
        onTriggered: if (root.phase === "dismissing") root.phase = "hidden"
    }

    /*!
     * Maximum animated ring radius in logical pixels, after design scaling.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property real maxRadius: Theme.px(68)
    /*!
     * Seated seal radius as a fraction of the maximum ring radius.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property real sealSeatFactor: 0.95
    readonly property real seatRad: maxRadius * sealSeatFactor

    /*!
     * Follow the Windows reduced-motion preference. Suppresses spin, flashes, and debris.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool calm: WindowVM.reduceMotion

    /*!
     * Duration multiplier for the failure animation when reduced motion is off.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property real fracturePace: 2.4
    /*!
     * Duration multiplier for the success animation when reduced motion is off.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property real successPace: 1.4

    readonly property color hueIndigo:  Theme.auroraIndigo
    readonly property color hueTeal:    Theme.auroraTeal
    readonly property color hueMagenta: Theme.auroraMagenta

    readonly property bool isDark: Theme.dark
    readonly property color glowIndigo:  Theme.auroraGlowIndigo
    readonly property color glowTeal:    Theme.auroraGlowTeal
    readonly property color glowMagenta: Theme.auroraGlowMagenta
    readonly property real glowMul: isDark ? 0.55 : 1.6
    readonly property real payoffMul: isDark ? 1.0 : 1.3

    /*!
     * Verdict tint in [-1, 1]: -1 selects failure, 0 is neutral, and 1 selects success.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property real verdict: 0.0
    readonly property real vGreen: Math.max(0.0, verdict)
    readonly property real vRed: Math.max(0.0, -verdict)
    /*!
     * \brief Interpolate two colors and return an opaque result.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * \a a and \a b supply RGB channels. \a k is a blend factor in [0, 1], where 0 selects
     * \a a and 1 selects \a {b}. The factor is not clamped; input alpha is ignored.
     */
    function vmix(a, b, k) {
        return Qt.rgba(a.r + (b.r - a.r) * k, a.g + (b.g - a.g) * k, a.b + (b.b - a.b) * k, 1.0);
    }

    // Animate layer opacity levels to fade between phases.
    property real auroraLevel: (phase === "sounding" || phase === "exiting"
                               || phase === "sealing" || phase === "dismissing") ? 1.0
                               : (root.fracturing ? 0.5 : 0.0)
    property real ringsLevel: (phase === "sounding" || phase === "exiting") ? 1.0 : 0.0
    property real coreLevel: (phase === "sounding" || phase === "exiting" || phase === "sealing") ? 1.0 : 0.0
    Behavior on auroraLevel { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
    Behavior on ringsLevel { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
    Behavior on coreLevel { NumberAnimation { duration: 300; easing.type: Easing.OutCubic } }

    property real sealProgress: 0.0   // Radius progress: 0 is expanded, 1 is seated.
    property real sealAngle: 0.0      // Conical gradient angle in degrees.
    property real bandOpacity: 0.0    // Band opacity, independent of radius progress.
    readonly property bool sealActive: phase === "sealing" || phase === "dismissing"
    readonly property real sealRad: maxRadius * (1.12 + (sealSeatFactor - 1.12) * sealProgress)

    property real dialAngle: 0.0   // Dial rotation in degrees.
    property real kick: 0.0        // Flash intensity across the cover in [0, 1].
    property real wavePhase: 0.0   // Shockwave expansion from 0 to 1.
    property bool waveActive: false
    property real boltDrive: 0.0   // Shared bolt progress; each bolt uses a different interval.
    property real spinBlur: 0.0    // Blur strength: 1 during rotation, 0 at rest.

    SequentialAnimation {
        id: sealAnim
        PropertyAction { target: root; property: "sealProgress"; value: 0.0 }
        PropertyAction { target: root; property: "sealAngle"; value: 188.0 }
        PropertyAction { target: root; property: "dialAngle"; value: -435.0 }
        PropertyAction { target: root; property: "kick"; value: 0.0 }
        PropertyAction { target: root; property: "wavePhase"; value: 0.0 }
        PropertyAction { target: root; property: "boltDrive"; value: 0.0 }
        PropertyAction { target: root; property: "verdict"; value: 0.0 }
        PropertyAction { target: root; property: "bandOpacity"; value: 0.0 }
        PropertyAction { target: root; property: "spinBlur"; value: root.calm ? 0.0 : 1.0 }
        ParallelAnimation {
            NumberAnimation { target: root; property: "bandOpacity"; to: 1.0; duration: root.calm ? 220 : Math.round(150 * root.successPace); easing.type: Easing.OutSine }
            NumberAnimation { target: root; property: "sealProgress"; to: 1.0; duration: root.calm ? 0 : Math.round(490 * root.successPace); easing.type: Easing.InCubic }
            // 360 + 14 settles just past one turn at a fixed resting angle.
            NumberAnimation { target: root; property: "sealAngle"; to: 374.0; duration: root.calm ? 0 : Math.round(490 * root.successPace); easing.type: Easing.OutExpo }
            SequentialAnimation {
                NumberAnimation { target: root; property: "dialAngle"; to: -30.0; duration: root.calm ? 0 : Math.round(430 * root.successPace); easing.type: Easing.OutQuart }
                NumberAnimation { target: root; property: "dialAngle"; to: 8.0; duration: root.calm ? 0 : Math.round(60 * root.successPace); easing.type: Easing.Linear }
                ParallelAnimation {
                    NumberAnimation { target: root; property: "dialAngle"; to: 0.0; duration: root.calm ? 0 : Math.round(140 * root.successPace); easing.type: Easing.OutBack; easing.overshoot: 1.8 }
                    NumberAnimation { target: root; property: "spinBlur"; to: 0.0; duration: root.calm ? 0 : Math.round(170 * root.successPace); easing.type: Easing.OutCubic }
                    SequentialAnimation {
                        PropertyAction { target: root; property: "waveActive"; value: true }
                        NumberAnimation { target: root; property: "wavePhase"; to: 1.0; duration: root.calm ? 0 : Math.round(460 * root.successPace); easing.type: Easing.OutCubic }
                        PropertyAction { target: root; property: "waveActive"; value: false }
                    }
                    SequentialAnimation {
                        NumberAnimation { target: root; property: "kick"; to: 1.0; duration: root.calm ? 0 : Math.round(70 * root.successPace); easing.type: Easing.OutQuad }
                        NumberAnimation { target: root; property: "kick"; to: 0.0; duration: root.calm ? 0 : Math.round(320 * root.successPace); easing.type: Easing.OutCubic }
                    }
                    NumberAnimation { target: root; property: "boltDrive"; to: 1.0; duration: root.calm ? 0 : Math.round(480 * root.successPace) }
                    // Apply the verdict color when the dial reaches its stop.
                    NumberAnimation { target: root; property: "verdict"; to: 1.0; duration: root.calm ? 240 : Math.round(200 * root.successPace); easing.type: Easing.OutCubic }
                }
            }
            SequentialAnimation {
                // Keep the success hold while reduced motion holds the seal still.
                PauseAnimation { duration: root.calm ? 250 : Math.round(1460 * root.successPace) }
                ScriptAction { script: { if (root.phase === "sealing") root.phase = "dismissing" } }
            }
        }
        // Dismiss if the hold branch misses completion.
        ScriptAction { script: { if (root.phase === "sealing") root.phase = "dismissing" } }
    }

    property real fractureProgress: 1.0   // Progress from 0 to 1; 1 hides fracture effects.
    ParallelAnimation {
        id: fractureAnim
        onFinished: root.fracturing = false
        NumberAnimation {
            target: root; property: "fractureProgress"
            from: 0.0; to: 1.0
            duration: root.calm ? 320 : Math.round(1050 * root.fracturePace)
            easing.type: Easing.OutCubic
        }
        SequentialAnimation {
            NumberAnimation { target: root; property: "verdict"; to: -1.0; duration: root.calm ? 140 : Math.round(140 * root.fracturePace); easing.type: Easing.OutCubic }
            PauseAnimation { duration: root.calm ? 60 : Math.round(640 * root.fracturePace) }
            NumberAnimation { target: root; property: "verdict"; to: 0.0; duration: root.calm ? 160 : Math.round(240 * root.fracturePace); easing.type: Easing.InOutSine }
        }
    }

    opacity: (root.booting || root.fracturing) ? 1.0
           : (phase === "hidden" || phase === "exiting" || phase === "dismissing") ? 0.0 : 1.0
    visible: opacity > 0.001
    Behavior on opacity {
        enabled: !root.snap
        NumberAnimation {
            duration: root.phase === "dismissing" ? 440 : 320
            easing.type: Easing.OutCubic
        }
    }

    // Consume clicks and wheel input. Permit WindowVM dragging while the normal
    // title strip is covered; disable interception during dismissal.
    MouseArea {
        anchors.fill: parent
        enabled: root.visible && root.phase !== "dismissing"
        hoverEnabled: true
        acceptedButtons: Qt.AllButtons
        preventStealing: true
        onPressed: function(mouse) {
            if (mouse.button === Qt.LeftButton
                    && (root.sounding || root.phase === "sealing" || root.phase === "listening"))
                WindowVM.startWindowDrag();
        }
        onWheel: function(wheel) { wheel.accepted = true }
    }

    Shape {
        id: kickGlow
        anchors.fill: parent
        visible: root.kick > 0.001 && !root.calm
        antialiasing: true
        preferredRendererType: Shape.CurveRenderer
        readonly property color kc: root.isDark ? Qt.rgba(0.80, 0.97, 0.88, 1.0) : Theme.verdictSeal
        opacity: (root.isDark ? 0.42 : 0.55) * root.kick
        ShapePath {
            strokeWidth: -1
            fillGradient: RadialGradient {
                centerX: kickGlow.width / 2
                centerY: kickGlow.height / 2
                centerRadius: Math.max(kickGlow.width, kickGlow.height) * 0.62
                focalX: centerX
                focalY: centerY
                GradientStop { position: 0.0;  color: Qt.rgba(kickGlow.kc.r, kickGlow.kc.g, kickGlow.kc.b, 0.26) }
                GradientStop { position: 0.15; color: Qt.rgba(kickGlow.kc.r, kickGlow.kc.g, kickGlow.kc.b, 0.17) }
                GradientStop { position: 0.35; color: Qt.rgba(kickGlow.kc.r, kickGlow.kc.g, kickGlow.kc.b, 0.10) }
                GradientStop { position: 0.55; color: Qt.rgba(kickGlow.kc.r, kickGlow.kc.g, kickGlow.kc.b, 0.05) }
                GradientStop { position: 0.75; color: Qt.rgba(kickGlow.kc.r, kickGlow.kc.g, kickGlow.kc.b, 0.02) }
                GradientStop { position: 1.0;  color: Qt.rgba(kickGlow.kc.r, kickGlow.kc.g, kickGlow.kc.b, 0.0) }
            }
            startX: 0; startY: 0
            PathLine { x: kickGlow.width; y: 0 }
            PathLine { x: kickGlow.width; y: kickGlow.height }
            PathLine { x: 0; y: kickGlow.height }
            PathLine { x: 0; y: 0 }
        }
    }

    Rectangle {
        anchors.fill: parent
        visible: root.fractureProgress < 1.0 && !root.calm
        color: Qt.rgba(0.10, 0.0, 0.02, 1.0)
        opacity: Math.sin(Math.min(1.0, root.fractureProgress / 0.45) * Math.PI) * (root.isDark ? 0.28 : 0.14)
    }

    // Center the animated rings on the password field.
    Item {
        id: spinner
        anchors.centerIn: parent
        width: root.maxRadius * 2
        height: width

        readonly property real tau: 2.0 * Math.PI

        // Stop clocks for reduced motion or a hidden cover to avoid idle repaints.
        property real t: 0.0
        NumberAnimation on t {
            running: root.visible && !root.calm
            from: 0.0; to: 1.0
            duration: 2600
            loops: Animation.Infinite
        }
        property real breath: 0.0
        NumberAnimation on breath {
            running: root.visible && !root.calm
            from: 0.0; to: 1.0
            duration: 5200
            loops: Animation.Infinite
        }
        readonly property real swell: 0.5 - 0.5 * Math.cos(breath * tau)
        readonly property real swellB: 0.5 - 0.5 * Math.cos((breath + 0.15) * tau)
        property real drift: 0.0
        NumberAnimation on drift {
            running: root.visible && !root.calm
            from: 0.0; to: 1.0
            duration: 44000
            loops: Animation.Infinite
        }

        property real sweep: 0.0      // Hue angle in degrees; runs only while rings are visible.
        NumberAnimation on sweep {
            running: root.visible && !root.calm && root.ringsLevel > 0.001
            from: 0.0; to: 360.0
            duration: 7000
            loops: Animation.Infinite
        }

        Shape {
            id: bloom
            visible: root.isDark && root.coreLevel > 0.001
            anchors.centerIn: parent
            width: Theme.px(150); height: width
            antialiasing: true
            preferredRendererType: Shape.CurveRenderer
            // Offset swellB to delay the halo relative to the core.
            opacity: (0.28 + 0.10 * spinner.swellB) * root.coreLevel
            ShapePath {
                strokeWidth: -1
                fillGradient: RadialGradient {
                    centerX: bloom.width / 2
                    centerY: bloom.height / 2
                    centerRadius: bloom.width / 2
                    focalX: centerX
                    focalY: centerY
                    GradientStop { position: 0.0;  color: Qt.rgba(0.78, 0.84, 1.0, 0.16) }
                    GradientStop { position: 0.35; color: Qt.rgba(0.62, 0.72, 1.0, 0.085) }
                    GradientStop { position: 0.6;  color: Qt.rgba(0.55, 0.66, 1.0, 0.035) }
                    GradientStop { position: 0.8;  color: Qt.rgba(0.55, 0.66, 1.0, 0.011) }
                    GradientStop { position: 1.0;  color: Qt.rgba(0.55, 0.66, 1.0, 0.0) }
                }
                startX: bloom.width; startY: bloom.height / 2
                PathArc { x: 0; y: bloom.height / 2; radiusX: bloom.width / 2; radiusY: bloom.height / 2 }
                PathArc { x: bloom.width; y: bloom.height / 2; radiusX: bloom.width / 2; radiusY: bloom.height / 2 }
            }
        }

        Repeater {
            model: [
                { off: 0.00, size: 250 },
                { off: 0.37, size: 214 },
                { off: 0.68, size: 228 }
            ]
            Shape {
                id: aurora
                readonly property color baseHue: [root.glowIndigo, root.glowTeal, root.glowMagenta][index]
                readonly property real verdictStr: [0.35, 0.55, 0.75][index]
                readonly property color hue: root.verdict >= 0.0
                    ? root.vmix(baseHue, Theme.verdictSealFlash, root.vGreen * verdictStr)
                    : root.vmix(baseHue, Theme.verdictBreak, root.vRed * verdictStr)
                readonly property real ph: (spinner.drift + modelData.off) % 1.0
                readonly property real ang: ph * spinner.tau
                readonly property real breathe: 0.5 - 0.5 * Math.cos(ph * spinner.tau)
                visible: root.auroraLevel > 0.001
                anchors.centerIn: parent
                width: Theme.px(modelData.size)
                height: width
                antialiasing: true
                preferredRendererType: Shape.CurveRenderer
                opacity: (0.09 + breathe * 0.06) * root.glowMul * root.auroraLevel
                transform: Translate {
                    x: Math.cos(aurora.ang) * Theme.px(18)
                    y: Math.sin(aurora.ang) * Theme.px(12)
                }
                ShapePath {
                    strokeWidth: -1
                    fillGradient: RadialGradient {
                        centerX: aurora.width / 2
                        centerY: aurora.height / 2
                        centerRadius: aurora.width / 2
                        focalX: centerX
                        focalY: centerY
                        GradientStop { position: 0.0;  color: Qt.rgba(aurora.hue.r, aurora.hue.g, aurora.hue.b, 0.90) }
                        GradientStop { position: 0.35; color: Qt.rgba(aurora.hue.r, aurora.hue.g, aurora.hue.b, 0.48) }
                        GradientStop { position: 0.6;  color: Qt.rgba(aurora.hue.r, aurora.hue.g, aurora.hue.b, 0.20) }
                        GradientStop { position: 0.8;  color: Qt.rgba(aurora.hue.r, aurora.hue.g, aurora.hue.b, 0.06) }
                        GradientStop { position: 1.0;  color: Qt.rgba(aurora.hue.r, aurora.hue.g, aurora.hue.b, 0.0) }
                    }
                    startX: aurora.width; startY: aurora.height / 2
                    PathArc { x: 0; y: aurora.height / 2; radiusX: aurora.width / 2; radiusY: aurora.height / 2 }
                    PathArc { x: aurora.width; y: aurora.height / 2; radiusX: aurora.width / 2; radiusY: aurora.height / 2 }
                }
            }
        }

        Repeater {
            model: 3
            Shape {
                id: ring
                readonly property real ringPhase: (spinner.t + index / 3.0) % 1.0
                readonly property real eased: 1.0 - Math.pow(1.0 - ringPhase, 1.7)
                readonly property real outerR: Math.max(1, eased * root.maxRadius)
                readonly property real strokeW: Math.max(1.0, Theme.pxf(3.0) * (1.0 - 0.55 * ringPhase))
                readonly property real innerR: Math.max(0, outerR - strokeW)
                readonly property real cx: width / 2
                readonly property real cy: width / 2

                visible: root.ringsLevel > 0.001 && !root.calm
                anchors.centerIn: parent
                width: spinner.width
                height: width
                opacity: Math.sin(Math.pow(ringPhase, 0.6) * Math.PI) * 0.7 * root.ringsLevel
                antialiasing: true
                preferredRendererType: Shape.CurveRenderer

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

        Shape {
            id: focal
            visible: root.coreLevel > 0.001
            anchors.centerIn: parent
            width: Theme.px(50); height: width
            antialiasing: true
            preferredRendererType: Shape.CurveRenderer
            readonly property color fc: root.vmix(Theme.accent, Theme.verdictSeal, root.vGreen * 0.55)
            opacity: ((root.isDark ? 0.20 : 0.55) + 0.12 * spinner.swell) * root.coreLevel
            ShapePath {
                strokeWidth: -1
                fillGradient: RadialGradient {
                    centerX: focal.width / 2
                    centerY: focal.height / 2
                    centerRadius: focal.width / 2
                    focalX: centerX
                    focalY: centerY
                    GradientStop { position: 0.0;  color: Qt.rgba(focal.fc.r, focal.fc.g, focal.fc.b, 0.85) }
                    GradientStop { position: 0.35; color: Qt.rgba(focal.fc.r, focal.fc.g, focal.fc.b, 0.45) }
                    GradientStop { position: 0.6;  color: Qt.rgba(focal.fc.r, focal.fc.g, focal.fc.b, 0.19) }
                    GradientStop { position: 0.8;  color: Qt.rgba(focal.fc.r, focal.fc.g, focal.fc.b, 0.06) }
                    GradientStop { position: 1.0;  color: Qt.rgba(focal.fc.r, focal.fc.g, focal.fc.b, 0.0) }
                }
                startX: focal.width; startY: focal.height / 2
                PathArc { x: 0; y: focal.height / 2; radiusX: focal.width / 2; radiusY: focal.height / 2 }
                PathArc { x: focal.width; y: focal.height / 2; radiusX: focal.width / 2; radiusY: focal.height / 2 }
            }
        }

        Rectangle {
            anchors.centerIn: parent
            visible: root.coreLevel > 0.001
            width: Theme.px(7); height: width; radius: width / 2
            color: root.vmix(Theme.accentBright, Theme.verdictSealFlash, root.vGreen * 0.7)
            opacity: root.coreLevel
            scale: 0.92 + 0.18 * spinner.swell + 0.60 * root.kick
        }

        Shape {
            id: seal
            visible: root.sealActive
            anchors.centerIn: parent
            width: root.maxRadius * 4; height: width
            readonly property real cx: width / 2
            readonly property real cy: width / 2
            readonly property real outerR: Math.max(1, root.sealRad)
            readonly property real innerR: Math.max(0, outerR - Theme.pxf(3.6 + 2.6 * root.sealProgress))
            opacity: root.bandOpacity
            antialiasing: true
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                fillRule: ShapePath.OddEvenFill
                strokeWidth: -1
                fillGradient: ConicalGradient {
                    centerX: seal.cx
                    centerY: seal.cy
                    angle: root.sealAngle
                    GradientStop { position: 0.00; color: root.vmix(root.hueIndigo, root.hueTeal, root.vGreen) }
                    GradientStop { position: 0.33; color: root.vmix(root.hueTeal, Theme.verdictSeal, root.vGreen) }
                    GradientStop { position: 0.66; color: root.vmix(root.hueMagenta, root.hueIndigo, root.vGreen) }
                    GradientStop { position: 1.00; color: root.vmix(root.hueIndigo, root.hueTeal, root.vGreen) }
                }
                startX: seal.cx + seal.outerR; startY: seal.cy
                PathArc { x: seal.cx - seal.outerR; y: seal.cy; radiusX: seal.outerR; radiusY: seal.outerR }
                PathArc { x: seal.cx + seal.outerR; y: seal.cy; radiusX: seal.outerR; radiusY: seal.outerR }
                PathMove { x: seal.cx + seal.innerR; y: seal.cy }
                PathArc { x: seal.cx - seal.innerR; y: seal.cy; radiusX: seal.innerR; radiusY: seal.innerR }
                PathArc { x: seal.cx + seal.innerR; y: seal.cy; radiusX: seal.innerR; radiusY: seal.innerR }
            }
        }

        Shape {
            id: dialBlur
            visible: root.sealActive && root.spinBlur > 0.01 && !root.calm
            anchors.centerIn: parent
            width: spinner.width; height: width
            readonly property real cx: width / 2
            readonly property real cy: width / 2
            readonly property real outerR: root.sealRad + Theme.px(6) + Theme.pxf(3.2)
            readonly property real innerR: Math.max(0, root.sealRad + Theme.px(6) - Theme.pxf(3.2))
            readonly property color lobe: root.vmix(root.hueIndigo, Theme.verdictSeal, root.vGreen)
            antialiasing: true
            preferredRendererType: Shape.CurveRenderer
            opacity: root.spinBlur * 0.55 * root.bandOpacity
            ShapePath {
                fillRule: ShapePath.OddEvenFill
                strokeWidth: -1
                fillGradient: ConicalGradient {
                    centerX: dialBlur.cx
                    centerY: dialBlur.cy
                    angle: root.dialAngle
                    GradientStop { position: 0.00; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.85) }
                    GradientStop { position: 0.12; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.28) }
                    GradientStop { position: 0.25; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.85) }
                    GradientStop { position: 0.37; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.28) }
                    GradientStop { position: 0.50; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.85) }
                    GradientStop { position: 0.62; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.28) }
                    GradientStop { position: 0.75; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.85) }
                    GradientStop { position: 0.87; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.28) }
                    GradientStop { position: 1.00; color: Qt.rgba(dialBlur.lobe.r, dialBlur.lobe.g, dialBlur.lobe.b, 0.85) }
                }
                startX: dialBlur.cx + dialBlur.outerR; startY: dialBlur.cy
                PathArc { x: dialBlur.cx - dialBlur.outerR; y: dialBlur.cy; radiusX: dialBlur.outerR; radiusY: dialBlur.outerR }
                PathArc { x: dialBlur.cx + dialBlur.outerR; y: dialBlur.cy; radiusX: dialBlur.outerR; radiusY: dialBlur.outerR }
                PathMove { x: dialBlur.cx + dialBlur.innerR; y: dialBlur.cy }
                PathArc { x: dialBlur.cx - dialBlur.innerR; y: dialBlur.cy; radiusX: dialBlur.innerR; radiusY: dialBlur.innerR }
                PathArc { x: dialBlur.cx + dialBlur.innerR; y: dialBlur.cy; radiusX: dialBlur.innerR; radiusY: dialBlur.innerR }
            }
        }

        Item {
            anchors.centerIn: parent
            width: spinner.width; height: width
            visible: root.sealActive
            rotation: root.dialAngle
            Repeater {
                model: 24
                Item {
                    anchors.centerIn: parent
                    width: 2 * (root.sealRad + Theme.px(6)); height: width
                    rotation: index * 15
                    Rectangle {
                        anchors.horizontalCenter: parent.horizontalCenter
                        y: 0
                        width: index === 0 ? Theme.px(3) : Theme.px(2.0)
                        height: index === 0 ? Theme.px(9) : Theme.px(5.5)
                        radius: width / 2
                        color: index === 0 ? Theme.verdictSealFlash
                                           : root.vmix(root.hueIndigo, Theme.verdictSeal, root.vGreen)
                        opacity: index === 0 ? Math.min(1.0, root.bandOpacity * 1.2) * 0.95
                                             : (0.22 + 0.33 * root.sealProgress) * root.bandOpacity
                                               * (1.0 - root.spinBlur * 0.9)
                    }
                }
            }
        }

        Item {
            anchors.centerIn: parent
            width: 2 * (root.sealRad + Theme.px(13)); height: width
            visible: root.sealActive
            Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                y: 0
                width: Theme.px(2.5); height: Theme.px(6); radius: width / 2
                color: Theme.accentBright
                opacity: (0.25 + 0.55 * root.sealProgress) * root.bandOpacity
            }
        }

        Shape {
            id: shockwave
            visible: root.waveActive
            anchors.centerIn: parent
            width: root.maxRadius * 4.6; height: width
            antialiasing: true
            preferredRendererType: Shape.CurveRenderer
            readonly property real waveR: root.sealRad + (root.maxRadius * 2.1 - root.sealRad) * root.wavePhase
            readonly property color wc: Theme.verdictSealFlash
            opacity: Math.min(1.0, (1.0 - root.wavePhase) * 0.6 * root.payoffMul)
            // Paint the broad halo before the sharp foreground.
            ShapePath {
                strokeColor: Qt.rgba(shockwave.wc.r, shockwave.wc.g, shockwave.wc.b, 0.16)
                strokeWidth: Math.max(1.0, Theme.pxf(12.0 - 7.5 * root.wavePhase))
                fillColor: "transparent"
                PathAngleArc {
                    centerX: shockwave.width / 2
                    centerY: shockwave.height / 2
                    radiusX: shockwave.waveR
                    radiusY: shockwave.waveR
                    startAngle: 0
                    sweepAngle: 360
                }
            }
            ShapePath {
                strokeColor: shockwave.wc
                strokeWidth: Math.max(1.0, Theme.pxf(4.0 - 2.5 * root.wavePhase))
                fillColor: "transparent"
                PathAngleArc {
                    centerX: shockwave.width / 2
                    centerY: shockwave.height / 2
                    radiusX: shockwave.waveR
                    radiusY: shockwave.waveR
                    startAngle: 0
                    sweepAngle: 360
                }
            }
        }

        Repeater {
            model: 3
            Item {
                readonly property real bp: Math.max(0.0, Math.min(1.0, (root.boltDrive - index * 0.1) / 0.8))
                readonly property real bpE: 1.0 - Math.pow(1.0 - bp, 3)
                visible: root.sealActive && bp > 0.001 && !root.calm
                anchors.centerIn: parent
                width: 2 * (root.sealRad + Theme.px(6) + Theme.pxf(38) * bpE); height: width
                rotation: 30 + index * 120
                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    y: 0
                    width: Theme.px(3.5); height: Theme.pxf(12 + 8 * parent.bpE); radius: width / 2
                    color: [root.hueTeal, Theme.verdictSeal, root.hueIndigo][index]
                    opacity: Math.min(1.0, Math.min(1.0, parent.bp / 0.25) * 0.85 * root.payoffMul)
                }
            }
        }

        Repeater {
            model: 3
            Shape {
                id: frag
                readonly property real fp: root.fractureProgress
                readonly property real flightP: root.calm ? 0.0 : Math.max(0.0, (fp - 0.12) / 0.88)
                readonly property real rad: root.seatRad + (root.maxRadius * 1.42 - root.seatRad) * flightP
                readonly property real midAng: (index * 120 - 48) * Math.PI / 180.0
                visible: root.fractureProgress < 1.0
                anchors.centerIn: parent
                width: root.maxRadius * 6; height: width
                opacity: (fp < 0.12 ? fp / 0.12 : Math.pow((1.0 - fp) / 0.88, 1.15))
                antialiasing: true
                preferredRendererType: Shape.CurveRenderer
                rotation: [14, -16, 11][index] * flightP
                transform: Translate {
                    x: Math.cos(frag.midAng) * Theme.pxf(52) * frag.flightP
                    y: Math.sin(frag.midAng) * Theme.pxf(52) * frag.flightP
                }
                ShapePath {
                    strokeColor: [Theme.verdictBreak, root.hueMagenta, Theme.verdictBreakSoft][index]
                    // Use a thick stroke for the first 15% of progress, then taper.
                    strokeWidth: Math.max(1.0, Theme.pxf(4.2) * (1.0 - 0.6 * frag.fp)
                                               + Theme.pxf(2.6) * Math.max(0.0, 1.0 - frag.fp / 0.15))
                    fillColor: "transparent"
                    capStyle: ShapePath.RoundCap
                    PathAngleArc {
                        centerX: frag.width / 2
                        centerY: frag.height / 2
                        radiusX: frag.rad
                        radiusY: frag.rad
                        startAngle: index * 120 - 90
                        sweepAngle: 84 + 34 * Math.max(0.0, 1.0 - frag.flightP * 3.0)
                    }
                }
            }
        }

        Repeater {
            model: 24
            Item {
                readonly property real j1: (index * 0.61803) % 1.0
                readonly property real j2: (index * 0.38197 + 0.17) % 1.0
                readonly property real tp: root.calm ? 0.0
                    : Math.max(0.0, Math.min(1.0, (root.fractureProgress - j1 * 0.12) / 0.75))
                visible: root.fractureProgress < 1.0 && !root.calm
                anchors.centerIn: parent
                width: 2 * (root.seatRad + Theme.px(6) + Theme.pxf(20 + 34 * j1) * tp); height: width
                rotation: index * 15 + (j2 - 0.5) * 90 * tp
                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    y: 0
                    width: Theme.px(2.0); height: Theme.px(5.5); radius: width / 2
                    color: Theme.verdictBreakSoft
                    opacity: (parent.tp < 0.12 ? parent.tp / 0.12 : Math.pow((1.0 - parent.tp) / 0.88, 1.3)) * 0.65
                }
            }
        }
    }

    /*!
     * Last non-empty caption. Retained while the caption fades out.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string lastCaption: ""
    onCaptionChanged: if (caption.length > 0) lastCaption = caption

    Item {
        id: captionBlock
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        anchors.verticalCenterOffset: root.maxRadius + Theme.px(38)
        width: capText.implicitWidth
        height: capText.implicitHeight
        opacity: root.caption.length > 0 ? 1.0 : 0.0
        visible: opacity > 0.001
        Behavior on opacity { NumberAnimation { duration: 260; easing.type: Easing.OutCubic } }

        // Remove trailing dots and whitespace; the animated ellipsis supplies the dots.
        readonly property string baseText: root.lastCaption.replace(/[.\s]+$/, "")
        property int dots: 0
        Timer {
            interval: 420
            running: captionBlock.visible && captionBlock.baseText.length > 0
            repeat: true
            onTriggered: captionBlock.dots = (captionBlock.dots + 1) % 4
        }

        Text {
            id: capText
            anchors.horizontalCenter: parent.horizontalCenter
            text: captionBlock.baseText
            color: Theme.textSecondary
            font.family: Theme.fontFamily
            font.pixelSize: Theme.px(11)
            font.letterSpacing: Theme.px(2.4)
            font.weight: Font.Medium
            font.capitalization: Font.AllUppercase
            renderType: Text.NativeRendering
        }
        Text {
            anchors.left: capText.right
            anchors.baseline: capText.baseline
            text: "...".substring(0, captionBlock.dots)
            color: Theme.textSecondary
            font: capText.font
            renderType: Text.NativeRendering
        }
    }
}
