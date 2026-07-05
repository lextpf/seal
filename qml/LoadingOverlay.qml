import QtQuick
import QtQuick.Shapes

Item {
    id: root

    // --- Inputs (set by Main) -----------------------------------------------
    property bool listening: false   // Password entry active (dim aurora, bare field owns centre).
    property bool sounding: false    // scrypt grind running (full sonar).
    property string caption: ""      // Text beneath the sonar during the grind.

    property string phase: "hidden"

    property bool fracturing: false

    onListeningChanged: root._sync()
    onSoundingChanged: root._sync()
    Component.onCompleted: root._sync()

    function _sync() {
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
        // `sealing`/`exiting` are transient outros; they settle themselves.
    }

    function sealSuccess() {
        if (phase === "sounding" || phase === "exiting")
            phase = "sealing";
    }

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

    Timer {
        id: sealWatchdog
        interval: 3800
        onTriggered: if (root.phase === "sealing") root.phase = "hidden"
    }

    Timer {
        id: dismissTimer
        interval: 540
        onTriggered: if (root.phase === "dismissing") root.phase = "hidden"
    }

    // --- Tuning -------------------------------------------------------------
    readonly property real maxRadius: Theme.px(58)
    readonly property real sealSeatFactor: 0.95
    readonly property real seatRad: maxRadius * sealSeatFactor

    readonly property bool calm: WindowVM.reduceMotion

    readonly property real fracturePace: 2.4
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

    property real verdict: 0.0
    readonly property real vGreen: Math.max(0.0, verdict)
    readonly property real vRed: Math.max(0.0, -verdict)
    function vmix(a, b, k) {
        return Qt.rgba(a.r + (b.r - a.r) * k, a.g + (b.g - a.g) * k, a.b + (b.b - a.b) * k, 1.0);
    }

    property real auroraLevel: (phase === "sounding" || phase === "exiting"
                               || phase === "sealing" || phase === "dismissing") ? 1.0
                               : (root.fracturing ? 0.5 : 0.0)
    // Blooming sonar rings: ONLY during the grind. Dissolve as the seal forms.
    property real ringsLevel: (phase === "sounding" || phase === "exiting") ? 1.0 : 0.0
    // Bright core / focal: with the rings, plus through the seal outro.
    property real coreLevel: (phase === "sounding" || phase === "exiting" || phase === "sealing") ? 1.0 : 0.0
    Behavior on auroraLevel { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
    Behavior on ringsLevel { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
    Behavior on coreLevel { NumberAnimation { duration: 300; easing.type: Easing.OutCubic } }

    // --- Seal outro state (driven by sealAnim) ------------------------------
    property real sealProgress: 0.0   // The press: 0 formed wide -> 1 seated.
    property real sealAngle: 0.0      // conic sweep angle, decelerates to a locked rest.
    property real sealSpec: -0.2      // specular streak position around the rim.
    property real bandOpacity: 0.0    // band's own genesis fade (decoupled from the press).
    readonly property bool sealActive: phase === "sealing" || phase === "dismissing"
    readonly property real sealRad: maxRadius * (1.12 + (sealSeatFactor - 1.12) * sealProgress)

    property real dialAngle: 0.0
    // Clunk cluster drivers (all reset by sealAnim, all gate their own items).
    property real kick: 0.0        // full-cover luminance kick envelope.
    property real wavePhase: 0.0   // shockwave expansion 0 -> 1.
    property bool waveActive: false
    property real boltDrive: 0.0   // bolt-throw master clock; bolts window it.
    property real spinBlur: 0.0    // 1 while the dial whirs, eased to 0 at the catch.

    SequentialAnimation {
        id: sealAnim
        PropertyAction { target: root; property: "sealProgress"; value: 0.0 }
        PropertyAction { target: root; property: "sealSpec"; value: -0.2 }
        PropertyAction { target: root; property: "sealAngle"; value: 188.0 }
        PropertyAction { target: root; property: "dialAngle"; value: -435.0 }
        PropertyAction { target: root; property: "kick"; value: 0.0 }
        PropertyAction { target: root; property: "wavePhase"; value: 0.0 }
        PropertyAction { target: root; property: "boltDrive"; value: 0.0 }
        PropertyAction { target: root; property: "verdict"; value: 0.0 }
        PropertyAction { target: root; property: "bandOpacity"; value: 0.0 }
        PropertyAction { target: root; property: "spinBlur"; value: root.calm ? 0.0 : 1.0 }
        ParallelAnimation {
            // Genesis: the band fades in fast at its forming radius...
            NumberAnimation { target: root; property: "bandOpacity"; to: 1.0; duration: root.calm ? 220 : Math.round(150 * root.successPace); easing.type: Easing.OutSine }
            // ...then presses inward, accelerating INTO the seat.
            NumberAnimation { target: root; property: "sealProgress"; to: 1.0; duration: root.calm ? 0 : Math.round(490 * root.successPace); easing.type: Easing.InCubic }
            // 360 + 14: settle just past a full turn to a fixed resting angle.
            NumberAnimation { target: root; property: "sealAngle"; to: 374.0; duration: root.calm ? 0 : Math.round(490 * root.successPace); easing.type: Easing.OutExpo }
            SequentialAnimation {
                // Spin down to just short of rest...
                NumberAnimation { target: root; property: "dialAngle"; to: -30.0; duration: root.calm ? 0 : Math.round(430 * root.successPace); easing.type: Easing.OutQuart }
                // ...the STRIKE: visible velocity through zero...
                NumberAnimation { target: root; property: "dialAngle"; to: 8.0; duration: root.calm ? 0 : Math.round(60 * root.successPace); easing.type: Easing.Linear }
                // ...and the catch, with the clunk cluster fired on this frame.
                ParallelAnimation {
                    NumberAnimation { target: root; property: "dialAngle"; to: 0.0; duration: root.calm ? 0 : Math.round(140 * root.successPace); easing.type: Easing.OutBack; easing.overshoot: 1.8 }
                    // The blur resolves into crisp ticks as the dial seats.
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
                    // The verdict lands WITH the clunk, not before it.
                    NumberAnimation { target: root; property: "verdict"; to: 1.0; duration: root.calm ? 240 : Math.round(200 * root.successPace); easing.type: Easing.OutCubic }
                }
            }
            SequentialAnimation {
                PauseAnimation { duration: root.calm ? 250 : Math.round(720 * root.successPace) }
                NumberAnimation { target: root; property: "sealSpec"; to: 1.2; duration: root.calm ? 0 : Math.round(560 * root.successPace); easing.type: Easing.InOutSine }
                PauseAnimation { duration: root.calm ? 0 : Math.round(180 * root.successPace) }
                ScriptAction { script: { if (root.phase === "sealing") root.phase = "dismissing" } }
            }
        }
        // Guard: if the glint branch ever mistimes, the cover still dismisses.
        ScriptAction { script: { if (root.phase === "sealing") root.phase = "dismissing" } }
    }

    // --- Fracture state (driven by breakSeal) -------------------------------
    property real fractureProgress: 1.0   // 1 = idle/hidden; animates 0 -> 1.
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

    opacity: root.fracturing ? 1.0
           : (phase === "hidden" || phase === "exiting" || phase === "dismissing") ? 0.0 : 1.0
    visible: opacity > 0.001
    Behavior on opacity {
        NumberAnimation {
            duration: root.phase === "dismissing" ? 440 : 320
            easing.type: Easing.OutCubic
        }
    }

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

    Rectangle {
        anchors.fill: parent
        color: Qt.rgba(Theme.bgDeep.r, Theme.bgDeep.g, Theme.bgDeep.b, root.isDark ? 1.0 : 0.92)
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

    // The sonar core, centred on the exact pixel the password field occupies.
    Item {
        id: spinner
        anchors.centerIn: parent
        width: root.maxRadius * 2
        height: width

        readonly property real tau: 2.0 * Math.PI

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

        property real sweep: 0.0
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
            // Lagged swell (swellB) so the halo breathes a beat behind the core.
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

        // Crisp breathing core -- the bright point the ripples emanate from.
        Rectangle {
            anchors.centerIn: parent
            visible: root.coreLevel > 0.001
            width: Theme.px(7); height: width; radius: width / 2
            color: root.vmix(Theme.accentBright, Theme.verdictSealFlash, root.vGreen * 0.7)
            opacity: root.coreLevel
            // The pop rides the clunk's kick on top of the idle breathing.
            scale: 0.92 + 0.18 * spinner.swell + 0.60 * root.kick
        }

        // The conic band (the seal's face).
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

        Item {
            anchors.centerIn: parent
            width: spinner.width; height: width
            visible: root.sealActive
            rotation: -90 + root.sealSpec * 360
            Item {
                readonly property real env: (root.sealSpec >= 0.0 && root.sealSpec <= 1.0)
                                            ? Math.sin(root.sealSpec * Math.PI) : 0.0
                anchors.horizontalCenter: parent.horizontalCenter
                y: parent.height / 2 - root.sealRad - height / 2
                width: Theme.px(30); height: Theme.px(6)
                // Soft halo under the streak.
                Rectangle {
                    anchors.centerIn: parent
                    width: parent.width; height: parent.height; radius: height / 2
                    opacity: parent.env * 0.35
                    gradient: Gradient {
                        orientation: Gradient.Horizontal
                        GradientStop { position: 0.0; color: Qt.rgba(Theme.accentBright.r, Theme.accentBright.g, Theme.accentBright.b, 0.0) }
                        GradientStop { position: 0.5; color: Qt.rgba(Theme.accentBright.r, Theme.accentBright.g, Theme.accentBright.b, 0.9) }
                        GradientStop { position: 1.0; color: Qt.rgba(Theme.accentBright.r, Theme.accentBright.g, Theme.accentBright.b, 0.0) }
                    }
                }
                // Crisp core of the streak.
                Rectangle {
                    anchors.centerIn: parent
                    width: Theme.px(16); height: Theme.px(2.5); radius: height / 2
                    opacity: parent.env * 0.95
                    gradient: Gradient {
                        orientation: Gradient.Horizontal
                        GradientStop { position: 0.0; color: Qt.rgba(Theme.accentBright.r, Theme.accentBright.g, Theme.accentBright.b, 0.0) }
                        GradientStop { position: 0.5; color: Theme.accentBright }
                        GradientStop { position: 1.0; color: Qt.rgba(Theme.accentBright.r, Theme.accentBright.g, Theme.accentBright.b, 0.0) }
                    }
                }
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
            // Wide low-alpha halo first (paint order), crisp front on top.
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
                // Rotational shear per arc -- the break twists as it flies.
                rotation: [14, -16, 11][index] * flightP
                transform: Translate {
                    x: Math.cos(frag.midAng) * Theme.pxf(52) * frag.flightP
                    y: Math.sin(frag.midAng) * Theme.pxf(52) * frag.flightP
                }
                ShapePath {
                    strokeColor: [Theme.verdictBreak, root.hueMagenta, Theme.verdictBreakSoft][index]
                    // Early flash: thick for the first ~15%, then thins away.
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
