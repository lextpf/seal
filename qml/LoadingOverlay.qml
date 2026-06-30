import QtQuick
import QtQuick.Shapes

// The unified "unseal" instrument. One full-window cover that spans master-
// password entry AND the decryption it triggers, so the two read as a single
// continuous moment rather than a card popped over a spinner.
//
// Main raises this whenever the password dialog is open (entry) or the vault is
// being decrypted/re-encrypted on a worker thread (the grind). Both states sit
// on the SAME sonar, at the SAME centre the password field occupies -- the field
// is the heart of the instrument, the rings bloom from where you typed.
//
// PHASE MACHINE (driven by `listening`/`sounding` inputs + sealSuccess/breakSeal):
//   hidden    -- unmounted, zero cost (no timers).
//   listening -- password entry. A calm drifting aurora only; the working
//                "sonar ping" is suppressed so typing is never distracting, and
//                the bright core is suppressed so the bare field owns the centre.
//   sounding  -- scrypt key derivation. Full sonar: three rings bloom from the
//                centre, the bright breathing core anchors it, aurora at full.
//   sealing   -- a verified GCM auth tag. The signature: a milled ring forms and
//                contracts as its conic sweep decelerates and LOCKS, like a key
//                seating -- the cryptographic "seal" closing. One cold specular
//                glint crosses it. Then the cover fades out into the vault.
//   exiting   -- the grind ended without a seal trigger (hard error / fallback):
//                the full sonar simply fades out. The unlock flow is NEVER blocked
//                by the seal flourish -- if the success trigger doesn't fire, the
//                cover still dismisses normally.
//
// On a wrong key, breakSeal() plays a one-shot over the re-formed entry: the seal
// fractures into its three constituent hues, which fly apart and scatter -- a GCM
// tag that did not verify, shown as a seal that physically broke.
//
// All animation drivers are gated `running: root.visible` and the cover fully
// unmounts when idle, so it costs nothing -- and runs no animation -- between loads.
Item {
    id: root

    // --- Inputs (set by Main) -----------------------------------------------
    property bool listening: false   ///< Password entry active (dim aurora, bare field owns centre).
    property bool sounding: false    ///< scrypt grind running (full sonar).
    property string caption: ""      ///< Text beneath the sonar during the grind.

    // --- Phase machine ------------------------------------------------------
    // hidden | listening | sounding | exiting | sealing
    property string phase: "hidden"

    onListeningChanged: root._sync()
    onSoundingChanged: root._sync()
    Component.onCompleted: root._sync()

    // Reconcile phase from the two inputs. `sounding` wins (the grind is the
    // loudest state); then `listening`. When the grind ends with neither input
    // set, default to `exiting` (a graceful fade) UNLESS a seal is already
    // playing -- sealSuccess() upgrades `exiting`/`sounding` to `sealing`.
    function _sync() {
        if (sounding) {
            phase = "sounding";
        } else if (listening) {
            phase = "listening";
        } else if (phase === "sounding") {
            phase = "exiting";
        } else if (phase !== "sealing" && phase !== "exiting") {
            phase = "hidden";
        }
        // `sealing`/`exiting` are transient outros; they settle themselves.
    }

    // Called by Main on a verified unlock (vaultLoadedChanged && vaultLoaded).
    // Upgrades the pending exit into the closing-seal outro. Only valid coming
    // out of the grind, so a stray call can never resurrect a hidden cover.
    function sealSuccess() {
        if (phase === "sounding" || phase === "exiting")
            phase = "sealing";
    }

    // Called by Main on a wrong key (passwordRetryRequired). One-shot fracture
    // over the re-formed entry; phase is driven back to `listening` by the
    // dialog re-opening, this just plays the break.
    function breakSeal() {
        fractureAnim.restart();
    }

    onPhaseChanged: {
        if (phase === "sealing") {
            sealWatchdog.restart();
            sealAnim.restart();
        } else if (phase === "dismissing") {
            dismissTimer.restart();
        }
    }

    // Safety net: a seal outro must always terminate. If anything stalls it,
    // force the cover hidden so a successful unlock can never leave it wedged.
    Timer {
        id: sealWatchdog
        interval: 1400
        onTriggered: if (root.phase === "sealing") root.phase = "hidden"
    }

    // After the seal seats, the cover fades out with the seated seal still on it
    // (the `dismissing` phase keeps opacity easing to 0 while the seal stays
    // visible, so the signature doesn't pop). This returns it to fully hidden
    // once the fade has cleared, so the next load starts from a clean idle.
    Timer {
        id: dismissTimer
        interval: 280
        onTriggered: if (root.phase === "dismissing") root.phase = "hidden"
    }

    // --- Tuning -------------------------------------------------------------
    readonly property real maxRadius: Theme.px(58)

    // The three signature blob hues, lifted to a saturation that READS on the
    // dim scrim. Hue-matched to Theme.blobColor1/2/3: indigo / teal / magenta.
    readonly property color hueIndigo:  Qt.rgba(0.42, 0.34, 0.95, 1.0)
    readonly property color hueTeal:    Qt.rgba(0.22, 0.74, 0.82, 1.0)
    readonly property color hueMagenta: Qt.rgba(0.82, 0.30, 0.74, 1.0)

    // Theme-aware GLOW for the aurora halos (see the long note in git history):
    // dark must EMIT luminous hues on near-black; light must SATURATE denser hues
    // on near-white. Same trick the cover has always used.
    readonly property bool isDark: Theme.dark
    readonly property color glowIndigo:  isDark ? Qt.rgba(0.60, 0.54, 1.00, 1.0) : hueIndigo
    readonly property color glowTeal:    isDark ? Qt.rgba(0.50, 0.90, 0.98, 1.0) : hueTeal
    readonly property color glowMagenta: isDark ? Qt.rgba(0.98, 0.60, 0.92, 1.0) : hueMagenta
    readonly property real glowMul: isDark ? 0.25 : 1.6

    // --- Amplitude levels (the inverse-amplitude discipline) ----------------
    // These three are bound to `phase` AND animated by the Behaviors below, so
    // they must be writable (not readonly): the binding sets each new target as
    // the phase changes and the Behavior eases the value to it -- the same
    // "bound property + Behavior" idiom used for the colour transitions elsewhere.
    // Aurora: NOT during password entry -- a clean dark scrim owns the bare
    // field, with no central glow behind it. The aurora blooms in only once the
    // grind/seal begins, so the instrument visibly comes alive on submit.
    property real auroraLevel: (phase === "sounding" || phase === "exiting"
                               || phase === "sealing" || phase === "dismissing") ? 1.0 : 0.0
    // Blooming sonar rings: ONLY during the grind. Dissolve as the seal forms.
    property real ringsLevel: (phase === "sounding" || phase === "exiting") ? 1.0 : 0.0
    // Bright core / focal: with the rings, plus through the seal outro.
    property real coreLevel: (phase === "sounding" || phase === "exiting" || phase === "sealing") ? 1.0 : 0.0
    Behavior on auroraLevel { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
    Behavior on ringsLevel { NumberAnimation { duration: 360; easing.type: Easing.OutCubic } }
    Behavior on coreLevel { NumberAnimation { duration: 300; easing.type: Easing.OutCubic } }

    // --- Seal outro state (driven by sealAnim) ------------------------------
    property real sealProgress: 0.0   ///< 0 forming -> 1 locked; drives contraction.
    property real sealAngle: 0.0      ///< conic sweep angle, decelerates to a locked rest.
    property real sealSpec: -0.2      ///< specular glint position around the rim.
    readonly property bool sealActive: phase === "sealing" || phase === "dismissing"
    // Ring contracts from a wide forming radius down to a seated resting radius.
    readonly property real sealRad: maxRadius * (0.95 + (0.58 - 0.95) * sealProgress)

    SequentialAnimation {
        id: sealAnim
        PropertyAction { target: root; property: "sealProgress"; value: 0.0 }
        PropertyAction { target: root; property: "sealSpec"; value: -0.2 }
        PropertyAction { target: root; property: "sealAngle"; value: 188.0 }
        ParallelAnimation {
            NumberAnimation { target: root; property: "sealProgress"; to: 1.0; duration: 560; easing.type: Easing.OutExpo }
            // 360 + 14: settle just past a full turn to a fixed resting angle.
            NumberAnimation { target: root; property: "sealAngle"; to: 374.0; duration: 640; easing.type: Easing.OutExpo }
            SequentialAnimation {
                PauseAnimation { duration: 130 }
                NumberAnimation { target: root; property: "sealSpec"; to: 1.2; duration: 460; easing.type: Easing.OutCubic }
            }
        }
        PauseAnimation { duration: 90 }
        // Hand off to the dismiss fade with the seated seal still visible, so the
        // signature fades out with the cover instead of popping.
        ScriptAction { script: { if (root.phase === "sealing") root.phase = "dismissing" } }
    }

    // --- Fracture state (driven by breakSeal) -------------------------------
    property real fractureProgress: 1.0   ///< 1 = idle/hidden; animates 0 -> 1.
    NumberAnimation {
        id: fractureAnim
        target: root; property: "fractureProgress"
        from: 0.0; to: 1.0; duration: 540; easing.type: Easing.OutCubic
    }

    // Cross-fade the whole cover; unmount once fully faded so the looping
    // animations stop and no input is captured while idle.
    opacity: (phase === "hidden" || phase === "exiting" || phase === "dismissing") ? 0.0 : 1.0
    visible: opacity > 0.001
    Behavior on opacity { NumberAnimation { duration: 220; easing.type: Easing.OutCubic } }

    // Swallow all pointer input to the UI underneath for the duration. A
    // left-press still drags the frameless window (the title bar is covered),
    // so the user can reposition while decrypting -- during password entry the
    // dialog's modal layer handles the same gesture (see PasswordDialog).
    MouseArea {
        anchors.fill: parent
        enabled: root.visible
        hoverEnabled: true
        acceptedButtons: Qt.AllButtons
        preventStealing: true
        onPressed: function(mouse) {
            // Drag only while the cover is OPAQUE (the grind, and the opaque seal
            // close). During the translucent dismissing/exiting fade the vault is
            // already showing through, so a press there must NOT be hijacked into
            // a window move -- it falls through to a harmless swallow, as before.
            // (Entry-state dragging is handled by the dialog's modal dim layer.)
            if (mouse.button === Qt.LeftButton && (root.sounding || root.phase === "sealing"))
                WindowVM.startWindowDrag();
        }
        onWheel: function(wheel) { wheel.accepted = true }
    }

    // Strong scrim derived from the theme's deepest background: opaque enough to
    // firmly cover the app underneath while still adapting to dark/light. Makes
    // the colourful instrument -- and the bare field over it -- pop.
    Rectangle {
        anchors.fill: parent
        color: Qt.rgba(Theme.bgDeep.r, Theme.bgDeep.g, Theme.bgDeep.b, root.isDark ? 0.985 : 0.92)
    }

    // The sonar core, centred on the exact pixel the password field occupies.
    Item {
        id: spinner
        anchors.centerIn: parent
        width: root.maxRadius * 2
        height: width

        readonly property real tau: 2.0 * Math.PI

        // Ripple driver: one phase in [0,1) loops; each ring reads it at an offset.
        property real t: 0.0
        NumberAnimation on t {
            running: root.visible
            from: 0.0; to: 1.0
            duration: 2600
            loops: Animation.Infinite
        }

        // Conic-sweep driver: one slow full turn so ring colours shimmer through
        // the blob spectrum as they grow.
        property real sweep: 0.0
        NumberAnimation on sweep {
            running: root.visible
            from: 0.0; to: 360.0
            duration: 7000
            loops: Animation.Infinite
        }

        // Gentle breathing curve for the bright core's swell.
        property real breath: 0.0
        NumberAnimation on breath {
            running: root.visible
            from: 0.0; to: 1.0
            duration: 2600
            loops: Animation.Infinite
        }
        readonly property real swell: 0.5 - 0.5 * Math.cos(breath * spinner.tau)

        // Dark-only near-white bloom that just barely lifts the centre so the
        // coloured rings read as emitted light. Tied to the core's presence.
        Shape {
            id: bloom
            visible: root.isDark && root.coreLevel > 0.001
            anchors.centerIn: parent
            width: Theme.px(150); height: width
            antialiasing: true
            preferredRendererType: Shape.CurveRenderer
            layer.enabled: true
            layer.samples: 4
            opacity: (0.28 + 0.10 * spinner.swell) * root.coreLevel
            ShapePath {
                strokeWidth: -1
                fillGradient: RadialGradient {
                    centerX: bloom.width / 2
                    centerY: bloom.height / 2
                    centerRadius: bloom.width / 2
                    focalX: centerX
                    focalY: centerY
                    GradientStop { position: 0.0;  color: Qt.rgba(0.78, 0.84, 1.0, 0.16) }
                    GradientStop { position: 0.45; color: Qt.rgba(0.55, 0.66, 1.0, 0.05) }
                    GradientStop { position: 1.0;  color: Qt.rgba(0.55, 0.66, 1.0, 0.0) }
                }
                startX: bloom.width; startY: bloom.height / 2
                PathArc { x: 0; y: bloom.height / 2; radiusX: bloom.width / 2; radiusY: bloom.height / 2 }
                PathArc { x: bloom.width; y: bloom.height / 2; radiusX: bloom.width / 2; radiusY: bloom.height / 2 }
            }
        }

        // Aurora backdrop: three large radial glows in the blob hues, drifting on
        // their own ellipses for atmospheric depth. The only motion during entry
        // (scaled by auroraLevel), full during the grind.
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
                visible: root.auroraLevel > 0.001
                anchors.centerIn: parent
                width: Theme.px(modelData.size)
                height: width
                antialiasing: true
                preferredRendererType: Shape.CurveRenderer
                layer.enabled: true
                layer.samples: 4
                opacity: (0.09 + breathe * 0.06) * root.glowMul * root.auroraLevel
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

        // Conic sonar ripples: three donut rings expanding from the centre to
        // maxRadius. Present only during the grind (ringsLevel) -- the "working"
        // signal. Radius eases out for a natural ping; the stroke is a soft conic
        // sweep of the three blob hues, rotating with `sweep`, offset 120 deg per
        // ring. Drawn as GPU vector donuts (OddEvenFill).
        Repeater {
            model: 3
            Shape {
                id: ring
                readonly property real phase: (spinner.t + index / 3.0) % 1.0
                readonly property real eased: 1.0 - Math.pow(1.0 - phase, 2.4)
                readonly property real outerR: Math.max(1, eased * root.maxRadius)
                readonly property real strokeW: Math.max(1.0, Theme.px(3.0) * (1.0 - 0.55 * phase))
                readonly property real innerR: Math.max(0, outerR - strokeW)
                readonly property real cx: width / 2
                readonly property real cy: width / 2

                visible: root.ringsLevel > 0.001
                anchors.centerIn: parent
                width: spinner.width
                height: width
                opacity: Math.sin(phase * Math.PI) * 0.7 * root.ringsLevel
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

        // Clean focal point: one soft accent halo so the centre reads as a single
        // intentional glowing point. Present with the core.
        Shape {
            id: focal
            visible: root.coreLevel > 0.001
            anchors.centerIn: parent
            width: Theme.px(50); height: width
            antialiasing: true
            preferredRendererType: Shape.CurveRenderer
            layer.enabled: true
            layer.samples: 4
            opacity: ((root.isDark ? 0.20 : 0.55) + 0.12 * spinner.swell) * root.coreLevel
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

        // Crisp breathing core -- the bright point the ripples emanate from.
        Rectangle {
            anchors.centerIn: parent
            visible: root.coreLevel > 0.001
            width: Theme.px(7); height: width; radius: width / 2
            color: Theme.accentBright
            opacity: root.coreLevel
            scale: 0.92 + 0.18 * spinner.swell
        }

        // --- The closing seal (signature) -----------------------------------
        // A milled ring that forms and contracts as its conic sweep decelerates
        // to a locked resting angle -- the cryptographic seal closing on a
        // verified GCM tag. Cold light pressed into deep water, never warm wax.

        // The conic band (the seal's face).
        Shape {
            id: seal
            visible: root.sealActive
            anchors.centerIn: parent
            width: spinner.width; height: width
            readonly property real cx: width / 2
            readonly property real cy: width / 2
            readonly property real outerR: Math.max(1, root.sealRad)
            readonly property real innerR: Math.max(0, outerR - Theme.px(3.2))
            opacity: Math.min(1.0, root.sealProgress * 4.0)
            antialiasing: true
            layer.enabled: true
            layer.samples: 4
            layer.smooth: true
            ShapePath {
                fillRule: ShapePath.OddEvenFill
                strokeWidth: -1
                fillGradient: ConicalGradient {
                    centerX: seal.cx
                    centerY: seal.cy
                    angle: root.sealAngle
                    GradientStop { position: 0.00; color: root.hueIndigo }
                    GradientStop { position: 0.33; color: root.hueTeal }
                    GradientStop { position: 0.66; color: root.hueMagenta }
                    GradientStop { position: 1.00; color: root.hueIndigo }
                }
                startX: seal.cx + seal.outerR; startY: seal.cy
                PathArc { x: seal.cx - seal.outerR; y: seal.cy; radiusX: seal.outerR; radiusY: seal.outerR }
                PathArc { x: seal.cx + seal.outerR; y: seal.cy; radiusX: seal.outerR; radiusY: seal.outerR }
                PathMove { x: seal.cx + seal.innerR; y: seal.cy }
                PathArc { x: seal.cx - seal.innerR; y: seal.cy; radiusX: seal.innerR; radiusY: seal.innerR }
                PathArc { x: seal.cx + seal.innerR; y: seal.cy; radiusX: seal.innerR; radiusY: seal.innerR }
            }
        }

        // The milled / reeded rim -- 24 fine ticks evoking a pressed seal's edge
        // and a cipher dial, brightening as the seal seats.
        Item {
            anchors.centerIn: parent
            width: spinner.width; height: width
            visible: root.sealActive
            Repeater {
                model: 24
                Item {
                    anchors.centerIn: parent
                    width: 2 * (root.sealRad + Theme.px(5)); height: width
                    rotation: index * 15
                    Rectangle {
                        anchors.horizontalCenter: parent.horizontalCenter
                        y: 0
                        width: Theme.px(1.6); height: Theme.px(4.4); radius: width / 2
                        color: Theme.accent
                        opacity: (0.10 + 0.20 * root.sealProgress) * Math.min(1.0, root.sealProgress * 4.0)
                    }
                }
            }
        }

        // A single cold specular glint sweeping once across the seated seal,
        // like light catching pressed metal.
        Item {
            anchors.centerIn: parent
            width: spinner.width; height: width
            visible: root.sealActive
            rotation: -90 + root.sealSpec * 360
            Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                y: parent.height / 2 - root.sealRad - height / 2
                width: Theme.px(6); height: width; radius: width / 2
                color: Theme.accentBright
                // Envelope: rises then falls across the 0..1 sweep window.
                opacity: (root.sealSpec >= 0.0 && root.sealSpec <= 1.0)
                         ? Math.sin(root.sealSpec * Math.PI) * 0.9 : 0.0
            }
        }

        // --- The fracture (wrong key) ---------------------------------------
        // The seal splits into its three constituent hues; the arcs fly apart
        // and scatter -- a GCM tag that did not verify. Plays over the re-formed
        // entry. One-shot; unmounts when done.
        Repeater {
            model: 3
            Shape {
                id: frag
                readonly property real fp: root.fractureProgress
                readonly property real rad: Theme.px(40) + (Theme.px(86) - Theme.px(40)) * fp
                readonly property real midAng: (index * 120 - 48) * Math.PI / 180.0
                visible: root.fractureProgress < 1.0
                anchors.centerIn: parent
                width: spinner.width; height: width
                opacity: (fp < 0.12 ? fp / 0.12 : Math.pow(1.0 - fp, 1.3))
                antialiasing: true
                layer.enabled: true
                layer.samples: 4
                layer.smooth: true
                transform: Translate {
                    x: Math.cos(frag.midAng) * Theme.px(10) * frag.fp
                    y: Math.sin(frag.midAng) * Theme.px(10) * frag.fp
                }
                ShapePath {
                    strokeColor: [root.hueIndigo, root.hueTeal, root.hueMagenta][index]
                    strokeWidth: Math.max(1.0, Theme.px(3.4) * (1.0 - 0.6 * frag.fp))
                    fillColor: "transparent"
                    capStyle: ShapePath.RoundCap
                    PathAngleArc {
                        centerX: frag.width / 2
                        centerY: frag.height / 2
                        radiusX: frag.rad
                        radiusY: frag.rad
                        startAngle: index * 120 - 90
                        sweepAngle: 84
                    }
                }
            }
        }
    }

    // Caption with a gently animated trailing ellipsis, seated below the sonar
    // so the rings/seal bloom from the exact centre. The C++ side may send a
    // string with trailing dots; we strip those and re-add an animated 0-3 dot
    // cycle. A fixed-width dots slot keeps the base label from shifting.
    Row {
        id: captionRow
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        anchors.verticalCenterOffset: root.maxRadius + Theme.px(34)
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
            color: Theme.textPrimary
            font.family: Theme.fontFamily
            font.pixelSize: Theme.px(13)
            font.letterSpacing: 1.4
            font.weight: Font.Bold
            renderType: Text.QtRendering
        }
        Text {
            width: dotsMetrics.implicitWidth
            text: "...".substring(0, captionRow.dots)
            color: Theme.textPrimary
            font: capText.font
            renderType: Text.QtRendering
        }
        Text { id: dotsMetrics; visible: false; text: "..."; font: capText.font }
    }
}
