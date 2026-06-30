pragma Singleton
import QtQuick
import QtCore

// Centralized design token singleton. Every visual property (colors, spacing,
// radii, fonts, icons) lives here so components never hard-code values.
//
// Theme switching is a single `dark` property flip: every color binding
// re-evaluates via the pick() helper, and QML's reactive system propagates
// the change to all consumers automatically. The `dark` preference is persisted
// via Qt Settings so it survives application restarts.
//
// Color philosophy:
//   Dark mode  = deep navy-black base with blue/purple accents
//   Light mode = bright cool-white base with cobalt/teal accents
// Semi-transparent fills (alpha < 1) let the background blobs bleed through
// for a layered glass-like depth effect.

QtObject {
    id: root

    // HiDPI text scaling. On screens wider than 1920 physical pixels, text
    // scales up proportionally with a 0.45 dampening factor to stay readable
    // without becoming oversized. Clamped to [1.0, 1.5].
    function detectTextScale() {
        var screens = (Qt.application && Qt.application.screens) ? Qt.application.screens : [];
        if (!screens || screens.length === 0)
            return 1.0;

        var primary = screens[0];
        var dpr = primary.devicePixelRatio > 0 ? primary.devicePixelRatio : 1.0;
        var physicalWidth = primary.width * dpr;
        if (physicalWidth <= 1920.0)
            return 1.0;

        var rawScale = physicalWidth / 1920.0;
        var textScale = 1.0 + (rawScale - 1.0) * 0.45;
        return Math.max(1.0, Math.min(textScale, 1.5));
    }

    readonly property real textScale: detectTextScale()

    // Bundled Inter font. GUID filename is from the vendor's licensing distribution.
    readonly property FontLoader _interFont: FontLoader {
        source: "qrc:/qt/qml/seal/assets/fonts/b0a4eabe-5fe5-41e3-8dc3-2df2b82ec4eb.ttf"
    }

    // Round to nearest pixel after scaling; min 1 to avoid zero-size elements.
    function px(base) {
        return Math.max(1, Math.round(base * textScale));
    }

    // Current theme mode. Bound via Settings alias so it persists to the
    // platform's native storage (registry on Windows, plist on macOS).
    // toggle() is called from the sun/moon icon in HeaderBar.
    property bool dark: true
    function toggle() { dark = !dark }

    // Palette selector: returns the dark-mode or light-mode value based on
    // the current theme. Every color property below uses pick(darkVal, lightVal)
    // instead of an inline ternary, keeping definitions concise and scannable.
    // QML's binding system tracks the `dark` dependency inside the function,
    // so all consumers re-evaluate automatically when the theme toggles.
    function pick(d, l) { return dark ? d : l }

    // Persisted accounts-grid sort preference. Maps to VaultListModel::SortMode
    // (0 = A-Z, 1 = Z-A, 2 = Grouped by brand). Stored alongside `dark` so all
    // UI prefs share the same Settings group.
    property int sortMode: 0

    property Settings _settings: Settings {
        property alias dark: root.dark
        property alias sortMode: root.sortMode
    }

    // -- Background layers --
    // Semi-transparent bgCard lets background blobs bleed through for depth.
    property color bgDeep:            pick("#060a14", "#f4f7fb")
    property color bgSurface:         pick("#0a101c", "#eaf0f7")
    property color bgCard:            pick(Qt.rgba(0.03, 0.06, 0.12, 0.78), Qt.rgba(0.975, 0.985, 1.0, 0.95))
    property color bgCardEnd:         pick(Qt.rgba(0.02, 0.05, 0.11, 0.86), Qt.rgba(0.95, 0.965, 0.985, 0.98))
    // The accounts-grid card sits directly over the animated background blobs,
    // so it runs noticeably more transparent than bgCard/bgCardEnd (which back
    // the search field and the empty-state panels). The lower alpha lets the
    // floating blobs read through beneath the chips as moving colour.
    property color bgGrid:            pick(Qt.rgba(0.03, 0.06, 0.12, 0.50), Qt.rgba(0.975, 0.985, 1.0, 0.40))
    property color bgGridEnd:         pick(Qt.rgba(0.02, 0.05, 0.11, 0.60), Qt.rgba(0.95, 0.965, 0.985, 0.50))
    property color bgDialog:          pick("#101828", "#fafbfd")
    property color bgInput:           pick(Qt.rgba(0.02, 0.05, 0.11, 0.92), Qt.rgba(0.985, 0.99, 1.0, 0.98))
    property color bgInputFocus:      pick(Qt.rgba(0.04, 0.07, 0.15, 0.96), Qt.rgba(1.0, 1.0, 1.0, 0.99))
    property color bgOverlay:         pick(Qt.rgba(0.01, 0.02, 0.05, 0.58), Qt.rgba(0.10, 0.14, 0.22, 0.38))
    property color bgHover:           pick(Qt.rgba(0.06, 0.10, 0.24, 0.50), Qt.rgba(0.22, 0.36, 0.56, 0.16))
    property color bgTableHeader:     pick(Qt.rgba(0.02, 0.04, 0.08, 0.65), Qt.rgba(0.96, 0.98, 0.99, 0.72))
    property color bgTableHeaderEdge: pick(Qt.rgba(0.04, 0.08, 0.20, 0.97), Qt.rgba(0.90, 0.94, 0.98, 0.98))
    property color bgTableHeaderTop:  pick(Qt.rgba(0.02, 0.05, 0.12, 0.97), Qt.rgba(0.945, 0.965, 0.992, 0.99))
    property color bgTableHeaderEnd:  pick(Qt.rgba(0.02, 0.04, 0.10, 0.98), Qt.rgba(0.91, 0.945, 0.985, 1.0))
    property color bgTooltip:         pick("#162040", "#28354a")
    property color bgBadge:           pick(Qt.rgba(0.08, 0.12, 0.26, 0.84), Qt.rgba(0.86, 0.90, 0.94, 0.90))

    property color bgHeaderTop:       pick(Qt.rgba(0.04, 0.08, 0.18, 0.96), Qt.rgba(0.96, 0.975, 0.995, 0.98))
    property color bgHeaderEnd:       pick(Qt.rgba(0.03, 0.06, 0.16, 0.98), Qt.rgba(0.88, 0.91, 0.96, 0.99))
    // Footer runs as transparent as the accounts-grid card (bgGrid/bgGridEnd)
    // so the floating background blobs stay visible through the bottom bar; the
    // faint top border (borderDim) still separates it from the content above.
    property color bgFooterTop:       pick(Qt.rgba(0.02, 0.05, 0.12, 0.50), Qt.rgba(0.90, 0.93, 0.97, 0.40))
    property color bgFooterEnd:       pick(Qt.rgba(0.02, 0.04, 0.10, 0.60), Qt.rgba(0.82, 0.86, 0.92, 0.50))
    property color surfaceHighlight:  pick(Qt.rgba(0.74, 0.84, 1.0, 0.16), Qt.rgba(1.0, 1.0, 1.0, 0.78))
    property color surfaceHighlightSoft:
                                      pick(Qt.rgba(0.54, 0.68, 1.0, 0.10), Qt.rgba(0.40, 0.62, 0.98, 0.18))
    property color surfaceGlow:       pick(Qt.rgba(0.22, 0.40, 0.98, 0.18), Qt.rgba(0.22, 0.46, 0.90, 0.14))
    property color surfaceGlowEdge:   pick(Qt.rgba(0.22, 0.40, 0.98, 0.0),  Qt.rgba(0.22, 0.46, 0.90, 0.0))
    property color focusSheen:        pick(Qt.rgba(0.88, 0.94, 1.0, 0.20), Qt.rgba(1.0, 1.0, 1.0, 0.48))
    property color dialogBand:        pick(Qt.rgba(0.22, 0.38, 0.90, 0.28), Qt.rgba(0.26, 0.48, 0.90, 0.16))
    property color dialogEdgeLight:   pick(Qt.rgba(0.80, 0.88, 1.0, 0.18), Qt.rgba(1.0, 1.0, 1.0, 0.50))
    property color statusChipTop:     pick(Qt.rgba(0.06, 0.10, 0.22, 0.84), Qt.rgba(0.93, 0.96, 0.99, 0.90))
    property color statusChipEnd:     pick(Qt.rgba(0.04, 0.08, 0.18, 0.90), Qt.rgba(0.88, 0.92, 0.97, 0.94))
    property color statusChipBorder:  pick(Qt.rgba(0.36, 0.50, 0.88, 0.24), Qt.rgba(0.34, 0.48, 0.72, 0.24))
    property color statusChipText:    pick("#b6c6e6", "#2a3a56")
    // "On" state of the bridge status chip. Cool soft blue in both themes —
    // distinct from every color already used in the button row above (Add
    // teal-green, Edit purple, Delete red, Fill yellow-green) and a calming
    // pairing with the green status dot. The "off" state uses the regular
    // statusChip tokens (neutral muted gray-blue).
    property color statusChipStrongTop:
                                      pick(Qt.rgba(0.10, 0.18, 0.34, 0.88), Qt.rgba(0.84, 0.90, 0.97, 0.94))
    property color statusChipStrongEnd:
                                      pick(Qt.rgba(0.08, 0.14, 0.30, 0.92), Qt.rgba(0.78, 0.86, 0.95, 0.96))
    property color statusChipStrongBorder:
                                      pick(Qt.rgba(0.36, 0.52, 0.92, 0.40), Qt.rgba(0.30, 0.48, 0.78, 0.30))
    property color statusChipStrongText:
                                      pick("#b8d0ff", "#1c3b78")

    // -- Button palettes --
    // Each button type carries four gradient states: rest, hover, pressed, disabled.
    // Alpha < 1 on all fills lets the background tint show through, maintaining the
    // layered glass aesthetic. Icon buttons (Load/Save/Unload) share a single neutral
    // palette; CRUD buttons each have a unique semantic hue.
    property color iconBtnTop:        pick(Qt.rgba(0.04, 0.08, 0.20, 0.82), Qt.rgba(0.91, 0.94, 0.97, 0.90))
    property color iconBtnEnd:        pick(Qt.rgba(0.03, 0.06, 0.16, 0.86), Qt.rgba(0.87, 0.91, 0.96, 0.94))
    property color iconBtnHoverTop:   pick(Qt.rgba(0.08, 0.14, 0.32, 0.90), Qt.rgba(0.86, 0.91, 0.96, 0.94))
    property color iconBtnHoverEnd:   pick(Qt.rgba(0.06, 0.11, 0.26, 0.92), Qt.rgba(0.82, 0.88, 0.95, 0.96))
    property color iconBtnPressed:    pick(Qt.rgba(0.03, 0.05, 0.14, 0.96), Qt.rgba(0.78, 0.85, 0.94, 0.98))

    // Ghost buttons (Cancel, No): low-alpha fills so they recede behind primary actions.
    property color ghostBtnTop:       pick(Qt.rgba(0.04, 0.08, 0.20, 0.62), Qt.rgba(0.92, 0.95, 0.98, 0.78))
    property color ghostBtnEnd:       pick(Qt.rgba(0.03, 0.06, 0.16, 0.72), Qt.rgba(0.88, 0.92, 0.96, 0.84))
    property color ghostBtnHoverTop:  pick(Qt.rgba(0.12, 0.18, 0.40, 0.48), Qt.rgba(0.84, 0.89, 0.95, 0.92))
    property color ghostBtnHoverEnd:  pick(Qt.rgba(0.08, 0.14, 0.34, 0.52), Qt.rgba(0.80, 0.86, 0.93, 0.94))
    property color ghostBtnPressed:   pick(Qt.rgba(0.14, 0.18, 0.52, 0.24), Qt.rgba(0.68, 0.76, 0.86, 0.90))

    // CRUD buttons: green=add, purple=edit, red=delete, yellow-green=fill.
    property color btnAddTop:         pick(Qt.rgba(0.08, 0.18, 0.20, 0.65), Qt.rgba(0.73, 0.90, 0.83, 0.86))
    property color btnAddEnd:         pick(Qt.rgba(0.06, 0.15, 0.17, 0.72), Qt.rgba(0.67, 0.86, 0.77, 0.90))
    property color btnAddHoverTop:    pick(Qt.rgba(0.10, 0.25, 0.28, 0.70), Qt.rgba(0.61, 0.84, 0.73, 0.92))
    property color btnAddHoverEnd:    pick(Qt.rgba(0.08, 0.22, 0.25, 0.76), Qt.rgba(0.55, 0.80, 0.67, 0.94))
    property color btnAddPressed:     pick(Qt.rgba(0.05, 0.14, 0.16, 0.35), Qt.rgba(0.42, 0.68, 0.56, 0.56))
    property color btnAddText:        pick("#50c0b0", "#0f5d43")
    property color btnAddTextHover:   pick("#68d8c8", "#0a4a34")

    property color btnEditTop:        pick(Qt.rgba(0.20, 0.10, 0.22, 0.65), Qt.rgba(0.89, 0.80, 0.95, 0.86))
    property color btnEditEnd:        pick(Qt.rgba(0.17, 0.08, 0.19, 0.72), Qt.rgba(0.84, 0.72, 0.92, 0.90))
    property color btnEditHoverTop:   pick(Qt.rgba(0.28, 0.14, 0.32, 0.70), Qt.rgba(0.82, 0.66, 0.90, 0.92))
    property color btnEditHoverEnd:   pick(Qt.rgba(0.24, 0.12, 0.28, 0.76), Qt.rgba(0.77, 0.60, 0.87, 0.94))
    property color btnEditPressed:    pick(Qt.rgba(0.16, 0.08, 0.18, 0.35), Qt.rgba(0.62, 0.44, 0.70, 0.56))
    property color btnEditText:       pick("#c080c8", "#5d3a85")
    property color btnEditTextHover:  pick("#d098d8", "#4d2f73")

    property color btnDeleteTop:      pick(Qt.rgba(0.22, 0.10, 0.14, 0.65), Qt.rgba(0.95, 0.82, 0.84, 0.86))
    property color btnDeleteEnd:      pick(Qt.rgba(0.18, 0.08, 0.12, 0.72), Qt.rgba(0.91, 0.76, 0.78, 0.90))
    property color btnDeleteHoverTop: pick(Qt.rgba(0.32, 0.14, 0.20, 0.70), Qt.rgba(0.90, 0.70, 0.73, 0.92))
    property color btnDeleteHoverEnd: pick(Qt.rgba(0.28, 0.12, 0.17, 0.76), Qt.rgba(0.86, 0.64, 0.67, 0.94))
    property color btnDeletePressed:  pick(Qt.rgba(0.18, 0.08, 0.10, 0.35), Qt.rgba(0.71, 0.48, 0.52, 0.56))
    property color btnDeleteText:     pick("#c87080", "#8f3340")
    property color btnDeleteTextHover:pick("#d88898", "#782834")

    property color btnFillTop:        pick(Qt.rgba(0.14, 0.18, 0.06, 0.65), Qt.rgba(0.87, 0.92, 0.74, 0.86))
    property color btnFillEnd:        pick(Qt.rgba(0.12, 0.15, 0.05, 0.72), Qt.rgba(0.82, 0.88, 0.67, 0.90))
    property color btnFillHoverTop:   pick(Qt.rgba(0.20, 0.26, 0.08, 0.70), Qt.rgba(0.79, 0.87, 0.60, 0.92))
    property color btnFillHoverEnd:   pick(Qt.rgba(0.17, 0.22, 0.07, 0.76), Qt.rgba(0.74, 0.83, 0.54, 0.94))
    property color btnFillPressed:    pick(Qt.rgba(0.10, 0.14, 0.04, 0.35), Qt.rgba(0.58, 0.68, 0.40, 0.56))
    property color btnFillText:       pick("#a0b850", "#54681a")
    property color btnFillTextHover:  pick("#b0c860", "#44570e")
    property color windowCloseHover:   "#8f352c"
    property color windowClosePressed: "#742a22"

    property color btnDisabledTop:    pick("#101828", "#dbe2ec")
    property color btnDisabledBot:    pick("#0e1424", "#d5dce8")

    property color accent:            pick("#80b0ff", "#2f6fd6")
    property color accentBright:      pick("#6090ff", "#4386f2")
    property color accentDim:         pick("#5a6ea8", "#5477b2")
    property color accentSoft:        pick(Qt.rgba(0.35, 0.50, 1.0, 0.14), Qt.rgba(0.18, 0.44, 0.86, 0.12))
    property color accentMuted:       pick("#384c78", "#647fa8")
    property color btnGradTop:        pick("#4a7ef0", "#3579e6")
    property color btnGradBot:        pick("#3664d8", "#295fca")
    property color btnHoverTop:       pick("#6090ff", "#4a8ff5")
    property color btnHoverBot:       pick("#4a7ef0", "#3579e6")
    property color btnPressTop:       pick("#2e52b8", "#214fb0")
    property color btnPressBot:       pick("#2646a0", "#1b4396")

    property color accent2:           pick("#50d0cc", "#2e8b86")
    property color accent2Dim:        pick("#4a8a88", "#3e8a85")

    // Tertiary accent (rose in dark, violet in light) completing the
    // three-color system used across table columns and dialog labels.
    property color accent3:           pick("#d89090", "#8868a0")
    property color accent3Dim:        pick("#907070", "#6b4f8a")

    // Fill-armed: same yellow-green hue as Fill, boosted saturation & alpha.
    property color fillArmedTop:      pick(Qt.rgba(0.22, 0.30, 0.08, 0.88), Qt.rgba(0.72, 0.84, 0.52, 0.92))
    property color fillArmedEnd:      pick(Qt.rgba(0.18, 0.26, 0.06, 0.92), Qt.rgba(0.68, 0.80, 0.46, 0.94))
    property color fillArmedHoverTop: pick(Qt.rgba(0.28, 0.38, 0.10, 0.92), Qt.rgba(0.64, 0.78, 0.42, 0.94))
    property color fillArmedHoverEnd: pick(Qt.rgba(0.24, 0.34, 0.08, 0.95), Qt.rgba(0.60, 0.74, 0.36, 0.96))
    property color fillArmedPressTop: pick(Qt.rgba(0.14, 0.18, 0.04, 0.50), Qt.rgba(0.50, 0.62, 0.32, 0.55))
    property color fillArmedPressEnd: pick(Qt.rgba(0.12, 0.16, 0.04, 0.55), Qt.rgba(0.46, 0.58, 0.28, 0.58))
    property color fillArmedDot:      pick("#c0d848", "#5a7a20")
    property color borderFillArmed:   pick(Qt.rgba(0.55, 0.72, 0.18, 0.45), Qt.rgba(0.38, 0.52, 0.12, 0.45))

    // -- Text colors --
    // Graduated hierarchy: primary > secondary > muted > disabled > subtle.
    // Dark mode uses saturated navy-black; light mode uses cool blue-white.
    // Grey tones are avoided in favor of hue-carrying values throughout.
    property color textPrimary:       pick("#e6ecf6", "#141c28")
    property color textSecondary:     pick("#b4c0d6", "#2f4158")
    property color textMuted:         pick("#5c70a8", "#4e637d")
    property color textDisabled:      pick("#3e4e80", "#7d8da2")
    property color textSubtle:        pick("#6c80b8", "#425873")
    property color textIcon:          pick("#7c90c0", "#334861")
    property color textGhost:         pick("#acbad6", "#223550")
    property color textOnAccent:      "#ffffff"
    property color textPlaceholder:   pick("#3e4e80", "#8192a7")
    property color textError:         pick("#ff6868", "#c83030")
    property color textSuccess:       pick("#48d878", "#187838")
    property color textWarning:       pick("#ffc040", "#c88008")
    property color textLink:          pick("#50d0cc", "#1f6a78")
    property color textTooltip:       pick("#c6cee6", "#e0e8f2")
    property color textBadge:         pick("#94a8d0", "#364860")

    // -- Borders --
    // Graduated alpha scale from borderDim (nearly invisible) to borderBright
    // (clearly visible). All share the same base hue per theme so borders look
    // cohesive regardless of intensity. Components pick the level that matches
    // their visual weight (e.g. cards use borderSubtle, focused inputs use borderFocus).
    property color borderDim:         pick(Qt.rgba(0.35, 0.45, 0.85, 0.08), Qt.rgba(0.24, 0.36, 0.56, 0.11))
    property color borderSoft:        pick(Qt.rgba(0.35, 0.45, 0.85, 0.12), Qt.rgba(0.24, 0.36, 0.56, 0.16))
    property color borderSubtle:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.15), Qt.rgba(0.24, 0.36, 0.56, 0.22))
    property color borderInput:       pick(Qt.rgba(0.30, 0.42, 0.80, 0.20), Qt.rgba(0.22, 0.34, 0.54, 0.28))
    property color borderMedium:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.22), Qt.rgba(0.24, 0.36, 0.56, 0.30))
    property color borderBtn:         pick(Qt.rgba(0.35, 0.45, 0.85, 0.24), Qt.rgba(0.24, 0.36, 0.56, 0.32))
    property color borderHover:       pick(Qt.rgba(0.35, 0.45, 0.85, 0.28), Qt.rgba(0.24, 0.36, 0.56, 0.40))
    property color borderHighlight:   pick(Qt.rgba(0.35, 0.45, 0.85, 0.32), Qt.rgba(0.24, 0.36, 0.56, 0.44))
    property color borderBright:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.42), Qt.rgba(0.22, 0.34, 0.54, 0.54))
    property color borderPressed:     pick(Qt.rgba(0.30, 0.35, 0.80, 0.35), Qt.rgba(0.22, 0.36, 0.56, 0.36))
    property color borderFocusHover:  pick(Qt.rgba(0.30, 0.35, 0.80, 0.45), Qt.rgba(0.22, 0.36, 0.56, 0.48))
    property color borderFocus:       pick(Qt.rgba(0.30, 0.35, 0.80, 0.72), Qt.rgba(0.22, 0.36, 0.56, 0.68))
    property color divider:           pick(Qt.rgba(0.35, 0.45, 0.85, 0.10), Qt.rgba(0.24, 0.36, 0.56, 0.16))

    property color rowAlt:            pick(Qt.rgba(0.04, 0.08, 0.20, 0.32), Qt.rgba(0.22, 0.34, 0.54, 0.14))
    property color rowSpotlight:      pick(Qt.rgba(0.62, 0.78, 1.0, 0.12), Qt.rgba(1.0, 1.0, 1.0, 0.20))
    property color rowSpotlightEdge:  pick(Qt.rgba(0.62, 0.78, 1.0, 0.0),  Qt.rgba(1.0, 1.0, 1.0, 0.0))
    property color rowHoverRail:      pick(Qt.rgba(0.44, 0.62, 1.0, 0.24), Qt.rgba(0.28, 0.52, 0.94, 0.22))

    property color selectionBg:       pick(Qt.rgba(0.32, 0.24, 0.88, 0.28), Qt.rgba(0.23, 0.44, 0.88, 0.16))
    property color selectionHover:    pick(Qt.rgba(0.35, 0.28, 0.92, 0.12), Qt.rgba(0.23, 0.44, 0.88, 0.11))
    property color selectionActive:   pick(Qt.rgba(0.32, 0.24, 0.88, 0.36), Qt.rgba(0.23, 0.44, 0.88, 0.26))

    property color scrollThumb:       pick(Qt.rgba(0.18, 0.28, 0.58, 0.48), Qt.rgba(0.24, 0.36, 0.56, 0.48))
    property color scrollThumbHover:  pick(Qt.rgba(0.22, 0.34, 0.65, 0.62), Qt.rgba(0.22, 0.34, 0.54, 0.64))

    property color rippleColor:       pick(Qt.rgba(1.0, 1.0, 1.0, 0.25), Qt.rgba(0.0, 0.0, 0.0, 0.18))

    // Background blobs: three distinct hues bleeding through the semi-transparent
    // surfaces for layered depth. Each hue contrasts with the others (purple /
    // teal / magenta in dark; cobalt / teal / lilac in light). Light runs a
    // HIGHER alpha than dark: a colour glowing over the near-black dark base
    // reads at far lower alpha than the same colour tinting the near-white light
    // base, so to keep the blobs equally visible in both themes light needs the
    // stronger fill. Surfaces (bgGrid/footer) sit at matched transparency in both
    // themes so the field reads through identically.
    property color blobColor1:        pick(Qt.rgba(0.32, 0.22, 0.88, 0.084), Qt.rgba(0.20, 0.47, 0.90, 0.22))
    property color blobColor2:        pick(Qt.rgba(0.08, 0.58, 0.68, 0.078), Qt.rgba(0.12, 0.56, 0.54, 0.20))
    property color blobColor3:        pick(Qt.rgba(0.65, 0.12, 0.55, 0.070), Qt.rgba(0.54, 0.34, 0.82, 0.18))

    // Drifting motes (see Main.qml): tiny plankton/snow specks. Kept fainter
    // than the blobs so they stay a peripheral texture, not bright dots. (The
    // Mote's own twinkle multiplies this, so the effective alpha peaks ~0.09.)
    property color moteColor:    pick(Qt.rgba(0.82, 0.90, 1.0, 0.12), Qt.rgba(0.22, 0.45, 0.88, 0.20))

    // Dialog background blobs: higher alpha than main-window blobs because
    // dialogs paint on a solid bgDialog fill (not semi-transparent) and sit
    // under a modal overlay, so colors read on top rather than bleeding
    // through. Same three hues / order as blobColor1-3 for family cohesion.
    property color dialogBlobColor1:  pick(Qt.rgba(0.32, 0.22, 0.88, 0.14), Qt.rgba(0.20, 0.47, 0.90, 0.11))
    property color dialogBlobColor2:  pick(Qt.rgba(0.08, 0.58, 0.68, 0.13), Qt.rgba(0.12, 0.56, 0.54, 0.10))
    property color dialogBlobColor3:  pick(Qt.rgba(0.65, 0.12, 0.55, 0.12), Qt.rgba(0.54, 0.34, 0.82, 0.09))

    // Selection glow: fades from selectionGlow to transparent at row edges.
    property color selectionGlow:     pick(Qt.rgba(0.38, 0.28, 0.92, 0.40), Qt.rgba(0.24, 0.46, 0.88, 0.30))
    property color selectionGlowEdge: pick(Qt.rgba(0.38, 0.28, 0.92, 0.0),  Qt.rgba(0.24, 0.46, 0.88, 0.0))
    property color selectionStripe:   pick(Qt.rgba(0.52, 0.42, 1.0, 0.62),  Qt.rgba(0.28, 0.52, 0.94, 0.48))

    property color shadow:            pick(Qt.rgba(0, 0, 0, 0.48), Qt.rgba(0.10, 0.16, 0.28, 0.26))

    // -- Animation timing --
    readonly property int hoverDuration:  150
    readonly property int pressDuration:  80

    readonly property int radiusSmall:  10
    readonly property int radiusMedium: 12
    readonly property int radiusLarge:  14

    readonly property int spacingSmall:  10
    readonly property int spacingMedium: 14
    readonly property int spacingLarge:  20
    readonly property int spacingXL:     36

    // Consolas ships with every Windows install.
    readonly property string fontFamily:     _interFont.name !== "" ? _interFont.name : "Inter"
    readonly property string fontMono:       "Consolas"
    readonly property string fontEmoji:      "Segoe UI Emoji"
    readonly property int fontSizeSmall:     px(10)
    readonly property int fontSizeMedium:    px(11)
    readonly property int fontSizeLarge:     px(12)
    readonly property int fontSizeTitle:     px(26)
    readonly property int fontSizeSubtitle:  px(11)
    readonly property int iconSizeSmall:     px(13)
    readonly property int iconSizeMedium:    px(15)

    // Chip background palette for the accounts grid. Used as the fallback when
    // a chip has no recognized brand icon (no entry in brandColors). 8 hues
    // chosen to read well at α=0.12 (idle fill), α=0.22 (hover), and α=1.0
    // (monogram circle / selected). The array re-evaluates on dark/light
    // toggle because pick() is invoked at binding time; each entry is
    // independent.
    readonly property var chipPalette: [
        pick("#80b0ff", "#2f6fd6"),  // blue
        pick("#50d0cc", "#2e8b86"),  // teal
        pick("#d89090", "#8868a0"),  // rose / violet (mirrors accent3 family)
        pick("#d8a060", "#a86820"),  // amber
        pick("#80c0c0", "#1f6a78"),  // cyan
        pick("#a0c860", "#4a6818"),  // lime
        pick("#e08070", "#aa3030"),  // coral
        pick("#a090d8", "#5040a0"),  // indigo
    ]

    // Real brand colors keyed by the asset slug BrandIconResolver returns
    // (the filename under assets/brands/ without the .svg suffix). Used so
    // recognizable services (GitHub, Bitcoin, Discord, ...) read with their
    // actual identity rather than a hash-mapped accent. Slugs not listed
    // here fall back to chipPalette via the FNV-1a hash. Pure black/white
    // brand colors are nudged toward a brand-adjacent hue that survives both
    // dark and light themes (e.g. X uses Twitter cyan instead of #000000).
    readonly property var brandColors: ({
        "github":              "#6e7681",
        "square-github":       "#6e7681",
        "x-twitter":           "#1d9bf0",
        "square-x-twitter":    "#1d9bf0",
        "signal-messenger":    "#3a76f0",
        "dropbox":             "#0061ff",
        "bitcoin":             "#f7931a",
        "discord":             "#5865f2",
        "facebook-messenger":  "#00b2ff",
        "wordpress":           "#21759b",
        "wordpress-simple":    "#21759b",
        "telegram":            "#0088cc",
        "tiktok":              "#69c9d0",
        "snapchat":            "#ffeb3b",
        "whatsapp-square":     "#25d366",
        "playstation":         "#003791",
        "steam":               "#66c0f4",
        "steam-symbol":        "#66c0f4",
        "google-drive":        "#4285f4",
        "google-pay":          "#4285f4",
        "google-play":         "#4285f4",
        "google-plus":         "#dd4b39",
        "amazon-pay":          "#ff9900",
        "linux":               "#fcc624",
        "windows":             "#0078d7",
        "android":             "#3ddc84",
        "edge":                "#0078d7",
        "edge-legacy":         "#0078d7",
        "firefox":             "#ff7139",
        "firefox-browser":     "#ff7139",
        "safari":              "#006cff",
        "tor-browser":         "#7d4698",
        "etsy":                "#f56400",
        "shopify":             "#7ab55c",
        "stack-exchange":      "#1e5397",
        "reddit-square":       "#ff4500",
        "square-reddit":       "#ff4500",
        "vimeo":               "#1ab7ea",
        "soundcloud":          "#ff7700",
        "linkedin":            "#0a66c2",
        "linkedin-in":         "#0a66c2",
        "square-linkedin":     "#0a66c2",
        "behance":             "#053eff",
        "behance-square":      "#053eff",
        "mastodon":            "#6364ff",
        "bluesky":             "#0085ff",
        "square-bluesky":      "#0085ff",
        "threads":             "#888888",
        "dribbble":            "#ea4c89",
        "square-dribbble":     "#ea4c89",
        "gitlab":              "#fc6d26",
        "kickstarter":         "#05ce78",
        "kickstarter-k":       "#05ce78",
        "lastfm":              "#d51007",
        "square-lastfm":       "#d51007",
        "y-combinator":        "#ff6600",
        "hacker-news-square":  "#ff6600",
        "blogger":             "#ff5722",
        "medium":              "#1a8917",
        "evernote":            "#00a82d",
        "duolingo":            "#58cc02",
        "yahoo":               "#5f01d1",
        "tumblr":              "#36465d",
        "tumblr-square":       "#36465d",
        "slack-hash":          "#4a154b",
        "battle-net":          "#00aeff",
        "buffer":              "#168eea",
        "chromecast":          "#ea4335",
        "figma":               "#f24e1e",
        "flickr":              "#0063dc",
        "guilded":             "#f5c400",
        "houzz":               "#7ac142",
        "kaggle":              "#20beff",
        "keybase":             "#4c8eff",
        "line":                "#00c300",
        "linode":              "#00a95c",
        "lyft":                "#ff00bf",
        "mailchimp":           "#ffe01b",
        "mix":                 "#ff8126",
        "octopus-deploy":      "#00b3a1",
        "openid":              "#ff721f",
        "opensuse":            "#73ba25",
        "paypal":              "#0070ba",
        "cc-paypal":           "#0070ba",
        "cc-visa":             "#1a1f71",
        "cc-mastercard":       "#eb001b",
        "cc-diners-club":      "#0079be",
        "cc-discover":         "#ff6000",
        "pinterest-square":    "#e60023",
        "pixiv":               "#0096fa",
        "postgresql":          "#336791",
        "qq":                  "#eb1923",
        "quora":               "#b92b27",
        "readme":              "#018ef5",
        "rust":                "#ce422b",
        "salesforce":          "#00a1e0",
        "shopware":            "#189eff",
        "speaker-deck":        "#009287",
        "tailwind-css":        "#06b6d4",
        "untappd":             "#ffc000",
        "vim":                 "#019733",
        "vk":                  "#4a76a8",
        "webflow":             "#4353ff",
        "weebly":              "#ff7300",
        "weixin":              "#07c160",
        "bootstrap":           "#7952b3",
        "css3-alt":            "#1572b6",
        "debian":              "#a81d33",
        "suse":                "#0c322c",
        "zhihu":               "#0066ff",
        "artstation":          "#13aff0",
        "audible":             "#f8991c",
        "500px":               "#0099e5",
        "scribd":              "#1e7b85",
        "sourcetree":          "#0052cc",
        "hotjar":              "#fd3a5c",
        "invision":            "#ff3366",
        "itch-io":             "#fa5c5c",
        "mendeley":            "#9d1620",
        "padlet":              "#ed3835",
        "phabricator":         "#4a5f88",
        "slideshare":          "#0077b5",
        "wpbeginner":          "#ed5a45",
    })

    // Strip the qrc prefix/.svg suffix off a brandIconPath to recover the
    // bare asset slug for use as a brandColors key. Returns "" if path is
    // empty or doesn't match the expected layout.
    function brandSlugFromPath(path)
    {
        if (!path) return "";
        var prefix = "qrc:/qt/qml/seal/assets/brands/";
        var suffix = ".svg";
        if (path.indexOf(prefix) !== 0) return "";
        if (path.lastIndexOf(suffix) !== path.length - suffix.length) return "";
        return path.substring(prefix.length, path.length - suffix.length);
    }

    // Chip color resolver. If we recognize the brand (icon resolved AND the
    // slug has a curated brand color), use the brand identity. Otherwise hash
    // the platform name into a chipPalette slot so unbranded chips still get
    // a deterministic-but-arbitrary hue.
    function chipColorFor(name, brandSlug)
    {
        if (brandSlug && brandSlug.length > 0) {
            var bc = brandColors[brandSlug];
            if (bc) return bc;
        }
        if (!name) return chipPalette[0];
        var h = 2166136261 >>> 0;
        for (var i = 0; i < name.length; i++) {
            h ^= name.charCodeAt(i);
            h = Math.imul(h, 16777619) >>> 0;
        }
        return chipPalette[h % chipPalette.length];
    }

    // Return a readable foreground color (white or near-black) for text /
    // glyphs that sit on top of `color` at full alpha — used on the selected
    // chip background and on the monogram-circle letter so bright brand hues
    // (Snapchat yellow, Linux yellow, ...) don't end up with white-on-white.
    function chipTextOn(color)
    {
        var lum = 0.299 * color.r + 0.587 * color.g + 0.114 * color.b;
        return lum > 0.55 ? "#15171d" : "#ffffff";
    }

    // SVG icon paths. SvgIcon.qml wraps IconImage for runtime recoloring.
    // The new duotone/ asset set uses FA's "alt" suffix convention (lock-alt,
    // pen-alt, trash-alt, ...) rather than bare names, and substitutes some
    // icons entirely. Mappings below choose the closest-meaning available
    // filename — see git history for the previous svgs/ paths.
    readonly property string iconLock:         "qrc:/qt/qml/seal/assets/duotone/lock-alt.svg"
    readonly property string iconLockOpen:     "qrc:/qt/qml/seal/assets/duotone/lock-keyhole-open.svg"
    readonly property string iconPlus:         "qrc:/qt/qml/seal/assets/duotone/plus.svg"
    readonly property string iconPen:          "qrc:/qt/qml/seal/assets/duotone/pen-alt.svg"
    readonly property string iconTrash:        "qrc:/qt/qml/seal/assets/duotone/recycle.svg"
    readonly property string iconFloppyDisk:   "qrc:/qt/qml/seal/assets/duotone/floppy-disk.svg"
    readonly property string iconFolderOpen:   "qrc:/qt/qml/seal/assets/duotone/folder-open.svg"
    readonly property string iconEject:        "qrc:/qt/qml/seal/assets/duotone/right-from-bracket.svg"
    readonly property string iconKeyboard:     "qrc:/qt/qml/seal/assets/duotone/keyboard.svg"
    readonly property string iconKey:          "qrc:/qt/qml/seal/assets/duotone/key-skeleton-left-right.svg"
    readonly property string iconSearch:       "qrc:/qt/qml/seal/assets/duotone/magnifying-glass-plus.svg"
    readonly property string iconShieldHalved: "qrc:/qt/qml/seal/assets/duotone/shield.svg"
    readonly property string iconService:      "qrc:/qt/qml/seal/assets/duotone/database.svg"
    readonly property string iconUsername:     "qrc:/qt/qml/seal/assets/duotone/user-circle.svg"
    readonly property string iconPassword:     "qrc:/qt/qml/seal/assets/duotone/lock-alt.svg"
    readonly property string iconCamera:       "qrc:/qt/qml/seal/assets/duotone/camera-alt.svg"
    readonly property string iconQrCode:       "qrc:/qt/qml/seal/assets/duotone/qrcode.svg"
    readonly property string iconFilterSlash:  "qrc:/qt/qml/seal/assets/duotone/filter-slash.svg"
    readonly property string iconNarwhal:      "qrc:/qt/qml/seal/assets/duotone/narwhal.svg"
    readonly property string iconEye:          "qrc:/qt/qml/seal/assets/duotone/eye.svg"
    readonly property string iconEyeSlash:     "qrc:/qt/qml/seal/assets/duotone/eye-closed.svg"
    readonly property string iconCrosshairs:   "qrc:/qt/qml/seal/assets/duotone/crosshairs-simple.svg"
    readonly property string iconSun:          "qrc:/qt/qml/seal/assets/duotone/sun-bright.svg"
    readonly property string iconXmark:        "qrc:/qt/qml/seal/assets/duotone/xmark.svg"
    readonly property string iconBan:          "qrc:/qt/qml/seal/assets/duotone/ban.svg"
    readonly property string iconMoon:         "qrc:/qt/qml/seal/assets/duotone/moon.svg"
    readonly property string iconChevronDown:  "qrc:/qt/qml/seal/assets/duotone/angle-down.svg"
    readonly property string iconPowerOff:    "qrc:/qt/qml/seal/assets/duotone/power-off.svg"
    readonly property string iconThumbtack:   "qrc:/qt/qml/seal/assets/duotone/thumbtack-angle.svg"
    readonly property string iconCompress:    "qrc:/qt/qml/seal/assets/duotone/compress.svg"
    readonly property string iconExpand:      "qrc:/qt/qml/seal/assets/duotone/arrows-maximize.svg"
    readonly property string iconTriangleExclamation: "qrc:/qt/qml/seal/assets/duotone/exclamation-triangle.svg"
    readonly property string iconCircleInfo:  "qrc:/qt/qml/seal/assets/duotone/info-square.svg"
    readonly property string iconCircleCheck: "qrc:/qt/qml/seal/assets/duotone/check-circle.svg"
    readonly property string iconTerminal:   "qrc:/qt/qml/seal/assets/duotone/terminal.svg"
}
