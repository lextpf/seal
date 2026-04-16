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

    property Settings _settings: Settings {
        property alias dark: root.dark
    }

    // -- Background layers --
    // Semi-transparent bgCard lets background blobs bleed through for depth.
    property color bgDeep:            pick("#060a14", "#f8fafc")
    property color bgSurface:         pick("#0a101c", "#f0f5fa")
    property color bgCard:            pick(Qt.rgba(0.03, 0.06, 0.12, 0.78), Qt.rgba(0.96, 0.98, 0.99, 0.88))
    property color bgCardEnd:         pick(Qt.rgba(0.02, 0.05, 0.11, 0.86), Qt.rgba(0.93, 0.95, 0.97, 0.92))
    property color bgDialog:          pick("#101828", "#fafbfd")
    property color bgInput:           pick(Qt.rgba(0.02, 0.05, 0.11, 0.92), Qt.rgba(0.98, 0.99, 1.0, 0.92))
    property color bgInputFocus:      pick(Qt.rgba(0.04, 0.07, 0.15, 0.96), Qt.rgba(0.98, 0.99, 1.0, 0.96))
    property color bgOverlay:         pick(Qt.rgba(0.01, 0.02, 0.05, 0.58), Qt.rgba(0.10, 0.14, 0.22, 0.38))
    property color bgHover:           pick(Qt.rgba(0.06, 0.10, 0.24, 0.50), Qt.rgba(0.26, 0.36, 0.52, 0.08))
    property color bgTableHeader:     pick(Qt.rgba(0.02, 0.04, 0.08, 0.65), Qt.rgba(0.96, 0.98, 0.99, 0.72))
    property color bgTableHeaderEdge: pick(Qt.rgba(0.04, 0.08, 0.20, 0.97), Qt.rgba(0.92, 0.95, 0.98, 0.97))
    property color bgTableHeaderTop:  pick(Qt.rgba(0.02, 0.05, 0.12, 0.97), Qt.rgba(0.95, 0.97, 0.99, 0.97))
    property color bgTableHeaderEnd:  pick(Qt.rgba(0.02, 0.04, 0.10, 0.98), Qt.rgba(0.93, 0.95, 0.98, 0.98))
    property color bgTooltip:         pick("#162040", "#28354a")
    property color bgBadge:           pick(Qt.rgba(0.08, 0.12, 0.26, 0.84), Qt.rgba(0.88, 0.91, 0.95, 0.85))

    property color bgHeaderTop:       pick(Qt.rgba(0.04, 0.08, 0.18, 0.96), Qt.rgba(0.92, 0.95, 0.98, 0.96))
    property color bgHeaderEnd:       pick(Qt.rgba(0.03, 0.06, 0.16, 0.98), Qt.rgba(0.90, 0.93, 0.96, 0.98))
    property color bgFooterTop:       pick(Qt.rgba(0.02, 0.05, 0.12, 0.96), Qt.rgba(0.90, 0.93, 0.96, 0.96))
    property color bgFooterEnd:       pick(Qt.rgba(0.02, 0.04, 0.10, 1.0),  Qt.rgba(0.88, 0.91, 0.94, 1.0))
    property color surfaceHighlight:  pick(Qt.rgba(0.74, 0.84, 1.0, 0.16), Qt.rgba(1.0, 1.0, 1.0, 0.58))
    property color surfaceHighlightSoft:
                                      pick(Qt.rgba(0.54, 0.68, 1.0, 0.10), Qt.rgba(0.42, 0.62, 0.98, 0.16))
    property color surfaceGlow:       pick(Qt.rgba(0.22, 0.40, 0.98, 0.18), Qt.rgba(0.22, 0.46, 0.90, 0.10))
    property color surfaceGlowEdge:   pick(Qt.rgba(0.22, 0.40, 0.98, 0.0),  Qt.rgba(0.22, 0.46, 0.90, 0.0))
    property color focusSheen:        pick(Qt.rgba(0.88, 0.94, 1.0, 0.20), Qt.rgba(1.0, 1.0, 1.0, 0.40))
    property color dialogBand:        pick(Qt.rgba(0.22, 0.38, 0.90, 0.28), Qt.rgba(0.26, 0.48, 0.90, 0.16))
    property color dialogEdgeLight:   pick(Qt.rgba(0.80, 0.88, 1.0, 0.18), Qt.rgba(1.0, 1.0, 1.0, 0.50))
    property color statusChipTop:     pick(Qt.rgba(0.06, 0.10, 0.22, 0.84), Qt.rgba(0.93, 0.96, 0.99, 0.90))
    property color statusChipEnd:     pick(Qt.rgba(0.04, 0.08, 0.18, 0.90), Qt.rgba(0.88, 0.92, 0.97, 0.94))
    property color statusChipBorder:  pick(Qt.rgba(0.36, 0.50, 0.88, 0.24), Qt.rgba(0.34, 0.48, 0.72, 0.18))
    property color statusChipText:    pick("#b6c6e6", "#40506a")
    property color statusChipStrongTop:
                                      pick(Qt.rgba(0.20, 0.28, 0.08, 0.88), Qt.rgba(0.76, 0.86, 0.54, 0.92))
    property color statusChipStrongEnd:
                                      pick(Qt.rgba(0.16, 0.24, 0.06, 0.92), Qt.rgba(0.70, 0.80, 0.42, 0.95))
    property color statusChipStrongBorder:
                                      pick(Qt.rgba(0.58, 0.74, 0.18, 0.34), Qt.rgba(0.42, 0.56, 0.16, 0.28))
    property color statusChipStrongText:
                                      pick("#eef6c2", "#40540e")

    // -- Button palettes --
    // Each button type carries four gradient states: rest, hover, pressed, disabled.
    // Alpha < 1 on all fills lets the background tint show through, maintaining the
    // layered glass aesthetic. Icon buttons (Load/Save/Unload) share a single neutral
    // palette; CRUD buttons each have a unique semantic hue.
    property color iconBtnTop:        pick(Qt.rgba(0.04, 0.08, 0.20, 0.82), Qt.rgba(0.90, 0.93, 0.96, 0.82))
    property color iconBtnEnd:        pick(Qt.rgba(0.03, 0.06, 0.16, 0.86), Qt.rgba(0.86, 0.90, 0.94, 0.86))
    property color iconBtnHoverTop:   pick(Qt.rgba(0.08, 0.14, 0.32, 0.90), Qt.rgba(0.82, 0.86, 0.92, 0.90))
    property color iconBtnHoverEnd:   pick(Qt.rgba(0.06, 0.11, 0.26, 0.92), Qt.rgba(0.78, 0.84, 0.90, 0.92))
    property color iconBtnPressed:    pick(Qt.rgba(0.03, 0.05, 0.14, 0.96), Qt.rgba(0.74, 0.80, 0.86, 0.96))

    // Ghost buttons (Cancel, No): low-alpha fills so they recede behind primary actions.
    property color ghostBtnTop:       pick(Qt.rgba(0.04, 0.08, 0.20, 0.62), Qt.rgba(0.90, 0.93, 0.96, 0.62))
    property color ghostBtnEnd:       pick(Qt.rgba(0.03, 0.06, 0.16, 0.72), Qt.rgba(0.86, 0.90, 0.94, 0.72))
    property color ghostBtnHoverTop:  pick(Qt.rgba(0.12, 0.18, 0.40, 0.48), Qt.rgba(0.76, 0.82, 0.88, 0.48))
    property color ghostBtnHoverEnd:  pick(Qt.rgba(0.08, 0.14, 0.34, 0.52), Qt.rgba(0.72, 0.78, 0.86, 0.52))
    property color ghostBtnPressed:   pick(Qt.rgba(0.14, 0.18, 0.52, 0.24), Qt.rgba(0.44, 0.52, 0.62, 0.28))

    // CRUD buttons: green=add, purple=edit, red=delete, yellow-green=fill.
    property color btnAddTop:         pick(Qt.rgba(0.08, 0.18, 0.20, 0.65), Qt.rgba(0.78, 0.92, 0.86, 0.78))
    property color btnAddEnd:         pick(Qt.rgba(0.06, 0.15, 0.17, 0.72), Qt.rgba(0.72, 0.88, 0.80, 0.84))
    property color btnAddHoverTop:    pick(Qt.rgba(0.10, 0.25, 0.28, 0.70), Qt.rgba(0.65, 0.86, 0.76, 0.82))
    property color btnAddHoverEnd:    pick(Qt.rgba(0.08, 0.22, 0.25, 0.76), Qt.rgba(0.58, 0.82, 0.70, 0.86))
    property color btnAddPressed:     pick(Qt.rgba(0.05, 0.14, 0.16, 0.35), Qt.rgba(0.42, 0.68, 0.56, 0.40))
    property color btnAddText:        pick("#50c0b0", "#1a7050")
    property color btnAddTextHover:   pick("#68d8c8", "#0e5838")

    property color btnEditTop:        pick(Qt.rgba(0.20, 0.10, 0.22, 0.65), Qt.rgba(0.92, 0.80, 0.94, 0.78))
    property color btnEditEnd:        pick(Qt.rgba(0.17, 0.08, 0.19, 0.72), Qt.rgba(0.88, 0.74, 0.90, 0.84))
    property color btnEditHoverTop:   pick(Qt.rgba(0.28, 0.14, 0.32, 0.70), Qt.rgba(0.86, 0.68, 0.88, 0.82))
    property color btnEditHoverEnd:   pick(Qt.rgba(0.24, 0.12, 0.28, 0.76), Qt.rgba(0.82, 0.62, 0.84, 0.86))
    property color btnEditPressed:    pick(Qt.rgba(0.16, 0.08, 0.18, 0.35), Qt.rgba(0.64, 0.42, 0.66, 0.40))
    property color btnEditText:       pick("#c080c8", "#783878")
    property color btnEditTextHover:  pick("#d098d8", "#602868")

    property color btnDeleteTop:      pick(Qt.rgba(0.22, 0.10, 0.14, 0.65), Qt.rgba(0.94, 0.80, 0.82, 0.78))
    property color btnDeleteEnd:      pick(Qt.rgba(0.18, 0.08, 0.12, 0.72), Qt.rgba(0.90, 0.74, 0.76, 0.84))
    property color btnDeleteHoverTop: pick(Qt.rgba(0.32, 0.14, 0.20, 0.70), Qt.rgba(0.88, 0.66, 0.70, 0.82))
    property color btnDeleteHoverEnd: pick(Qt.rgba(0.28, 0.12, 0.17, 0.76), Qt.rgba(0.84, 0.60, 0.64, 0.86))
    property color btnDeletePressed:  pick(Qt.rgba(0.18, 0.08, 0.10, 0.35), Qt.rgba(0.68, 0.42, 0.46, 0.40))
    property color btnDeleteText:     pick("#c87080", "#a03840")
    property color btnDeleteTextHover:pick("#d88898", "#882830")

    property color btnFillTop:        pick(Qt.rgba(0.14, 0.18, 0.06, 0.65), Qt.rgba(0.86, 0.92, 0.76, 0.78))
    property color btnFillEnd:        pick(Qt.rgba(0.12, 0.15, 0.05, 0.72), Qt.rgba(0.82, 0.88, 0.70, 0.84))
    property color btnFillHoverTop:   pick(Qt.rgba(0.20, 0.26, 0.08, 0.70), Qt.rgba(0.78, 0.86, 0.62, 0.82))
    property color btnFillHoverEnd:   pick(Qt.rgba(0.17, 0.22, 0.07, 0.76), Qt.rgba(0.74, 0.82, 0.56, 0.86))
    property color btnFillPressed:    pick(Qt.rgba(0.10, 0.14, 0.04, 0.35), Qt.rgba(0.56, 0.66, 0.38, 0.40))
    property color btnFillText:       pick("#a0b850", "#4a6818")
    property color btnFillTextHover:  pick("#b0c860", "#385808")

    property color btnDisabledTop:    pick("#101828", "#dbe2ec")
    property color btnDisabledBot:    pick("#0e1424", "#d5dce8")

    property color accent:            pick("#80b0ff", "#2f6fd6")
    property color accentBright:      pick("#6090ff", "#4386f2")
    property color accentDim:         pick("#5a6ea8", "#6d8fc2")
    property color accentSoft:        pick(Qt.rgba(0.35, 0.50, 1.0, 0.14), Qt.rgba(0.18, 0.44, 0.86, 0.12))
    property color accentMuted:       pick("#384c78", "#8eadd8")
    property color btnGradTop:        pick("#4a7ef0", "#3579e6")
    property color btnGradBot:        pick("#3664d8", "#295fca")
    property color btnHoverTop:       pick("#6090ff", "#4a8ff5")
    property color btnHoverBot:       pick("#4a7ef0", "#3579e6")
    property color btnPressTop:       pick("#2e52b8", "#214fb0")
    property color btnPressBot:       pick("#2646a0", "#1b4396")

    property color accent2:           pick("#50d0cc", "#2e8b86")
    property color accent2Dim:        pick("#4a8a88", "#5c7f84")

    // Tertiary accent (rose in dark, violet in light) completing the
    // three-color system used across table columns and dialog labels.
    property color accent3:           pick("#d89090", "#8868a0")
    property color accent3Dim:        pick("#907070", "#7a6888")

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
    property color textSecondary:     pick("#b4c0d6", "#364252")
    property color textMuted:         pick("#5c70a8", "#687888")
    property color textDisabled:      pick("#3e4e80", "#a0aab8")
    property color textSubtle:        pick("#6c80b8", "#586878")
    property color textIcon:          pick("#7c90c0", "#50607a")
    property color textGhost:         pick("#acbad6", "#3a4860")
    property color textOnAccent:      "#ffffff"
    property color textPlaceholder:   pick("#3e4e80", "#a0aab8")
    property color textError:         pick("#ff6868", "#c83030")
    property color textSuccess:       pick("#48d878", "#187838")
    property color textWarning:       pick("#ffc040", "#c88008")
    property color textLink:          pick("#50d0cc", "#246f7a")
    property color textTooltip:       pick("#c6cee6", "#e0e8f2")
    property color textBadge:         pick("#94a8d0", "#485870")

    // -- Borders --
    // Graduated alpha scale from borderDim (nearly invisible) to borderBright
    // (clearly visible). All share the same base hue per theme so borders look
    // cohesive regardless of intensity. Components pick the level that matches
    // their visual weight (e.g. cards use borderSubtle, focused inputs use borderFocus).
    property color borderDim:         pick(Qt.rgba(0.35, 0.45, 0.85, 0.08), Qt.rgba(0.30, 0.42, 0.58, 0.08))
    property color borderSoft:        pick(Qt.rgba(0.35, 0.45, 0.85, 0.12), Qt.rgba(0.30, 0.42, 0.58, 0.13))
    property color borderSubtle:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.15), Qt.rgba(0.30, 0.42, 0.58, 0.16))
    property color borderInput:       pick(Qt.rgba(0.30, 0.42, 0.80, 0.20), Qt.rgba(0.26, 0.40, 0.56, 0.22))
    property color borderMedium:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.22), Qt.rgba(0.30, 0.42, 0.58, 0.24))
    property color borderBtn:         pick(Qt.rgba(0.35, 0.45, 0.85, 0.24), Qt.rgba(0.30, 0.42, 0.58, 0.28))
    property color borderHover:       pick(Qt.rgba(0.35, 0.45, 0.85, 0.28), Qt.rgba(0.30, 0.42, 0.58, 0.34))
    property color borderHighlight:   pick(Qt.rgba(0.35, 0.45, 0.85, 0.32), Qt.rgba(0.30, 0.42, 0.58, 0.40))
    property color borderBright:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.42), Qt.rgba(0.30, 0.42, 0.58, 0.48))
    property color borderPressed:     pick(Qt.rgba(0.30, 0.35, 0.80, 0.35), Qt.rgba(0.22, 0.36, 0.56, 0.32))
    property color borderFocusHover:  pick(Qt.rgba(0.30, 0.35, 0.80, 0.45), Qt.rgba(0.22, 0.36, 0.56, 0.42))
    property color borderFocus:       pick(Qt.rgba(0.30, 0.35, 0.80, 0.72), Qt.rgba(0.22, 0.36, 0.56, 0.62))
    property color divider:           pick(Qt.rgba(0.35, 0.45, 0.85, 0.10), Qt.rgba(0.30, 0.42, 0.58, 0.10))

    property color rowAlt:            pick(Qt.rgba(0.04, 0.08, 0.20, 0.32), Qt.rgba(0.30, 0.40, 0.55, 0.05))
    property color rowSpotlight:      pick(Qt.rgba(0.62, 0.78, 1.0, 0.12), Qt.rgba(1.0, 1.0, 1.0, 0.26))
    property color rowSpotlightEdge:  pick(Qt.rgba(0.62, 0.78, 1.0, 0.0),  Qt.rgba(1.0, 1.0, 1.0, 0.0))
    property color rowHoverRail:      pick(Qt.rgba(0.44, 0.62, 1.0, 0.24), Qt.rgba(0.28, 0.52, 0.94, 0.18))

    property color selectionBg:       pick(Qt.rgba(0.32, 0.24, 0.88, 0.28), Qt.rgba(0.23, 0.44, 0.88, 0.16))
    property color selectionHover:    pick(Qt.rgba(0.35, 0.28, 0.92, 0.12), Qt.rgba(0.23, 0.44, 0.88, 0.09))
    property color selectionActive:   pick(Qt.rgba(0.32, 0.24, 0.88, 0.36), Qt.rgba(0.23, 0.44, 0.88, 0.24))

    property color scrollThumb:       pick(Qt.rgba(0.18, 0.28, 0.58, 0.48), Qt.rgba(0.32, 0.42, 0.56, 0.26))
    property color scrollThumbHover:  pick(Qt.rgba(0.22, 0.34, 0.65, 0.62), Qt.rgba(0.32, 0.42, 0.56, 0.40))

    property color rippleColor:       pick(Qt.rgba(1.0, 1.0, 1.0, 0.25), Qt.rgba(0.0, 0.0, 0.0, 0.18))

    // Background blobs: three distinct hues at 5-6% alpha for visible layered
    // depth. Dark gets slightly more opacity. Each hue is chosen to contrast
    // with the others (purple / teal / magenta in dark; cobalt / teal / lilac in
    // light) for color variety that bleeds through semi-transparent surfaces.
    property color blobColor1:        pick(Qt.rgba(0.32, 0.22, 0.88, 0.060), Qt.rgba(0.20, 0.47, 0.90, 0.050))
    property color blobColor2:        pick(Qt.rgba(0.08, 0.58, 0.68, 0.055), Qt.rgba(0.12, 0.56, 0.54, 0.046))
    property color blobColor3:        pick(Qt.rgba(0.65, 0.12, 0.55, 0.050), Qt.rgba(0.54, 0.34, 0.82, 0.040))

    // Selection glow: fades from selectionGlow to transparent at row edges.
    property color selectionGlow:     pick(Qt.rgba(0.38, 0.28, 0.92, 0.40), Qt.rgba(0.24, 0.46, 0.88, 0.30))
    property color selectionGlowEdge: pick(Qt.rgba(0.38, 0.28, 0.92, 0.0),  Qt.rgba(0.24, 0.46, 0.88, 0.0))
    property color selectionStripe:   pick(Qt.rgba(0.52, 0.42, 1.0, 0.62),  Qt.rgba(0.28, 0.52, 0.94, 0.48))

    property color shadow:            pick(Qt.rgba(0, 0, 0, 0.48), Qt.rgba(0.12, 0.18, 0.28, 0.20))

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

    // SVG icon paths. SvgIcon.qml wraps IconImage for runtime recoloring.
    readonly property string iconLock:         "qrc:/qt/qml/seal/assets/svgs/lock.svg"
    readonly property string iconLockOpen:     "qrc:/qt/qml/seal/assets/svgs/lock-open.svg"
    readonly property string iconPlus:         "qrc:/qt/qml/seal/assets/svgs/plus.svg"
    readonly property string iconPen:          "qrc:/qt/qml/seal/assets/svgs/pen.svg"
    readonly property string iconTrash:        "qrc:/qt/qml/seal/assets/svgs/trash.svg"
    readonly property string iconFloppyDisk:   "qrc:/qt/qml/seal/assets/svgs/floppy-disk.svg"
    readonly property string iconFolderOpen:   "qrc:/qt/qml/seal/assets/svgs/folder-open.svg"
    readonly property string iconEject:        "qrc:/qt/qml/seal/assets/svgs/eject.svg"
    readonly property string iconKeyboard:     "qrc:/qt/qml/seal/assets/svgs/keyboard.svg"
    readonly property string iconKey:          "qrc:/qt/qml/seal/assets/svgs/key.svg"
    readonly property string iconSearch:       "qrc:/qt/qml/seal/assets/svgs/magnifying-glass.svg"
    readonly property string iconShieldHalved: "qrc:/qt/qml/seal/assets/svgs/shield-halved.svg"
    readonly property string iconService:      "qrc:/qt/qml/seal/assets/svgs/database.svg"
    readonly property string iconUsername:     "qrc:/qt/qml/seal/assets/svgs/user.svg"
    readonly property string iconPassword:     "qrc:/qt/qml/seal/assets/svgs/lock.svg"
    readonly property string iconCamera:       "qrc:/qt/qml/seal/assets/svgs/camera-web.svg"
    readonly property string iconQrCode:       "qrc:/qt/qml/seal/assets/svgs/qrcode-read.svg"
    readonly property string iconFilterSlash:  "qrc:/qt/qml/seal/assets/svgs/filter-slash.svg"
    readonly property string iconNarwhal:      "qrc:/qt/qml/seal/assets/svgs/narwhal.svg"
    readonly property string iconEye:          "qrc:/qt/qml/seal/assets/svgs/eye.svg"
    readonly property string iconEyeSlash:     "qrc:/qt/qml/seal/assets/svgs/eye-slash.svg"
    readonly property string iconCrosshairs:   "qrc:/qt/qml/seal/assets/svgs/crosshairs.svg"
    readonly property string iconSun:          "qrc:/qt/qml/seal/assets/svgs/sun-bright.svg"
    readonly property string iconXmark:        "qrc:/qt/qml/seal/assets/svgs/xmark.svg"
    readonly property string iconMoon:         "qrc:/qt/qml/seal/assets/svgs/moon.svg"
    readonly property string iconChevronDown:  "qrc:/qt/qml/seal/assets/svgs/chevron-down.svg"
    readonly property string iconPowerOff:    "qrc:/qt/qml/seal/assets/svgs/power-off.svg"
    readonly property string iconThumbtack:   "qrc:/qt/qml/seal/assets/svgs/thumbtack.svg"
    readonly property string iconCompress:    "qrc:/qt/qml/seal/assets/svgs/compress.svg"
    readonly property string iconExpand:      "qrc:/qt/qml/seal/assets/svgs/expand.svg"
    readonly property string iconTriangleExclamation: "qrc:/qt/qml/seal/assets/svgs/triangle-exclamation.svg"
    readonly property string iconCircleInfo:  "qrc:/qt/qml/seal/assets/svgs/circle-info.svg"
    readonly property string iconCircleCheck: "qrc:/qt/qml/seal/assets/svgs/circle-check.svg"
    readonly property string iconTerminal:   "qrc:/qt/qml/seal/assets/svgs/terminal.svg"
}
