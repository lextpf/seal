pragma Singleton
import QtQuick
import QtCore

// Centralized design token singleton. Every visual property (colors, spacing,
// radii, fonts, icons) lives here so components never hard-code values.
//
// Theme switching is a single `dark` property flip: every color binding
// re-evaluates via ternary expressions, and QML's reactive system propagates
// the change to all consumers automatically. The `dark` preference is persisted
// via Qt Settings so it survives application restarts.
//
// Color philosophy:
//   Dark mode  = cool blue-gray base with blue/purple accents
//   Light mode = warm parchment base with amber/brown accents
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

    property Settings _settings: Settings {
        property alias dark: root.dark
    }

    // -- Background layers --
    // Semi-transparent bgCard lets background blobs bleed through for depth.
    property color bgDeep:       dark ? "#121826" : "#f5ede0"
    property color bgSurface:    dark ? "#161e2e" : "#f0e8d8"
    property color bgCard:       dark ? Qt.rgba(0.08, 0.10, 0.16, 0.78)   : Qt.rgba(1.0, 0.97, 0.93, 0.88)
    property color bgCardEnd:    dark ? Qt.rgba(0.07, 0.08, 0.14, 0.86)   : Qt.rgba(0.97, 0.94, 0.89, 0.92)
    property color bgDialog:     dark ? "#1c2540" : "#fef8ec"
    property color bgInput:      dark ? Qt.rgba(0.07, 0.09, 0.15, 0.92)   : Qt.rgba(1.0, 0.99, 0.96, 0.92)
    property color bgInputFocus: dark ? Qt.rgba(0.09, 0.11, 0.19, 0.96)   : Qt.rgba(1.0, 0.99, 0.97, 0.96)
    property color bgOverlay:    dark ? Qt.rgba(0.02, 0.03, 0.07, 0.58)   : Qt.rgba(0.26, 0.20, 0.12, 0.38)
    property color bgHover:      dark ? Qt.rgba(0.14, 0.16, 0.28, 0.50)   : Qt.rgba(0.55, 0.38, 0.18, 0.08)
    property color bgTableHeader:dark ? Qt.rgba(0.08, 0.10, 0.17, 0.65)   : Qt.rgba(0.96, 0.93, 0.87, 0.72)
    property color bgTableHeaderEdge:dark ? Qt.rgba(0.20, 0.22, 0.52, 0.97) : Qt.rgba(0.88, 0.82, 0.68, 0.97)
    property color bgTableHeaderTop: dark ? Qt.rgba(0.12, 0.14, 0.27, 0.97) : Qt.rgba(0.94, 0.90, 0.80, 0.97)
    property color bgTableHeaderEnd: dark ? Qt.rgba(0.10, 0.12, 0.24, 0.98) : Qt.rgba(0.92, 0.88, 0.78, 0.98)
    property color bgTooltip:    dark ? "#253252" : "#3a2c1a"
    property color bgBadge:      dark ? Qt.rgba(0.16, 0.14, 0.32, 0.84)   : Qt.rgba(0.92, 0.87, 0.76, 0.85)

    property color bgHeaderTop:  dark ? Qt.rgba(0.13, 0.11, 0.24, 0.96)   : Qt.rgba(0.96, 0.92, 0.85, 0.96)
    property color bgHeaderEnd:  dark ? Qt.rgba(0.11, 0.09, 0.21, 0.98)   : Qt.rgba(0.94, 0.90, 0.82, 0.98)
    property color bgFooterTop:  dark ? Qt.rgba(0.06, 0.10, 0.17, 0.96)   : Qt.rgba(0.93, 0.91, 0.86, 0.96)
    property color bgFooterEnd:  dark ? Qt.rgba(0.04, 0.08, 0.14, 1.0)    : Qt.rgba(0.91, 0.89, 0.84, 1.0)

    // -- Button palettes --
    // Each button type carries four gradient states: rest, hover, pressed, disabled.
    // Alpha < 1 on all fills lets the background tint show through, maintaining the
    // layered glass aesthetic. Icon buttons (Load/Save/Unload) share a single neutral
    // palette; CRUD buttons each have a unique semantic hue.
    property color iconBtnTop:        dark ? Qt.rgba(0.08, 0.14, 0.22, 0.82)  : Qt.rgba(0.94, 0.90, 0.82, 0.82)
    property color iconBtnEnd:        dark ? Qt.rgba(0.06, 0.11, 0.18, 0.86)  : Qt.rgba(0.91, 0.86, 0.78, 0.86)
    property color iconBtnHoverTop:   dark ? Qt.rgba(0.10, 0.20, 0.34, 0.90)  : Qt.rgba(0.90, 0.84, 0.72, 0.90)
    property color iconBtnHoverEnd:   dark ? Qt.rgba(0.08, 0.16, 0.28, 0.92)  : Qt.rgba(0.86, 0.80, 0.68, 0.92)
    property color iconBtnPressed:    dark ? Qt.rgba(0.06, 0.10, 0.18, 0.96)  : Qt.rgba(0.82, 0.76, 0.66, 0.96)

    // Ghost buttons (Cancel, No): low-alpha fills so they recede behind primary actions.
    property color ghostBtnTop:        dark ? Qt.rgba(0.12, 0.10, 0.22, 0.62) : Qt.rgba(0.90, 0.92, 0.84, 0.62)
    property color ghostBtnEnd:        dark ? Qt.rgba(0.10, 0.08, 0.18, 0.72) : Qt.rgba(0.86, 0.88, 0.80, 0.72)
    property color ghostBtnHoverTop:   dark ? Qt.rgba(0.22, 0.18, 0.44, 0.48) : Qt.rgba(0.78, 0.82, 0.68, 0.48)
    property color ghostBtnHoverEnd:   dark ? Qt.rgba(0.18, 0.14, 0.38, 0.52) : Qt.rgba(0.74, 0.78, 0.64, 0.52)
    property color ghostBtnPressed:    dark ? Qt.rgba(0.24, 0.18, 0.60, 0.24) : Qt.rgba(0.50, 0.56, 0.38, 0.28)

    // CRUD buttons: green=add, purple=edit, red=delete, yellow-green=fill.
    property color btnAddTop:         dark ? Qt.rgba(0.08, 0.18, 0.20, 0.65) : Qt.rgba(0.78, 0.92, 0.86, 0.78)
    property color btnAddEnd:         dark ? Qt.rgba(0.06, 0.15, 0.17, 0.72) : Qt.rgba(0.72, 0.88, 0.80, 0.84)
    property color btnAddHoverTop:    dark ? Qt.rgba(0.10, 0.25, 0.28, 0.70) : Qt.rgba(0.65, 0.86, 0.76, 0.82)
    property color btnAddHoverEnd:    dark ? Qt.rgba(0.08, 0.22, 0.25, 0.76) : Qt.rgba(0.58, 0.82, 0.70, 0.86)
    property color btnAddPressed:     dark ? Qt.rgba(0.05, 0.14, 0.16, 0.35) : Qt.rgba(0.42, 0.68, 0.56, 0.40)
    property color btnAddText:        dark ? "#50c0b0" : "#1a7050"
    property color btnAddTextHover:   dark ? "#68d8c8" : "#0e5838"

    property color btnEditTop:        dark ? Qt.rgba(0.20, 0.10, 0.22, 0.65) : Qt.rgba(0.92, 0.80, 0.94, 0.78)
    property color btnEditEnd:        dark ? Qt.rgba(0.17, 0.08, 0.19, 0.72) : Qt.rgba(0.88, 0.74, 0.90, 0.84)
    property color btnEditHoverTop:   dark ? Qt.rgba(0.28, 0.14, 0.32, 0.70) : Qt.rgba(0.86, 0.68, 0.88, 0.82)
    property color btnEditHoverEnd:   dark ? Qt.rgba(0.24, 0.12, 0.28, 0.76) : Qt.rgba(0.82, 0.62, 0.84, 0.86)
    property color btnEditPressed:    dark ? Qt.rgba(0.16, 0.08, 0.18, 0.35) : Qt.rgba(0.64, 0.42, 0.66, 0.40)
    property color btnEditText:       dark ? "#c080c8" : "#783878"
    property color btnEditTextHover:  dark ? "#d098d8" : "#602868"

    property color btnDeleteTop:        dark ? Qt.rgba(0.22, 0.10, 0.14, 0.65) : Qt.rgba(0.94, 0.80, 0.82, 0.78)
    property color btnDeleteEnd:        dark ? Qt.rgba(0.18, 0.08, 0.12, 0.72) : Qt.rgba(0.90, 0.74, 0.76, 0.84)
    property color btnDeleteHoverTop:   dark ? Qt.rgba(0.32, 0.14, 0.20, 0.70) : Qt.rgba(0.88, 0.66, 0.70, 0.82)
    property color btnDeleteHoverEnd:   dark ? Qt.rgba(0.28, 0.12, 0.17, 0.76) : Qt.rgba(0.84, 0.60, 0.64, 0.86)
    property color btnDeletePressed:    dark ? Qt.rgba(0.18, 0.08, 0.10, 0.35) : Qt.rgba(0.68, 0.42, 0.46, 0.40)
    property color btnDeleteText:       dark ? "#c87080" : "#a03840"
    property color btnDeleteTextHover:  dark ? "#d88898" : "#882830"

    property color btnFillTop:        dark ? Qt.rgba(0.14, 0.18, 0.06, 0.65) : Qt.rgba(0.86, 0.92, 0.76, 0.78)
    property color btnFillEnd:        dark ? Qt.rgba(0.12, 0.15, 0.05, 0.72) : Qt.rgba(0.82, 0.88, 0.70, 0.84)
    property color btnFillHoverTop:   dark ? Qt.rgba(0.20, 0.26, 0.08, 0.70) : Qt.rgba(0.78, 0.86, 0.62, 0.82)
    property color btnFillHoverEnd:   dark ? Qt.rgba(0.17, 0.22, 0.07, 0.76) : Qt.rgba(0.74, 0.82, 0.56, 0.86)
    property color btnFillPressed:    dark ? Qt.rgba(0.10, 0.14, 0.04, 0.35) : Qt.rgba(0.56, 0.66, 0.38, 0.40)
    property color btnFillText:       dark ? "#a0b850" : "#4a6818"
    property color btnFillTextHover:  dark ? "#b0c860" : "#385808"

    property color btnDisabledTop: dark ? "#1c2640" : "#dcd2c4"
    property color btnDisabledBot: dark ? "#182038" : "#d2c8ba"

    property color accent:        dark ? "#80b0ff" : "#be6628"
    property color accentBright:  dark ? "#6090ff" : "#d47630"
    property color accentDim:     dark ? "#5a6ea8" : "#c49870"
    property color accentSoft:    dark ? Qt.rgba(0.35, 0.50, 1.0, 0.14)  : Qt.rgba(0.72, 0.42, 0.18, 0.12)
    property color accentMuted:   dark ? "#384c78" : "#d4a880"
    property color btnGradTop:    dark ? "#4a7ef0" : "#c46c2a"
    property color btnGradBot:    dark ? "#3664d8" : "#ac5e24"
    property color btnHoverTop:   dark ? "#6090ff" : "#dc7c34"
    property color btnHoverBot:   dark ? "#4a7ef0" : "#c46c2a"
    property color btnPressTop:   dark ? "#2e52b8" : "#925626"
    property color btnPressBot:   dark ? "#2646a0" : "#7a461e"

    property color accent2:       dark ? "#50d0cc" : "#428a50"
    property color accent2Dim:    dark ? "#4a8a88" : "#5a7a58"

    // Tertiary accent (rose in dark, violet in light) completing the
    // three-color system used across table columns and dialog labels.
    property color accent3:       dark ? "#d89090" : "#8868a0"
    property color accent3Dim:    dark ? "#907070" : "#7a6888"

    // Fill-armed: same yellow-green hue as Fill, boosted saturation & alpha.
    property color fillArmedTop:      dark ? Qt.rgba(0.22, 0.30, 0.08, 0.88) : Qt.rgba(0.72, 0.84, 0.52, 0.92)
    property color fillArmedEnd:      dark ? Qt.rgba(0.18, 0.26, 0.06, 0.92) : Qt.rgba(0.68, 0.80, 0.46, 0.94)
    property color fillArmedHoverTop: dark ? Qt.rgba(0.28, 0.38, 0.10, 0.92) : Qt.rgba(0.64, 0.78, 0.42, 0.94)
    property color fillArmedHoverEnd: dark ? Qt.rgba(0.24, 0.34, 0.08, 0.95) : Qt.rgba(0.60, 0.74, 0.36, 0.96)
    property color fillArmedPressTop: dark ? Qt.rgba(0.14, 0.18, 0.04, 0.50) : Qt.rgba(0.50, 0.62, 0.32, 0.55)
    property color fillArmedPressEnd: dark ? Qt.rgba(0.12, 0.16, 0.04, 0.55) : Qt.rgba(0.46, 0.58, 0.28, 0.58)
    property color fillArmedDot:      dark ? "#c0d848" : "#5a7a20"
    property color borderFillArmed:   dark ? Qt.rgba(0.55, 0.72, 0.18, 0.45) : Qt.rgba(0.38, 0.52, 0.12, 0.45)

    // -- Text colors --
    // Graduated hierarchy: primary > secondary > muted > disabled > subtle.
    // Dark mode uses cool blue-grays; light mode uses warm browns so the
    // text temperature matches the overall background warmth/coolness.
    property color textPrimary:     dark ? "#e8ecf6" : "#2a1608"
    property color textSecondary:   dark ? "#c0c8de" : "#4a3420"
    property color textMuted:       dark ? "#6070a0" : "#887058"
    property color textDisabled:    dark ? "#485070" : "#baa890"
    property color textSubtle:      dark ? "#7888b8" : "#786048"
    property color textIcon:        dark ? "#8898c0" : "#685840"
    property color textGhost:       dark ? "#b8c0da" : "#584838"
    property color textOnAccent:    "#ffffff"
    property color textPlaceholder: dark ? "#485070" : "#b8a088"
    property color textError:       dark ? "#ff6868" : "#c83030"
    property color textSuccess:     dark ? "#48d878" : "#187838"
    property color textWarning:     dark ? "#ffc040" : "#c88008"
    property color textLink:        dark ? "#50d0cc" : "#2e7858"
    property color textTooltip:     dark ? "#c8d0e8" : "#f0e4d0"
    property color textBadge:       dark ? "#a0b0d0" : "#584838"

    // -- Borders --
    // Graduated alpha scale from borderDim (nearly invisible) to borderBright
    // (clearly visible). All share the same base hue per theme so borders look
    // cohesive regardless of intensity. Components pick the level that matches
    // their visual weight (e.g. cards use borderSubtle, focused inputs use borderFocus).
    property color borderDim:        dark ? Qt.rgba(0.45, 0.55, 1.0, 0.08)  : Qt.rgba(0.55, 0.40, 0.18, 0.08)
    property color borderSoft:       dark ? Qt.rgba(0.45, 0.55, 1.0, 0.12)  : Qt.rgba(0.55, 0.40, 0.18, 0.13)
    property color borderSubtle:     dark ? Qt.rgba(0.45, 0.55, 1.0, 0.15)  : Qt.rgba(0.55, 0.40, 0.18, 0.16)
    property color borderInput:      dark ? Qt.rgba(0.40, 0.55, 0.90, 0.20) : Qt.rgba(0.50, 0.38, 0.18, 0.22)
    property color borderMedium:     dark ? Qt.rgba(0.45, 0.55, 1.0, 0.22)  : Qt.rgba(0.55, 0.40, 0.18, 0.24)
    property color borderBtn:        dark ? Qt.rgba(0.45, 0.55, 1.0, 0.24)  : Qt.rgba(0.55, 0.40, 0.18, 0.28)
    property color borderHover:      dark ? Qt.rgba(0.45, 0.55, 1.0, 0.28)  : Qt.rgba(0.55, 0.40, 0.18, 0.34)
    property color borderHighlight:  dark ? Qt.rgba(0.45, 0.55, 1.0, 0.32)  : Qt.rgba(0.55, 0.40, 0.18, 0.40)
    property color borderBright:     dark ? Qt.rgba(0.45, 0.55, 1.0, 0.42)  : Qt.rgba(0.55, 0.40, 0.18, 0.48)
    property color borderPressed:    dark ? Qt.rgba(0.35, 0.30, 0.85, 0.35) : Qt.rgba(0.55, 0.30, 0.10, 0.32)
    property color borderFocusHover: dark ? Qt.rgba(0.35, 0.30, 0.85, 0.45) : Qt.rgba(0.55, 0.30, 0.10, 0.42)
    property color borderFocus:      dark ? Qt.rgba(0.35, 0.30, 0.85, 0.72) : Qt.rgba(0.55, 0.30, 0.10, 0.62)
    property color divider:          dark ? Qt.rgba(0.45, 0.55, 1.0, 0.10)  : Qt.rgba(0.55, 0.40, 0.18, 0.10)

    property color rowAlt:          dark ? Qt.rgba(0.10, 0.12, 0.20, 0.32) : Qt.rgba(0.50, 0.38, 0.18, 0.05)

    property color selectionBg:     dark ? Qt.rgba(0.32, 0.24, 0.88, 0.28)  : Qt.rgba(0.72, 0.50, 0.10, 0.18)
    property color selectionHover:  dark ? Qt.rgba(0.35, 0.28, 0.92, 0.12)  : Qt.rgba(0.72, 0.50, 0.10, 0.10)
    property color selectionActive: dark ? Qt.rgba(0.32, 0.24, 0.88, 0.36)  : Qt.rgba(0.72, 0.50, 0.10, 0.26)

    property color scrollThumb:      dark ? Qt.rgba(0.22, 0.28, 0.48, 0.48) : Qt.rgba(0.55, 0.42, 0.22, 0.26)
    property color scrollThumbHover: dark ? Qt.rgba(0.28, 0.35, 0.58, 0.62) : Qt.rgba(0.55, 0.42, 0.22, 0.40)

    property color rippleColor: dark ? Qt.rgba(1.0, 1.0, 1.0, 0.25) : Qt.rgba(0.0, 0.0, 0.0, 0.18)

    // Background blobs: three distinct hues at 5-6% alpha for visible layered
    // depth. Dark gets slightly more opacity. Each hue is chosen to contrast
    // with the others (purple / teal / magenta in dark; gold / teal / rose in
    // light) for color variety that bleeds through semi-transparent surfaces.
    property color blobColor1: dark ? Qt.rgba(0.32, 0.22, 0.88, 0.060) : Qt.rgba(0.78, 0.46, 0.10, 0.052)
    property color blobColor2: dark ? Qt.rgba(0.08, 0.58, 0.68, 0.055) : Qt.rgba(0.15, 0.52, 0.50, 0.048)
    property color blobColor3: dark ? Qt.rgba(0.65, 0.12, 0.55, 0.050) : Qt.rgba(0.62, 0.25, 0.25, 0.044)

    // Selection glow: fades from selectionGlow to transparent at row edges.
    property color selectionGlow:     dark ? Qt.rgba(0.38, 0.28, 0.92, 0.40) : Qt.rgba(0.74, 0.50, 0.12, 0.35)
    property color selectionGlowEdge: dark ? Qt.rgba(0.38, 0.28, 0.92, 0.0)  : Qt.rgba(0.74, 0.50, 0.12, 0.0)
    property color selectionStripe:   dark ? Qt.rgba(0.52, 0.42, 1.0, 0.62)  : Qt.rgba(0.74, 0.50, 0.12, 0.56)

    property color shadow: dark ? Qt.rgba(0, 0, 0, 0.48) : Qt.rgba(0.28, 0.18, 0.08, 0.20)

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
}
