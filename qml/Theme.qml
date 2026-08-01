pragma Singleton
import QtQuick
import QtCore

// The one source of design tokens: colors, type, spacing, radii, icon paths.
// A raw pixel number at a use site is off-scale against designScale, so wrap it
// in px() (rounded) or pxf() (unrounded). The stroke, font-size and icon-size
// tokens below already call px() or pxf(). The spacing and radius tokens are
// deliberately left unscaled. Use either family exactly as it is; never wrap a
// token a second time. Singleton status needs both the pragma above and
// QT_QML_SINGLETON_TYPE TRUE on qml/Theme.qml in CMakeLists.txt.
QtObject {
    id: root

    // Fixed authored-size boost for the visual language. Qt Quick still owns
    // the Windows per-monitor DPI conversion, so this stays identical across
    // displays instead of multiplying by their physical resolution.
    readonly property real designScale: 1.35
    readonly property real textScale: designScale

    // Bundled Inter font. GUID filename is from the vendor's licensing distribution.
    readonly property FontLoader _interFont: FontLoader {
        source: "qrc:/qt/qml/seal/assets/fonts/b0a4eabe-5fe5-41e3-8dc3-2df2b82ec4eb.ttf"
    }

    // Round authored device-independent sizes; min 1 avoids zero-size elements.
    function px(base) {
        return Math.max(1, Math.round(base * designScale));
    }

    // Unrounded variant, for strokes and radii that must not snap to whole pixels.
    function pxf(base) {
        return base * designScale;
    }

    property bool dark: true
    function toggle() { dark = !dark }

    // Dark/light selector. Nearly every color token below goes through it; the
    // few bare literals, such as textOnAccent, are theme-invariant on purpose.
    function pick(d, l) { return dark ? d : l }

    // Mix foreground over background by `amount` (0..1) and force alpha 1. Used
    // where a light-mode token has to stay opaque instead of blending twice.
    function opaqueBlend(foreground, background, amount) {
        var t = Math.max(0.0, Math.min(1.0, amount));
        return Qt.rgba(background.r + (foreground.r - background.r) * t,
                       background.g + (foreground.g - background.g) * t,
                       background.b + (foreground.b - background.b) * t,
                       1.0);
    }

    property int sortMode: 0

    // Theme choice and sort order persist to QSettings (HKCU\Software\seal\seal)
    // through these aliases. Adding an alias here is all that persisting takes.
    property Settings _settings: Settings {
        property alias dark: root.dark
        property alias sortMode: root.sortMode
    }

    property color bgDeep:            pick("#060a14", "#dce7f4")
    property color bgSurface:         pick("#0a101c", "#c7d7e8")
    // Light surfaces are deliberately blue and translucent: they establish
    // hierarchy without hiding the ambient field under another sheet of white.
    property color bgCard:            pick(Qt.rgba(0.03, 0.06, 0.12, 0.78), "#edf5fc")
    property color bgCardEnd:         pick(Qt.rgba(0.02, 0.05, 0.11, 0.86), "#d9e7f4")
    property color bgGrid:            pick(Qt.rgba(0.03, 0.06, 0.12, 0.50), Qt.rgba(0.64, 0.78, 0.94, 0.24))
    property color bgGridEnd:         pick(Qt.rgba(0.02, 0.05, 0.11, 0.60), Qt.rgba(0.52, 0.70, 0.88, 0.30))
    property color bgDialog:          pick("#101828", "#f3f7fc")
    property color bgInput:           pick(Qt.rgba(0.02, 0.05, 0.11, 0.92), "#e8f0f8")
    property color bgInputFocus:      pick(Qt.rgba(0.04, 0.07, 0.15, 0.96), "#f8fbff")
    property color bgOverlay:         pick(Qt.rgba(0.01, 0.02, 0.05, 0.58), Qt.rgba(0.10, 0.14, 0.22, 0.38))
    property color bgHover:           pick(Qt.rgba(0.06, 0.10, 0.24, 0.50), "#bed5eb")
    property color chromeHover:       pick(Qt.rgba(0.06, 0.10, 0.24, 0.50), Qt.rgba(0.22, 0.48, 0.82, 0.20))
    property color chromePressed:     pick(Qt.rgba(0.04, 0.07, 0.15, 0.96), Qt.rgba(0.16, 0.39, 0.72, 0.30))
    property color bgTableHeader:     pick(Qt.rgba(0.02, 0.04, 0.08, 0.65), "#d3e3f1")
    property color bgTableHeaderEdge: pick(Qt.rgba(0.04, 0.08, 0.20, 0.97), "#9db9d2")
    property color bgTableHeaderTop:  pick(Qt.rgba(0.02, 0.05, 0.12, 0.97), Qt.rgba(0.88, 0.93, 0.98, 0.26))
    property color bgTableHeaderEnd:  pick(Qt.rgba(0.02, 0.04, 0.10, 0.98), Qt.rgba(0.74, 0.84, 0.94, 0.30))
    property color bgTooltip:         pick("#162040", "#28354a")
    property color bgBadge:           pick(Qt.rgba(0.08, 0.12, 0.26, 0.84), "#cbdfee")

    property color bgHeaderTop:       pick(Qt.rgba(0.04, 0.08, 0.18, 0.96), "#cfe1f1")
    property color bgHeaderEnd:       pick(Qt.rgba(0.03, 0.06, 0.16, 0.98), "#bcd3e8")
    property color bgFooterTop:       pick(Qt.rgba(0.02, 0.05, 0.12, 0.50), Qt.rgba(0.74, 0.84, 0.93, 0.48))
    property color bgFooterEnd:       pick(Qt.rgba(0.02, 0.04, 0.10, 0.60), Qt.rgba(0.66, 0.78, 0.89, 0.56))
    property color surfaceHighlight:  pick(Qt.rgba(0.74, 0.84, 1.0, 0.16), Qt.rgba(1.0, 1.0, 1.0, 0.40))
    property color surfaceHighlightSoft:
                                      pick(Qt.rgba(0.54, 0.68, 1.0, 0.10), Qt.rgba(0.25, 0.50, 0.92, 0.20))
    property color surfaceGlow:       pick(Qt.rgba(0.22, 0.40, 0.98, 0.18), Qt.rgba(0.14, 0.42, 0.92, 0.24))
    property color surfaceGlowEdge:   pick(Qt.rgba(0.22, 0.40, 0.98, 0.0),  Qt.rgba(0.18, 0.46, 0.94, 0.0))
    property color focusSheen:        pick(Qt.rgba(0.88, 0.94, 1.0, 0.20), Qt.rgba(1.0, 1.0, 1.0, 0.48))
    property color dialogBand:        pick(Qt.rgba(0.22, 0.38, 0.90, 0.28), Qt.rgba(0.24, 0.46, 0.88, 0.15))
    property color dialogEdgeLight:   pick(Qt.rgba(0.80, 0.88, 1.0, 0.18), Qt.rgba(1.0, 1.0, 1.0, 0.50))
    property color statusChipTop:     pick(Qt.rgba(0.06, 0.10, 0.22, 0.84), "#e2edf8")
    property color statusChipEnd:     pick(Qt.rgba(0.04, 0.08, 0.18, 0.90), "#d4e4f3")
    property color statusChipBorder:  pick(Qt.rgba(0.36, 0.50, 0.88, 0.24), "#6f8fb2")
    property color statusChipText:    pick("#b6c6e6", "#2a3a56")
    property color statusChipStrongTop:
                                      pick(Qt.rgba(0.10, 0.18, 0.34, 0.88), "#cddff2")
    property color statusChipStrongEnd:
                                      pick(Qt.rgba(0.08, 0.14, 0.30, 0.92), "#bbd2eb")
    property color statusChipStrongBorder:
                                      pick(Qt.rgba(0.36, 0.52, 0.92, 0.40), "#4979aa")
    property color statusChipStrongText:
                                      pick("#b8d0ff", "#1f4f83")

    // Header actions are outlined glass controls: low-alpha fills let the
    // ambient field show through, while their border and label carry contrast.
    property color iconBtnTop:        pick(Qt.rgba(0.20, 0.36, 0.72, 0.16),
                                           Qt.rgba(0.19, 0.49, 0.82, 0.16))
    property color iconBtnEnd:        pick(Qt.rgba(0.12, 0.25, 0.58, 0.24),
                                           Qt.rgba(0.12, 0.38, 0.70, 0.23))
    property color iconBtnHoverTop:   pick(Qt.rgba(0.25, 0.44, 0.82, 0.28),
                                           Qt.rgba(0.18, 0.47, 0.80, 0.27))
    property color iconBtnHoverEnd:   pick(Qt.rgba(0.16, 0.32, 0.70, 0.38),
                                           Qt.rgba(0.10, 0.34, 0.68, 0.36))
    property color iconBtnPressed:    pick(Qt.rgba(0.10, 0.22, 0.52, 0.48),
                                           Qt.rgba(0.08, 0.30, 0.64, 0.44))
    property color iconBtnText:       pick("#c8d8f7", "#183956")
    property color iconBtnTextHover:  pick("#f4f8ff", "#071c2f")
    property color iconBtnTextDisabled:
                                      pick("#8294b2", "#3f5366")
    property color iconBtnBorder:     pick(Qt.rgba(0.55, 0.70, 1.0, 0.20),
                                           Qt.rgba(0.10, 0.31, 0.55, 0.25))
    property color iconBtnBorderHover:
                                      pick(Qt.rgba(0.70, 0.82, 1.0, 0.34),
                                           Qt.rgba(0.05, 0.22, 0.43, 0.42))
    property color iconBtnBorderDisabled:
                                      pick(Qt.rgba(0.48, 0.58, 0.78, 0.10),
                                           Qt.rgba(0.20, 0.33, 0.45, 0.14))

    // Ghost buttons (Cancel, No): low-alpha fills so they recede behind primary actions.
    property color ghostBtnTop:       pick(Qt.rgba(0.04, 0.08, 0.20, 0.62), "#edf3f9")
    property color ghostBtnEnd:       pick(Qt.rgba(0.03, 0.06, 0.16, 0.72), "#e2ebf4")
    property color ghostBtnHoverTop:  pick(Qt.rgba(0.12, 0.18, 0.40, 0.48), "#d3e2f1")
    property color ghostBtnHoverEnd:  pick(Qt.rgba(0.08, 0.14, 0.34, 0.52), "#c5d7e9")
    property color ghostBtnPressed:   pick(Qt.rgba(0.14, 0.18, 0.52, 0.24), "#adc5dc")

    // CRUD buttons: green=add, purple=edit, red=delete, yellow-green=fill.
    property color btnAddTop:         pick(Qt.rgba(0.08, 0.18, 0.20, 0.65), "#b0dec9")
    property color btnAddEnd:         pick(Qt.rgba(0.06, 0.15, 0.17, 0.72), "#91cdb0")
    property color btnAddHoverTop:    pick(Qt.rgba(0.10, 0.25, 0.28, 0.70), "#7cc3a4")
    property color btnAddHoverEnd:    pick(Qt.rgba(0.08, 0.22, 0.25, 0.76), "#62b38d")
    property color btnAddPressed:     pick(Qt.rgba(0.05, 0.14, 0.16, 0.35), "#479674")
    property color btnAddText:        pick("#50c0b0", "#07583d")
    property color btnAddTextHover:   pick("#68d8c8", "#013c29")

    property color btnEditTop:        pick(Qt.rgba(0.20, 0.10, 0.22, 0.65), "#d6bde6")
    property color btnEditEnd:        pick(Qt.rgba(0.17, 0.08, 0.19, 0.72), "#c09bd6")
    property color btnEditHoverTop:   pick(Qt.rgba(0.28, 0.14, 0.32, 0.70), "#b688d1")
    property color btnEditHoverEnd:   pick(Qt.rgba(0.24, 0.12, 0.28, 0.76), "#9f70bd")
    property color btnEditPressed:    pick(Qt.rgba(0.16, 0.08, 0.18, 0.35), "#8155a2")
    property color btnEditText:       pick("#c080c8", "#512b6a")
    property color btnEditTextHover:  pick("#d098d8", "#2a0d3a")

    property color btnDeleteTop:      pick(Qt.rgba(0.22, 0.10, 0.14, 0.65), "#e9bbc4")
    property color btnDeleteEnd:      pick(Qt.rgba(0.18, 0.08, 0.12, 0.72), "#dc98a6")
    property color btnDeleteHoverTop: pick(Qt.rgba(0.32, 0.14, 0.20, 0.70), "#d77f92")
    property color btnDeleteHoverEnd: pick(Qt.rgba(0.28, 0.12, 0.17, 0.76), "#c9677a")
    property color btnDeletePressed:  pick(Qt.rgba(0.18, 0.08, 0.10, 0.35), "#aa4d63")
    property color btnDeleteText:     pick("#c87080", "#6a2031")
    property color btnDeleteTextHover:pick("#d88898", "#370b15")

    property color btnFillTop:        pick(Qt.rgba(0.14, 0.18, 0.06, 0.65), "#d8e2a6")
    property color btnFillEnd:        pick(Qt.rgba(0.12, 0.15, 0.05, 0.72), "#c1d174")
    property color btnFillHoverTop:   pick(Qt.rgba(0.20, 0.26, 0.08, 0.70), "#b2c75c")
    property color btnFillHoverEnd:   pick(Qt.rgba(0.17, 0.22, 0.07, 0.76), "#9eb63f")
    property color btnFillPressed:    pick(Qt.rgba(0.10, 0.14, 0.04, 0.35), "#7d992f")
    property color btnFillText:       pick("#a0b850", "#455911")
    property color btnFillTextHover:  pick("#b0c860", "#2b3905")
    property color windowCloseHover:   "#8f352c"
    property color windowClosePressed: "#742a22"

    property color btnDisabledTop:    pick("#101828", "#d1dde8")
    property color btnDisabledBot:    pick("#0e1424", "#c6d3df")

    property color accent:            pick("#80b0ff", "#2f6fc7")
    property color accentBright:      pick("#6090ff", "#3475c9")
    property color accentDim:         pick("#5a6ea8", "#526f9e")
    property color accentSoft:        pick(Qt.rgba(0.35, 0.50, 1.0, 0.14), "#d9e7fa")
    property color accentMuted:       pick("#384c78", "#607da8")
    property color btnGradTop:        pick("#4a7ef0", "#2f6fc7")
    property color btnGradBot:        pick("#3664d8", "#285fae")
    property color btnHoverTop:       pick("#6090ff", "#3475c9")
    property color btnHoverBot:       pick("#4a7ef0", "#2e69ba")
    property color btnPressTop:       pick("#2e52b8", "#24549b")
    property color btnPressBot:       pick("#2646a0", "#1e4787")

    property color accent2:           pick("#50d0cc", "#197f7b")
    property color accent2Dim:        pick("#4a8a88", "#3e7774")

    property color accent3:           pick("#d89090", "#7a4d9b")
    property color accent3Dim:        pick("#907070", "#6d4f82")

    // Fill-armed: same yellow-green hue as Fill, boosted saturation & alpha.
    property color fillArmedTop:      pick(Qt.rgba(0.22, 0.30, 0.08, 0.88), "#d6e5ad")
    property color fillArmedEnd:      pick(Qt.rgba(0.18, 0.26, 0.06, 0.92), "#c7da90")
    property color fillArmedHoverTop: pick(Qt.rgba(0.28, 0.38, 0.10, 0.92), "#bcd278")
    property color fillArmedHoverEnd: pick(Qt.rgba(0.24, 0.34, 0.08, 0.95), "#abc75f")
    property color fillArmedPressTop: pick(Qt.rgba(0.14, 0.18, 0.04, 0.50), "#91ac40")
    property color fillArmedPressEnd: pick(Qt.rgba(0.12, 0.16, 0.04, 0.55), "#819b32")
    property color fillArmedDot:      pick("#c0d848", "#57751c")
    property color fillArmedText:     pick("#ffffff", "#293d0e")
    property color borderFillArmed:   pick(Qt.rgba(0.55, 0.72, 0.18, 0.45), "#718d2e")

    property color textPrimary:       pick("#e6ecf6", "#152033")
    property color textSecondary:     pick("#b4c0d6", "#2e4057")
    property color textMuted:         pick("#5c70a8", "#50647c")
    property color textDisabled:      pick("#3e4e80", "#74859a")
    property color textSubtle:        pick("#6c80b8", "#40566f")
    property color textIcon:          pick("#7c90c0", "#334a64")
    property color textGhost:         pick("#acbad6", "#263b55")
    property color textOnAccent:      "#ffffff"
    property color chromeIcon:        pick("#d8e1f0", "#18222e")
    property color chromeIconHover:   pick("#ffffff", "#020508")
    property color chromeIconDisabled:
                                      pick("#a8b4c8", "#3c4855")
    property color textPlaceholder:   pick("#3e4e80", "#4b6078")
    property color textError:         pick("#ff6868", "#c83030")
    property color textSuccess:       pick("#48d878", "#187838")
    property color textWarning:       pick("#ffc040", "#c88008")
    property color textLink:          pick("#50d0cc", "#176d7d")
    property color textTooltip:       pick("#c6cee6", "#e0e8f2")
    property color textBadge:         pick("#94a8d0", "#364860")

    // Opaque light borders preserve one-device-pixel contrast independently of
    // the Windows HDR/SDR composition path. Dark mode keeps its glass treatment.
    property color borderDim:         pick(Qt.rgba(0.35, 0.45, 0.85, 0.08), "#c1cfdd")
    property color borderSoft:        pick(Qt.rgba(0.35, 0.45, 0.85, 0.12), "#a9bbce")
    property color borderSubtle:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.15), "#879fb8")
    property color borderInput:       pick(Qt.rgba(0.30, 0.42, 0.80, 0.20), "#7692ae")
    property color borderMedium:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.22), "#6684a3")
    property color borderBtn:         pick(Qt.rgba(0.35, 0.45, 0.85, 0.24), "#58799c")
    property color borderHover:       pick(Qt.rgba(0.35, 0.45, 0.85, 0.28), "#426f9e")
    property color borderHighlight:   pick(Qt.rgba(0.35, 0.45, 0.85, 0.32), "#35679a")
    property color borderBright:      pick(Qt.rgba(0.35, 0.45, 0.85, 0.42), "#285e94")
    property color borderPressed:     pick(Qt.rgba(0.30, 0.35, 0.80, 0.35), "#3c6590")
    property color borderFocusHover:  pick(Qt.rgba(0.30, 0.35, 0.80, 0.45), "#2f6aaa")
    property color borderFocus:       pick(Qt.rgba(0.30, 0.35, 0.80, 0.72), "#236dbb")
    property color divider:           pick(Qt.rgba(0.35, 0.45, 0.85, 0.10), "#97abc0")

    property color rowAlt:            pick(Qt.rgba(0.04, 0.08, 0.20, 0.32), "#e8eef6")
    property color rowSpotlight:      pick(Qt.rgba(0.62, 0.78, 1.0, 0.12), "#d7e5f5")
    property color rowSpotlightEdge:  pick(Qt.rgba(0.62, 0.78, 1.0, 0.0),  Qt.rgba(1.0, 1.0, 1.0, 0.0))
    property color rowHoverRail:      pick(Qt.rgba(0.44, 0.62, 1.0, 0.24), "#7f9fc5")

    property color selectionBg:       pick(Qt.rgba(0.32, 0.24, 0.88, 0.28), "#d7e2f5")
    property color selectionHover:    pick(Qt.rgba(0.35, 0.28, 0.92, 0.12), "#e2e9f6")
    property color selectionActive:   pick(Qt.rgba(0.32, 0.24, 0.88, 0.36), "#c5d5f0")

    property color scrollThumb:       pick(Qt.rgba(0.18, 0.28, 0.58, 0.48), "#8ba0b9")
    property color scrollThumbHover:  pick(Qt.rgba(0.22, 0.34, 0.65, 0.62), "#667f9d")

    property color rippleColor:       pick(Qt.rgba(1.0, 1.0, 1.0, 0.25), Qt.rgba(0.0, 0.0, 0.0, 0.18))

    property color blobColor1:        pick(Qt.rgba(0.32, 0.22, 0.88, 0.150), Qt.rgba(0.28, 0.30, 0.90, 0.40))
    property color blobColor2:        pick(Qt.rgba(0.08, 0.58, 0.68, 0.140), Qt.rgba(0.02, 0.62, 0.54, 0.36))
    property color blobColor3:        pick(Qt.rgba(0.65, 0.12, 0.55, 0.130), Qt.rgba(0.68, 0.20, 0.82, 0.34))

    property color auroraIndigo:      pick(Qt.rgba(0.42, 0.34, 0.95, 1.0), Qt.rgba(0.32, 0.26, 0.68, 1.0))
    property color auroraTeal:        pick(Qt.rgba(0.22, 0.74, 0.82, 1.0), Qt.rgba(0.12, 0.54, 0.58, 1.0))
    property color auroraMagenta:     pick(Qt.rgba(0.82, 0.30, 0.74, 1.0), Qt.rgba(0.59, 0.23, 0.57, 1.0))
    property color auroraGlowIndigo:  pick(Qt.rgba(0.60, 0.54, 1.00, 1.0), Qt.rgba(0.42, 0.36, 0.82, 1.0))
    property color auroraGlowTeal:    pick(Qt.rgba(0.50, 0.90, 0.98, 1.0), Qt.rgba(0.24, 0.66, 0.69, 1.0))
    property color auroraGlowMagenta: pick(Qt.rgba(0.98, 0.60, 0.92, 1.0), Qt.rgba(0.70, 0.34, 0.67, 1.0))
    property color verdictSeal:       pick(Qt.rgba(0.26, 0.84, 0.55, 1.0), Qt.rgba(0.10, 0.55, 0.32, 1.0))
    property color verdictSealFlash:  pick(Qt.rgba(0.62, 0.98, 0.80, 1.0), Qt.rgba(0.10, 0.64, 0.39, 1.0))
    property color verdictBreak:      pick(Qt.rgba(1.00, 0.41, 0.41, 1.0), Qt.rgba(0.75, 0.23, 0.24, 1.0))
    property color verdictBreakSoft:  pick(Qt.rgba(0.97, 0.45, 0.58, 1.0), Qt.rgba(0.76, 0.32, 0.43, 1.0))

    property color moteColor:    pick(Qt.rgba(0.82, 0.90, 1.0, 0.12), Qt.rgba(0.22, 0.45, 0.88, 0.18))

    property color dialogBlobColor1:  pick(Qt.rgba(0.32, 0.22, 0.88, 0.14), Qt.rgba(0.20, 0.47, 0.90, 0.12))
    property color dialogBlobColor2:  pick(Qt.rgba(0.08, 0.58, 0.68, 0.13), Qt.rgba(0.12, 0.56, 0.54, 0.105))
    property color dialogBlobColor3:  pick(Qt.rgba(0.65, 0.12, 0.55, 0.12), Qt.rgba(0.54, 0.34, 0.82, 0.095))

    // Selection glow: fades from selectionGlow to transparent at row edges.
    property color selectionGlow:     pick(Qt.rgba(0.38, 0.28, 0.92, 0.40), Qt.rgba(0.24, 0.46, 0.88, 0.26))
    property color selectionGlowEdge: pick(Qt.rgba(0.38, 0.28, 0.92, 0.0),  Qt.rgba(0.24, 0.46, 0.88, 0.0))
    property color selectionStripe:   pick(Qt.rgba(0.52, 0.42, 1.0, 0.62),  Qt.rgba(0.28, 0.52, 0.94, 0.44))

    property color shadow:            pick(Qt.rgba(0, 0, 0, 0.48), Qt.rgba(0.10, 0.16, 0.28, 0.24))

    // -- Animation timing --
    readonly property int hoverDuration:  150
    readonly property int pressDuration:  80

    readonly property int radiusSmall:  10
    readonly property int radiusMedium: 12
    readonly property int radiusLarge:  14

    // Real-valued strokes avoid rounding the authored border back to a
    // one-pixel hairline while Qt still handles per-monitor DPI conversion.
    readonly property real strokeDivider:  pxf(1.00)
    readonly property real strokeRegular:  pxf(1.15)
    readonly property real strokeSelected: pxf(2.20)

    readonly property int spacingSmall:  10
    readonly property int spacingMedium: 14
    readonly property int spacingLarge:  20
    readonly property int spacingXL:     36

    // assets/ is untracked, so the bundled font can be absent; the fallback name
    // then resolves through the system font database. Consolas ships with Windows.
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

    // Official brand colors, keyed by the icon slug that brandSlugFromPath()
    // returns. A service with no entry falls back to the hashed chipPalette.
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

    // A few official brand colors are designed for dark surfaces and lose
    // definition on the translucent light-theme chips. Keep their hue, but
    // use a deliberately deeper display color in light mode.
    readonly property var lightBrandColors: ({
        "github":              "#46515e",
        "square-github":       "#46515e",
        "steam":               "#286f99",
        "steam-symbol":        "#286f99",
        "duolingo":            "#398b08",
        "battle-net":          "#087aaa",
    })

    // Brand slug of a bundled brand icon path, "" for any other path.
    function brandSlugFromPath(path)
    {
        if (!path) return "";
        var prefix = "qrc:/qt/qml/seal/assets/brands/";
        var suffix = ".svg";
        if (path.indexOf(prefix) !== 0) return "";
        if (path.lastIndexOf(suffix) !== path.length - suffix.length) return "";
        return path.substring(prefix.length, path.length - suffix.length);
    }

    // Chip fill for an account: the brand color when the slug is known, else an
    // FNV-1a hash of the name into chipPalette, so one service keeps one color.
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

    // Label color that stays readable on a chip fill: near-black or white.
    function chipTextOn(color)
    {
        var lum = 0.299 * color.r + 0.587 * color.g + 0.114 * color.b;
        return lum > 0.55 ? "#15171d" : "#ffffff";
    }

    // WCAG relative luminance, the contrast measure lightBrandColor() targets.
    function relativeLuminance(color)
    {
        function linearChannel(channel) {
            return channel <= 0.04045
                ? channel / 12.92
                : Math.pow((channel + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * linearChannel(color.r)
             + 0.7152 * linearChannel(color.g)
             + 0.0722 * linearChannel(color.b);
    }

    // Light-theme display color for a brand: the explicit override if there is
    // one, else desaturate slightly and darken until the luminance ceiling holds.
    function lightBrandColor(color, brandSlug)
    {
        if (brandSlug && brandSlug.length > 0) {
            var lightOverride = lightBrandColors[brandSlug];
            if (lightOverride) return lightOverride;
        }

        var luminance = 0.2126 * color.r + 0.7152 * color.g + 0.0722 * color.b;
        var saturation = 0.92;
        var red = luminance + (color.r - luminance) * saturation;
        var green = luminance + (color.g - luminance) * saturation;
        var blue = luminance + (color.b - luminance) * saturation;
        var adjusted = Qt.rgba(red, green, blue, color.a);

        // Graphical controls need roughly 4:1 contrast against the near-white
        // light surface. Scale over-bright colors toward black without shifting hue.
        var maxLuminance = 0.22;
        if (relativeLuminance(adjusted) <= maxLuminance) return adjusted;

        var low = 0.0;
        var high = 1.0;
        for (var i = 0; i < 8; ++i) {
            var factor = (low + high) / 2.0;
            var candidate = Qt.rgba(red * factor, green * factor, blue * factor, color.a);
            if (relativeLuminance(candidate) > maxLuminance)
                high = factor;
            else
                low = factor;
        }
        return Qt.rgba(red * low, green * low, blue * low, color.a);
    }

    // Icon paths, loaded through SvgIcon. assets/ is untracked, so a missing SVG
    // renders as an empty icon rather than breaking the build.
    readonly property string iconLock:         "qrc:/qt/qml/seal/assets/duotone/lock-alt.svg"
    readonly property string iconLockOpen:     "qrc:/qt/qml/seal/assets/duotone/lock-keyhole-open.svg"
    readonly property string iconPlus:         "qrc:/qt/qml/seal/assets/duotone/plus.svg"
    readonly property string iconPen:          "qrc:/qt/qml/seal/assets/duotone/pen-alt.svg"
    readonly property string iconTrash:        "qrc:/qt/qml/seal/assets/duotone/recycle.svg"
    readonly property string iconFloppyDisk:   "qrc:/qt/qml/seal/assets/duotone/floppy-disk.svg"
    readonly property string iconFolderOpen:   "qrc:/qt/qml/seal/assets/duotone/folder-open.svg"
    readonly property string iconEject:        "qrc:/qt/qml/seal/assets/duotone/right-from-bracket.svg"
    readonly property string iconBrowsers:     "qrc:/qt/qml/seal/assets/duotone/browsers.svg"
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
    readonly property string iconBolt:        "qrc:/qt/qml/seal/assets/duotone/bolt.svg"
    readonly property string iconBoltSlash:   "qrc:/qt/qml/seal/assets/duotone/bolt-slash.svg"
}
