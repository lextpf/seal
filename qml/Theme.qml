pragma Singleton
import QtQuick
import QtCore

/*!
 * \qmltype Theme
 * \inqmlmodule seal
 * \brief Supply shared colors, dimensions, icon paths, and persisted display preferences.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Color bindings follow \c dark unless a token uses a fixed color. Select related button
 * colors from the same family. The dark preference and sort mode persist through
 * QSettings under \c {HKCU\Software\seal\seal}.
 *
 * \section1 Dimensions and tokens
 *
 * Use size tokens directly. Apply \c px or \c pxf only to raw design dimensions.
 * Qt applies the screen device pixel ratio separately.
 *
 * \table
 * \header
 *     \li Token family
 *     \li Contract
 * \row
 *     \li \c {stroke*}, \c {fontSize*}, \c iconSize*
 *     \li Logical pixels after design scaling. Strokes retain fractions.
 * \row
 *     \li \c {spacing*}, \c {radius*}, \c chromeHeight
 *     \li Logical pixels without design scaling.
 * \row
 *     \li \c {hoverDuration}, \c pressDuration
 *     \li Animation durations in milliseconds.
 * \row
 *     \li \c {bgInput*}, \c bgInputGlass*
 *     \li Dialog field colors and translucent header field colors, respectively.
 * \row
 *     \li \c {btn*}, \c {ghostBtn*}, \c fillArmed*
 *     \li Button state colors. Top and End or Bot identify gradient endpoints.
 * \row
 *     \li \c icon* paths
 *     \li Optional bundled SVG resources. Missing assets render no icon.
 * \endtable
 *
 * Singleton registration requires \c QT_QML_SINGLETON_TYPE in CMakeLists.txt.
 */
QtObject {
    id: root

    /*!
     * Multiplier for raw design dimensions. Independent of the screen device pixel ratio.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property real designScale: 1.35
    /*!
     * Text multiplier exposed to consumers. Follows the design scale.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property real textScale: designScale

    readonly property FontLoader _interFont: FontLoader {
        source: "qrc:/qt/qml/seal/assets/fonts/b0a4eabe-5fe5-41e3-8dc3-2df2b82ec4eb.ttf"
    }

    /*!
     * \brief Scale and round a design dimension.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Returns \a base multiplied by the design scale and rounded to logical pixels.
     * The minimum result is 1.
     */
    function px(base) {
        return Math.max(1, Math.round(base * designScale));
    }

    /*!
     * \brief Scale a design dimension without rounding.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Returns \a base multiplied by the design scale in logical pixels. Preserves zero, sign,
     * and fractional values.
     */
    function pxf(base) {
        return base * designScale;
    }

    /*!
     * When true, select the dark palette. Restored and saved through QSettings.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool dark: true
    /*!
     * \brief Switch between the dark and light palettes.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Updates the persisted dark preference and all dependent color bindings.
     */
    function toggle() { dark = !dark }

    /*!
     * \brief Select a value for the active palette.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Returns \a d when dark mode is active; otherwise returns \a {l}. Values are unchanged.
     */
    function pick(d, l) { return dark ? d : l }

    /*!
     * \brief Interpolate color channels with an explicit output alpha.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * \a foreground and \a background supply RGB channels. Clamp \a amount to [0, 1],
     * where 0 selects background and 1 selects foreground. Clamp \a alpha to [0, 1]
     * and use it for the returned color; input alpha channels do not affect the result.
     */
    function blend(foreground, background, amount, alpha) {
        var t = Math.max(0.0, Math.min(1.0, amount));
        var a = Math.max(0.0, Math.min(1.0, alpha));
        return Qt.rgba(background.r + (foreground.r - background.r) * t,
                       background.g + (foreground.g - background.g) * t,
                       background.b + (foreground.b - background.b) * t,
                       a);
    }

    /*!
     * Persisted row ordering sent to AppViewModel. Use 0 for A to Z, 1 for Z to A,
     * or 2 for branded records first. The view model normalizes invalid values.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property int sortMode: 0

    // Persist only the display preferences exposed by these aliases.
    property Settings _settings: Settings {
        property alias dark: root.dark
        property alias sortMode: root.sortMode
    }

    property color bgDeep:            pick("#060a14", "#dce7f4")
    /*!
     * Alpha used for the window clear color and its premultiplied RGB channels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property real windowBaseAlpha: 0.78
    /*!
     * Premultiplied clear color for desktop composition. Straight RGB channels can
     * clip the light background to white.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property color windowBase:        Qt.rgba(bgDeep.r * windowBaseAlpha,
                                              bgDeep.g * windowBaseAlpha,
                                              bgDeep.b * windowBaseAlpha,
                                              windowBaseAlpha)
    property color bgSurface:         pick("#0a101c", "#c7d7e8")
    property color bgCard:            pick(Qt.rgba(0.03, 0.06, 0.12, 0.78), "#edf5fc")
    property color bgCardEnd:         pick(Qt.rgba(0.02, 0.05, 0.11, 0.86), "#d9e7f4")
    property color bgGrid:            pick(Qt.rgba(0.03, 0.06, 0.12, 0.50), Qt.rgba(0.64, 0.78, 0.94, 0.24))
    property color bgGridEnd:         pick(Qt.rgba(0.02, 0.05, 0.11, 0.60), Qt.rgba(0.52, 0.70, 0.88, 0.30))
    property color bgDialog:          pick("#101828", "#f3f7fc")
    property color bgInput:           pick(Qt.rgba(0.02, 0.05, 0.11, 0.92), "#e8f0f8")
    property color bgInputFocus:      pick(Qt.rgba(0.04, 0.07, 0.15, 0.96), "#f8fbff")
    // Keep header fields translucent; dialog fields use the bgInput family.
    property color bgInputGlass:      pick(Qt.rgba(0.03, 0.06, 0.12, 0.50), Qt.rgba(1, 1, 1, 0.34))
    property color bgInputGlassHover: pick(Qt.rgba(0.03, 0.06, 0.12, 0.58), Qt.rgba(1, 1, 1, 0.46))
    property color bgInputGlassFocus: pick(Qt.rgba(0.03, 0.06, 0.12, 0.66), Qt.rgba(1, 1, 1, 0.66))
    property color bgOverlay:         pick(Qt.rgba(0.01, 0.02, 0.05, 0.58), Qt.rgba(0.10, 0.14, 0.22, 0.38))
    property color bgHover:           pick(Qt.rgba(0.06, 0.10, 0.24, 0.50), "#bed5eb")
    property color chromeHover:       pick(Qt.rgba(0.06, 0.10, 0.24, 0.50), Qt.rgba(0.22, 0.48, 0.82, 0.20))
    property color chromePressed:     pick(Qt.rgba(0.04, 0.07, 0.15, 0.96), Qt.rgba(0.16, 0.39, 0.72, 0.30))
    property color bgTableHeader:     pick(Qt.rgba(0.02, 0.04, 0.08, 0.65), "#d3e3f1")
    property color bgTableHeaderEdge: pick(Qt.rgba(0.04, 0.08, 0.20, 0.97), "#9db9d2")
    property color bgTableHeaderTop:  pick(Qt.rgba(0.02, 0.05, 0.12, 0.72), Qt.rgba(0.88, 0.93, 0.98, 0.26))
    property color bgTableHeaderEnd:  pick(Qt.rgba(0.02, 0.04, 0.10, 0.78), Qt.rgba(0.74, 0.84, 0.94, 0.30))
    property color bgTooltip:         pick("#162040", "#28354a")
    property color bgBadge:           pick(Qt.rgba(0.08, 0.12, 0.26, 0.84), "#cbdfee")

    property color surfaceHighlight:  pick(Qt.rgba(0.74, 0.84, 1.0, 0.16), Qt.rgba(1.0, 1.0, 1.0, 0.40))
    property color surfaceGlow:       pick(Qt.rgba(0.22, 0.40, 0.98, 0.18), Qt.rgba(0.14, 0.42, 0.92, 0.24))
    property color surfaceGlowEdge:   pick(Qt.rgba(0.22, 0.40, 0.98, 0.0),  Qt.rgba(0.18, 0.46, 0.94, 0.0))
    property color dialogBand:        pick(Qt.rgba(0.22, 0.38, 0.90, 0.28), Qt.rgba(0.24, 0.46, 0.88, 0.15))
    property color dialogEdgeLight:   pick(Qt.rgba(0.80, 0.88, 1.0, 0.18), Qt.rgba(1.0, 1.0, 1.0, 0.50))
    // Blue-grey keeps light-mode status chips visible on the pale background.
    property color statusChipTop:     pick(Qt.rgba(0.10, 0.16, 0.32, 0.86), Qt.rgba(0.30, 0.45, 0.72, 0.16))
    property color statusChipEnd:     pick(Qt.rgba(0.08, 0.13, 0.28, 0.90), Qt.rgba(0.30, 0.45, 0.72, 0.22))
    property color statusChipText:    pick("#b6c6e6", "#2a3a56")
    property color statusChipStrongTop:
                                      pick(Qt.rgba(0.16, 0.26, 0.50, 0.90), Qt.rgba(0.18, 0.42, 0.80, 0.24))
    property color statusChipStrongEnd:
                                      pick(Qt.rgba(0.13, 0.22, 0.44, 0.94), Qt.rgba(0.18, 0.42, 0.80, 0.30))
    property color statusChipStrongText:
                                      pick("#b8d0ff", "#11335a")

    property color ghostBtnTop:       pick(Qt.rgba(0.04, 0.08, 0.20, 0.62), "#edf3f9")
    property color ghostBtnEnd:       pick(Qt.rgba(0.03, 0.06, 0.16, 0.72), "#e2ebf4")
    property color ghostBtnHoverTop:  pick(Qt.rgba(0.12, 0.18, 0.40, 0.48), "#d3e2f1")
    property color ghostBtnHoverEnd:  pick(Qt.rgba(0.08, 0.14, 0.34, 0.52), "#c5d7e9")
    property color ghostBtnPressed:   pick(Qt.rgba(0.14, 0.18, 0.52, 0.24), "#adc5dc")

    property color btnAddTop:         pick(Qt.rgba(0.08, 0.18, 0.20, 0.65), Qt.rgba(0.69, 0.87, 0.79, 0.65))
    property color btnAddEnd:         pick(Qt.rgba(0.06, 0.15, 0.17, 0.72), Qt.rgba(0.57, 0.80, 0.69, 0.72))
    property color btnAddHoverTop:    pick(Qt.rgba(0.10, 0.25, 0.28, 0.70), Qt.rgba(0.49, 0.76, 0.64, 0.70))
    property color btnAddHoverEnd:    pick(Qt.rgba(0.08, 0.22, 0.25, 0.76), Qt.rgba(0.38, 0.70, 0.55, 0.76))
    property color btnAddPressed:     pick(Qt.rgba(0.05, 0.14, 0.16, 0.35), Qt.rgba(0.28, 0.59, 0.45, 0.35))
    property color btnAddText:        pick("#50c0b0", "#064a33")
    property color btnAddTextHover:   pick("#68d8c8", "#013c29")

    property color btnEditTop:        pick(Qt.rgba(0.20, 0.10, 0.22, 0.65), Qt.rgba(0.84, 0.74, 0.90, 0.65))
    property color btnEditEnd:        pick(Qt.rgba(0.17, 0.08, 0.19, 0.72), Qt.rgba(0.75, 0.61, 0.84, 0.72))
    property color btnEditHoverTop:   pick(Qt.rgba(0.28, 0.14, 0.32, 0.70), Qt.rgba(0.71, 0.53, 0.82, 0.70))
    property color btnEditHoverEnd:   pick(Qt.rgba(0.24, 0.12, 0.28, 0.76), Qt.rgba(0.62, 0.44, 0.74, 0.76))
    property color btnEditPressed:    pick(Qt.rgba(0.16, 0.08, 0.18, 0.35), Qt.rgba(0.51, 0.33, 0.64, 0.35))
    property color btnEditText:       pick("#c080c8", "#512b6a")
    property color btnEditTextHover:  pick("#d098d8", "#2a0d3a")

    property color btnDeleteTop:      pick(Qt.rgba(0.22, 0.10, 0.14, 0.65), Qt.rgba(0.91, 0.73, 0.77, 0.65))
    property color btnDeleteEnd:      pick(Qt.rgba(0.18, 0.08, 0.12, 0.72), Qt.rgba(0.86, 0.60, 0.65, 0.72))
    property color btnDeleteHoverTop: pick(Qt.rgba(0.32, 0.14, 0.20, 0.70), Qt.rgba(0.84, 0.50, 0.57, 0.70))
    property color btnDeleteHoverEnd: pick(Qt.rgba(0.28, 0.12, 0.17, 0.76), Qt.rgba(0.79, 0.40, 0.48, 0.76))
    property color btnDeletePressed:  pick(Qt.rgba(0.18, 0.08, 0.10, 0.35), Qt.rgba(0.67, 0.30, 0.39, 0.35))
    property color btnDeleteText:     pick("#d07c8c", "#6a2031")
    property color btnDeleteTextHover:pick("#d88898", "#370b15")

    property color btnFillTop:        pick(Qt.rgba(0.14, 0.18, 0.06, 0.65), Qt.rgba(0.85, 0.89, 0.65, 0.65))
    property color btnFillEnd:        pick(Qt.rgba(0.12, 0.15, 0.05, 0.72), Qt.rgba(0.76, 0.82, 0.45, 0.72))
    property color btnFillHoverTop:   pick(Qt.rgba(0.20, 0.26, 0.08, 0.70), Qt.rgba(0.70, 0.78, 0.36, 0.70))
    property color btnFillHoverEnd:   pick(Qt.rgba(0.17, 0.22, 0.07, 0.76), Qt.rgba(0.62, 0.71, 0.25, 0.76))
    property color btnFillPressed:    pick(Qt.rgba(0.10, 0.14, 0.04, 0.35), Qt.rgba(0.49, 0.60, 0.18, 0.35))
    property color btnFillText:       pick("#a0b850", "#3a4b0e")
    property color btnFillTextHover:  pick("#b0c860", "#2b3905")

    property color btnLoadTop:        pick(Qt.rgba(0.06, 0.17, 0.20, 0.65), Qt.rgba(0.66, 0.87, 0.89, 0.65))
    property color btnLoadEnd:        pick(Qt.rgba(0.05, 0.14, 0.17, 0.72), Qt.rgba(0.53, 0.80, 0.84, 0.72))
    property color btnLoadHoverTop:   pick(Qt.rgba(0.08, 0.24, 0.28, 0.70), Qt.rgba(0.42, 0.75, 0.79, 0.70))
    property color btnLoadHoverEnd:   pick(Qt.rgba(0.07, 0.21, 0.25, 0.76), Qt.rgba(0.32, 0.68, 0.73, 0.76))
    property color btnLoadPressed:    pick(Qt.rgba(0.04, 0.13, 0.16, 0.35), Qt.rgba(0.24, 0.57, 0.61, 0.35))
    property color btnLoadText:       pick("#48c4d0", "#0a4f57")
    property color btnLoadTextHover:  pick("#62d8e4", "#02363c")

    property color btnSaveTop:        pick(Qt.rgba(0.09, 0.14, 0.26, 0.65), Qt.rgba(0.71, 0.81, 0.95, 0.65))
    property color btnSaveEnd:        pick(Qt.rgba(0.07, 0.12, 0.23, 0.72), Qt.rgba(0.59, 0.72, 0.92, 0.72))
    property color btnSaveHoverTop:   pick(Qt.rgba(0.12, 0.20, 0.36, 0.70), Qt.rgba(0.50, 0.65, 0.88, 0.70))
    property color btnSaveHoverEnd:   pick(Qt.rgba(0.10, 0.17, 0.32, 0.76), Qt.rgba(0.40, 0.56, 0.82, 0.76))
    property color btnSavePressed:    pick(Qt.rgba(0.06, 0.10, 0.22, 0.35), Qt.rgba(0.30, 0.46, 0.72, 0.35))
    property color btnSaveText:       pick("#78a8f0", "#173e7c")
    property color btnSaveTextHover:  pick("#92bcff", "#0a2857")

    property color btnUnloadTop:      pick(Qt.rgba(0.22, 0.16, 0.07, 0.65), Qt.rgba(0.95, 0.85, 0.65, 0.65))
    property color btnUnloadEnd:      pick(Qt.rgba(0.19, 0.14, 0.06, 0.72), Qt.rgba(0.91, 0.77, 0.49, 0.72))
    property color btnUnloadHoverTop: pick(Qt.rgba(0.30, 0.22, 0.09, 0.70), Qt.rgba(0.87, 0.70, 0.37, 0.70))
    property color btnUnloadHoverEnd: pick(Qt.rgba(0.26, 0.19, 0.08, 0.76), Qt.rgba(0.81, 0.63, 0.27, 0.76))
    property color btnUnloadPressed:  pick(Qt.rgba(0.17, 0.12, 0.05, 0.35), Qt.rgba(0.69, 0.53, 0.20, 0.35))
    property color btnUnloadText:     pick("#e0b060", "#6a4406")
    property color btnUnloadTextHover: pick("#f0c878", "#422a02")

    property color btnRekeyTop:       pick(Qt.rgba(0.22, 0.09, 0.18, 0.65), Qt.rgba(0.93, 0.75, 0.88, 0.65))
    property color btnRekeyEnd:       pick(Qt.rgba(0.19, 0.08, 0.16, 0.72), Qt.rgba(0.88, 0.64, 0.81, 0.72))
    property color btnRekeyHoverTop:  pick(Qt.rgba(0.31, 0.13, 0.26, 0.70), Qt.rgba(0.83, 0.54, 0.75, 0.70))
    property color btnRekeyHoverEnd:  pick(Qt.rgba(0.27, 0.11, 0.23, 0.76), Qt.rgba(0.77, 0.43, 0.67, 0.76))
    property color btnRekeyPressed:   pick(Qt.rgba(0.17, 0.07, 0.14, 0.35), Qt.rgba(0.65, 0.33, 0.56, 0.35))
    property color btnRekeyText:      pick("#e08cd0", "#6a1b57")
    property color btnRekeyTextHover: pick("#f0a4e0", "#3f0a33")

    property color btnSetupTop:       pick(Qt.rgba(0.12, 0.11, 0.26, 0.65), Qt.rgba(0.78, 0.79, 0.95, 0.65))
    property color btnSetupEnd:       pick(Qt.rgba(0.10, 0.09, 0.23, 0.72), Qt.rgba(0.68, 0.70, 0.92, 0.72))
    property color btnSetupHoverTop:  pick(Qt.rgba(0.17, 0.16, 0.36, 0.70), Qt.rgba(0.59, 0.62, 0.88, 0.70))
    property color btnSetupHoverEnd:  pick(Qt.rgba(0.15, 0.13, 0.32, 0.76), Qt.rgba(0.51, 0.54, 0.83, 0.76))
    property color btnSetupPressed:   pick(Qt.rgba(0.09, 0.08, 0.21, 0.35), Qt.rgba(0.41, 0.44, 0.72, 0.35))
    property color btnSetupText:      pick("#a0a8f0", "#2d3384")
    property color btnSetupTextHover: pick("#b8bcff", "#1a1e5a")

    property color windowCloseHover:   "#8f352c"
    property color windowClosePressed: "#742a22"

    property color btnDisabledTop:    pick(Qt.rgba(0.42, 0.48, 0.62, 0.16), Qt.rgba(0.30, 0.36, 0.46, 0.18))
    property color btnDisabledBot:    pick(Qt.rgba(0.38, 0.44, 0.58, 0.20), Qt.rgba(0.26, 0.32, 0.42, 0.22))
    property color btnDisabledBorder: pick(borderDim, Qt.rgba(0.30, 0.36, 0.46, 0.34))

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

    property color fillArmedTop:      pick(Qt.rgba(0.22, 0.30, 0.08, 0.88), Qt.rgba(0.84, 0.90, 0.68, 0.88))
    property color fillArmedEnd:      pick(Qt.rgba(0.18, 0.26, 0.06, 0.92), Qt.rgba(0.78, 0.85, 0.56, 0.92))
    property color fillArmedHoverTop: pick(Qt.rgba(0.28, 0.38, 0.10, 0.92), Qt.rgba(0.74, 0.82, 0.47, 0.92))
    property color fillArmedHoverEnd: pick(Qt.rgba(0.24, 0.34, 0.08, 0.95), Qt.rgba(0.67, 0.78, 0.37, 0.95))
    property color fillArmedPressTop: pick(Qt.rgba(0.14, 0.18, 0.04, 0.50), Qt.rgba(0.57, 0.67, 0.25, 0.50))
    property color fillArmedPressEnd: pick(Qt.rgba(0.12, 0.16, 0.04, 0.55), Qt.rgba(0.51, 0.61, 0.20, 0.55))
    property color fillArmedDot:      pick("#c0d848", "#57751c")
    property color fillArmedText:     pick("#ffffff", "#293d0e")
    property color borderFillArmed:   pick(Qt.rgba(0.55, 0.72, 0.18, 0.45), Qt.rgba(0.44, 0.55, 0.18, 0.62))

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
    // Error contrast at the expected background limits: 4.7:1 on rgb(61,64,72) in
    // dark mode and 5.3:1 on rgb(172,180,190) in light mode.
    property color textError:         pick("#ff8f8f", "#7a0f0f")
    property color textSuccess:       pick("#48d878", "#187838")
    property color textWarning:       pick("#ffc040", "#c88008")
    property color textLink:          pick("#50d0cc", "#176d7d")
    property color textTooltip:       pick("#c6cee6", "#e0e8f2")
    property color textBadge:         pick("#94a8d0", "#364860")

    // Opaque light borders retain contrast at one device pixel under HDR/SDR composition.
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

    property color selectionGlow:     pick(Qt.rgba(0.38, 0.28, 0.92, 0.40), Qt.rgba(0.24, 0.46, 0.88, 0.26))
    property color selectionGlowEdge: pick(Qt.rgba(0.38, 0.28, 0.92, 0.0),  Qt.rgba(0.24, 0.46, 0.88, 0.0))
    property color selectionStripe:   pick(Qt.rgba(0.52, 0.42, 1.0, 0.62),  Qt.rgba(0.28, 0.52, 0.94, 0.44))

    property color shadow:            pick(Qt.rgba(0, 0, 0, 0.48), Qt.rgba(0.10, 0.16, 0.28, 0.24))

    readonly property int hoverDuration:  150
    readonly property int pressDuration:  80

    readonly property int radiusSmall:  10
    readonly property int radiusMedium: 12
    readonly property int radiusLarge:  14

    // Fractional strokes avoid rounding back to a one-pixel border.
    readonly property real strokeDivider:  pxf(1.00)
    readonly property real strokeRegular:  pxf(1.15)

    readonly property int spacingSmall:  10
    readonly property int spacingMedium: 14
    readonly property int spacingLarge:  20
    readonly property int spacingXL:     36

    /*!
     * Height reserved for window controls and dragging, in unscaled logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int chromeHeight:  36

    /*!
     * Bundled font family when loaded. Otherwise, request Inter from the system.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property string fontFamily:     _interFont.name !== "" ? _interFont.name : "Inter"
    readonly property string fontMono:       "Consolas"
    readonly property string fontEmoji:      "Segoe UI Emoji"
    readonly property int fontSizeSmall:     px(10)
    readonly property int fontSizeMedium:    px(11)
    readonly property int fontSizeLarge:     px(12)
    readonly property int fontSizeTitle:     px(26)
    readonly property int iconSizeSmall:     px(13)
    readonly property int iconSizeMedium:    px(15)

    /*!
     * Theme-dependent fallback colors for account chips. Keep a non-empty array;
     * name hashes select an index from this order.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property var chipPalette: [
        pick("#80b0ff", "#2f6fd6"),  // Blue.
        pick("#50d0cc", "#2e8b86"),  // Teal.
        pick("#d89090", "#8868a0"),  // Rose or violet, matching the accent3 family.
        pick("#d8a060", "#a86820"),  // Amber.
        pick("#80c0c0", "#1f6a78"),  // Cyan.
        pick("#a0c860", "#4a6818"),  // Lime.
        pick("#e08070", "#aa3030"),  // Coral.
        pick("#a090d8", "#5040a0"),  // Indigo.
    ]

    /*!
     * Brand colors keyed by the slug from \c {brandSlugFromPath}. Missing keys use the palette.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
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

    /*!
     * Explicit brand colors for light chips. These opaque values take priority over
     * the computed luminance adjustment.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property var lightBrandColors: ({
        "github":              "#46515e",
        "square-github":       "#46515e",
        "steam":               "#286f99",
        "steam-symbol":        "#286f99",
        "duolingo":            "#398b08",
        "battle-net":          "#087aaa",
    })

    /*!
     * \brief Extract a brand slug from a resource path.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * \a path is a string with the prefix qrc:/qt/qml/seal/assets/brands/ and suffix .svg.
     * Returns the text between them, or an empty string for an empty or unmatched path.
     * The resource does not need to exist; this function only checks the path text.
     */
    function brandSlugFromPath(path)
    {
        if (!path) return "";
        var prefix = "qrc:/qt/qml/seal/assets/brands/";
        var suffix = ".svg";
        if (path.indexOf(prefix) !== 0) return "";
        if (path.lastIndexOf(suffix) !== path.length - suffix.length) return "";
        return path.substring(prefix.length, path.length - suffix.length);
    }

    /*!
     * \brief Choose a brand color or a stable fallback for an account name.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * \a name is case-sensitive UTF-16 text. \a brandSlug is an optional key in the brand
     * color map. A known key takes priority; otherwise FNV-1a maps the name to the palette.
     * Returns the first palette color if the name is empty and no brand color exists.
     */
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

    /*!
     * \brief Choose dark or white text for a chip background.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * \a color supplies RGB channels in [0, 1]. Returns dark text when the weighted
     * brightness exceeds 0.55; otherwise returns white. Ignores the input alpha.
     */
    function chipTextOn(color)
    {
        var lum = 0.299 * color.r + 0.587 * color.g + 0.114 * color.b;
        return lum > 0.55 ? "#15171d" : "#ffffff";
    }

    /*!
     * \brief Compute relative luminance from sRGB color channels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * \a color supplies sRGB channels in [0, 1]. Returns linear-light luminance in [0, 1]
     * for those channels. Ignores alpha and does not clamp input channels.
     */
    function relativeLuminance(color)
    {
        /*!
         * \brief Convert an sRGB channel to linear light.
         *
         * Author: \l {https://github.com/lextpf}{Lextpf}.
         *
         * Returns the linear value for \a channel in [0, 1]. The input is not clamped.
         */
        function linearChannel(channel) {
            return channel <= 0.04045
                ? channel / 12.92
                : Math.pow((channel + 0.055) / 1.055, 2.4);
        }
        return 0.2126 * linearChannel(color.r)
             + 0.7152 * linearChannel(color.g)
             + 0.0722 * linearChannel(color.b);
    }

    /*!
     * \brief Adjust a brand color for a light chip background.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * \a color supplies the fallback color. \a brandSlug is an optional override key.
     * Returns an opaque override when present. Otherwise, reduce saturation and darken
     * RGB channels until relative luminance is at most 0.22, preserving input alpha.
     * The computed path expects RGB channels in [0, 1].
     */
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

        // Scale toward black until the luminance ceiling is met; preserve the RGB ratios.
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

    // Optional SVG assets render no icon when absent.
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
