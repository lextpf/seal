import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

/*!
 * \qmltype ActionBar
 * \inqmlmodule seal
 * \brief Present account actions and the armed-fill countdown.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Main routes account commands to AppViewModel and fill cancellation to Fill.
 * The owner supplies selection, busy state, and countdown updates.
 * Compact mode shows only the fill control.
 *
 * \table
 * \header
 *     \li Fill state
 *     \li Availability and action
 * \row
 *     \li Armed
 *     \li Always enabled; request cancellation.
 * \row
 *     \li Disarmed, selected, and idle
 *     \li Enabled; request a fill.
 * \row
 *     \li Disarmed with no selection or while busy
 *     \li Disabled.
 * \endtable
 */
RowLayout {
    id: root
    spacing: narrowLayout ? 8 : Theme.spacingSmall

    /*!
     * Enable edit and delete actions; also required to start a fill.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool hasSelection: false
    /*!
     * Show cancellation and the countdown instead of the fill action.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool isFillArmed: false
    /*!
     * Remaining whole seconds from Fill; displayed only while armed, without clamping.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property int fillCountdownSeconds: 0
    /*!
     * Hide add, edit, and delete actions.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool isCompact: false
    /*!
     * Prevent a new fill; cancellation remains available while armed.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool isBusy: false
    /*!
     * Use smaller button widths and gaps below 820 logical pixels; zero width is excluded.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool narrowLayout: width > 0 && width < 820

    /*!
     * \brief Request the owner's account-creation flow.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal addClicked()
    /*!
     * \brief Request editing of the current selection.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal editClicked()
    /*!
     * \brief Request the owner's deletion flow for the current selection.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal deleteClicked()
    /*!
     * \brief Request a fill for the current selection.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * The button emits this only when disarmed, selected, and idle.
     */
    signal fillClicked()
    /*!
     * \brief Request cancellation of the armed fill.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * The button can emit this while the owner is busy.
     */
    signal cancelFillClicked()

    TintedButton {
        visible: !root.isCompact
        text: "Add"
        faIcon: Theme.iconPlus
        tintTop:         Theme.btnAddTop
        tintEnd:         Theme.btnAddEnd
        tintHoverTop:    Theme.btnAddHoverTop
        tintHoverEnd:    Theme.btnAddHoverEnd
        tintPressed:     Theme.btnAddPressed
        tintText:        Theme.btnAddText
        tintTextHover:   Theme.btnAddTextHover
        background.implicitWidth: root.narrowLayout ? 104 : 120

        onClicked: root.addClicked()
    }

    TintedButton {
        visible: !root.isCompact
        text: "Edit"
        faIcon: Theme.iconPen
        enabled: root.hasSelection
        tintTop:         Theme.btnEditTop
        tintEnd:         Theme.btnEditEnd
        tintHoverTop:    Theme.btnEditHoverTop
        tintHoverEnd:    Theme.btnEditHoverEnd
        tintPressed:     Theme.btnEditPressed
        tintText:        Theme.btnEditText
        tintTextHover:   Theme.btnEditTextHover
        background.implicitWidth: root.narrowLayout ? 104 : 120

        onClicked: root.editClicked()
    }

    TintedButton {
        visible: !root.isCompact
        text: "Delete"
        faIcon: Theme.iconTrash
        enabled: root.hasSelection
        tintTop:         Theme.btnDeleteTop
        tintEnd:         Theme.btnDeleteEnd
        tintHoverTop:    Theme.btnDeleteHoverTop
        tintHoverEnd:    Theme.btnDeleteHoverEnd
        tintPressed:     Theme.btnDeletePressed
        tintText:        Theme.btnDeleteText
        tintTextHover:   Theme.btnDeleteTextHover
        background.implicitWidth: root.narrowLayout ? 104 : 120

        onClicked: root.deleteClicked()
    }

    Button {
        id: fillBtn
        readonly property color _fillBorder: Theme.dark
            ? Qt.rgba(Theme.btnFillEnd.r, Theme.btnFillEnd.g, Theme.btnFillEnd.b,
                      Math.min(Theme.btnFillEnd.a + 0.18, 1.0))
            : Theme.blend(Theme.btnFillText, Theme.btnFillEnd, 0.24, 0.50)
        readonly property color _fillBorderHover: Theme.dark
            ? Theme.borderHover
            : Theme.blend(Theme.btnFillTextHover, Theme.btnFillHoverEnd, 0.24, 0.65)
        leftPadding: 14
        rightPadding: 14
        // Keep cancellation enabled while a fill is armed.
        enabled: root.isFillArmed || (root.hasSelection && !root.isBusy)
        onClicked: {
            if (root.isFillArmed)
                root.cancelFillClicked();
            else
                root.fillClicked();
        }

        HoverHandler { id: fillHover; cursorShape: Qt.PointingHandCursor }

        contentItem: Row {
            spacing: 6
            anchors.centerIn: parent
            SvgIcon {
                source: root.isFillArmed ? Theme.iconBan : Theme.iconCrosshairs
                width: Theme.iconSizeMedium
                height: Theme.iconSizeMedium
                color: !fillBtn.enabled ? Theme.textDisabled
                     : root.isFillArmed ? Theme.fillArmedText
                     : fillBtn.hovered ? Theme.btnFillTextHover : Theme.btnFillText
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
            Text {
                text: root.isFillArmed
                    ? "Cancel (" + root.fillCountdownSeconds + "s)"
                    : "Fill"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                font.weight: Font.DemiBold
                color: !fillBtn.enabled ? Theme.textDisabled
                     : root.isFillArmed ? Theme.fillArmedText
                     : fillBtn.hovered ? Theme.btnFillTextHover : Theme.btnFillText
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
        }

        scale: pressed ? 0.97 : 1.0
        Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

        background: Rectangle {
            implicitWidth: root.narrowLayout ? 136 : 160
            implicitHeight: 40
            radius: Theme.radiusMedium
            clip: true
            gradient: Gradient {
                GradientStop {
                    position: 0
                    color: root.isFillArmed
                        ? (fillBtn.pressed ? Theme.fillArmedPressTop : fillBtn.hovered ? Theme.fillArmedHoverTop : Theme.fillArmedTop)
                        : (!fillBtn.enabled ? Theme.btnDisabledTop : fillBtn.pressed ? Theme.btnFillPressed : fillBtn.hovered ? Theme.btnFillHoverTop : Theme.btnFillTop)
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
                GradientStop {
                    position: 1
                    color: root.isFillArmed
                        ? (fillBtn.pressed ? Theme.fillArmedPressEnd : fillBtn.hovered ? Theme.fillArmedHoverEnd : Theme.fillArmedEnd)
                        : (!fillBtn.enabled ? Theme.btnDisabledBot : fillBtn.pressed ? Theme.btnFillPressed : fillBtn.hovered ? Theme.btnFillHoverEnd : Theme.btnFillEnd)
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
            }
            border.width: Theme.strokeRegular
            border.color: root.isFillArmed
                ? Theme.borderFillArmed
                : (!fillBtn.enabled ? Theme.btnDisabledBorder
                    : fillBtn.hovered ? fillBtn._fillBorderHover
                    : fillBtn._fillBorder)

            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

            RippleEffect {
                id: fillRipple
                baseColor: root.isFillArmed
                    ? Qt.rgba(Theme.fillArmedDot.r, Theme.fillArmedDot.g, Theme.fillArmedDot.b, 0.30)
                    : Qt.rgba(Theme.btnFillText.r, Theme.btnFillText.g, Theme.btnFillText.b, 0.30)
                cornerRadius: parent.radius
            }
        }
        onPressed: fillRipple.trigger(fillHover.point.position.x, fillHover.point.position.y)
    }

    Item { Layout.fillWidth: true; visible: !root.isCompact }
}
