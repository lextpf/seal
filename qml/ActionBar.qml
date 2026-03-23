import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// CRUD action buttons + Fill auto-type.
//
// Each button is color-coded by semantic meaning:
//   Green        = Add (new credential)
//   Purple       = Edit (modify existing)
//   Red          = Delete (soft-delete, committed on save)
//   Yellow-green = Fill (arm auto-type hooks)
//   Orange       = Fill armed (hooks active, countdown running)
//
// TintedButton is a shared inline component that Add/Edit/Delete instantiate
// with their own tint* color overrides. Fill is a separate Button because it
// has two distinct visual states (normal vs armed) with different color branches,
// icon swap (crosshairs vs X), and text that includes the countdown timer.
//
// Edit, Delete, and Fill require a row selection; Add is always enabled.

RowLayout {
    id: root
    spacing: Theme.spacingSmall

    property bool hasSelection: false
    property bool isFillArmed: false
    property int fillCountdownSeconds: 0
    property bool isCompact: false
    property bool isBusy: false

    signal addClicked()
    signal editClicked()
    signal deleteClicked()
    signal fillClicked()
    signal cancelFillClicked()

    // Inline component: a parameterized button template. Each instance overrides
    // the tint* properties to apply its semantic color. Disabled state is derived
    // by reducing the tint alpha (same hue at lower opacity) rather than switching
    // to a generic gray, so the button's identity remains recognizable.
    component TintedButton: Button {
        id: tBtn
        property string faIcon: ""
        property color tintTop:         Theme.ghostBtnTop
        property color tintEnd:         Theme.ghostBtnEnd
        property color tintHoverTop:    Theme.ghostBtnHoverTop
        property color tintHoverEnd:    Theme.ghostBtnHoverEnd
        property color tintPressed:     Theme.ghostBtnPressed
        property color tintText:        Theme.textGhost
        property color tintTextHover:   Theme.textPrimary
        // Border derived from tint color with alpha boost to echo the button fill.
        readonly property color _tintBorder: Qt.rgba(tintEnd.r, tintEnd.g, tintEnd.b, Math.min(tintEnd.a + 0.18, 1.0))
        leftPadding: 14
        rightPadding: 14

        // Disabled: same hue at reduced opacity.
        readonly property color _disText:   Qt.rgba(tintText.r, tintText.g, tintText.b, 0.32)
        readonly property color _disTop:    Qt.rgba(tintTop.r, tintTop.g, tintTop.b, tintTop.a * 0.35)
        readonly property color _disEnd:    Qt.rgba(tintEnd.r, tintEnd.g, tintEnd.b, tintEnd.a * 0.35)

        HoverHandler { id: tBtnHover; cursorShape: Qt.PointingHandCursor }

        contentItem: Row {
            spacing: 6
            anchors.centerIn: parent
            SvgIcon {
                source: tBtn.faIcon
                width: Theme.iconSizeMedium
                height: Theme.iconSizeMedium
                color: !tBtn.enabled ? tBtn._disText : tBtn.hovered ? tBtn.tintTextHover : tBtn.tintText
                visible: tBtn.faIcon !== ""
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
            Text {
                text: tBtn.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                font.weight: Font.DemiBold
                color: !tBtn.enabled ? tBtn._disText : tBtn.hovered ? tBtn.tintTextHover : tBtn.tintText
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
        }

        // Press squish: 0.97 scale with spring-back easing.
        scale: pressed ? 0.97 : 1.0
        Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

        background: Rectangle {
            implicitWidth: 120
            implicitHeight: 38
            radius: Theme.radiusMedium
            clip: true
            // Four-state gradient: disabled / normal / hovered / pressed.
            gradient: Gradient {
                GradientStop { position: 0; color: !tBtn.enabled ? tBtn._disTop : tBtn.pressed ? tBtn.tintPressed : tBtn.hovered ? tBtn.tintHoverTop : tBtn.tintTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                GradientStop { position: 1; color: !tBtn.enabled ? tBtn._disEnd : tBtn.pressed ? tBtn.tintPressed : tBtn.hovered ? tBtn.tintHoverEnd : tBtn.tintEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
            }
            border.width: 1
            border.color: !tBtn.enabled ? Theme.borderDim
                        : tBtn.hovered ? Theme.borderHover
                        : tBtn._tintBorder

            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

            RippleEffect { id: tBtnRipple; baseColor: Qt.rgba(tBtn.tintText.r, tBtn.tintText.g, tBtn.tintText.b, 0.30) }
        }
        onPressed: tBtnRipple.trigger(tBtnHover.point.position.x, tBtnHover.point.position.y)
    }

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

        onClicked: root.deleteClicked()
    }

    // Fill button. Separate from TintedButton because it has two entirely different
    // visual states (normal yellow-green vs armed opaque orange) that need independent
    // color branches in the gradient stops, plus dynamic text showing the countdown.
    Button {
        id: fillBtn
        readonly property color _fillBorder: Qt.rgba(Theme.btnFillEnd.r, Theme.btnFillEnd.g, Theme.btnFillEnd.b, Math.min(Theme.btnFillEnd.a + 0.18, 1.0))
        leftPadding: 14
        rightPadding: 14
        // Always enabled when armed (so user can cancel), otherwise requires selection.
        enabled: root.isFillArmed || (root.hasSelection && !root.isBusy)
        onClicked: {
            if (root.isFillArmed)
                root.cancelFillClicked();
            else
                root.fillClicked();
        }

        // Faded tint for disabled state
        readonly property color _disText:   Qt.rgba(Theme.btnFillText.r, Theme.btnFillText.g, Theme.btnFillText.b, 0.32)
        readonly property color _disTop:    Qt.rgba(Theme.btnFillTop.r, Theme.btnFillTop.g, Theme.btnFillTop.b, Theme.btnFillTop.a * 0.35)
        readonly property color _disEnd:    Qt.rgba(Theme.btnFillEnd.r, Theme.btnFillEnd.g, Theme.btnFillEnd.b, Theme.btnFillEnd.a * 0.35)

        HoverHandler { id: fillHover; cursorShape: Qt.PointingHandCursor }

        // Icon: crosshairs (normal) vs X (armed).
        contentItem: Row {
            spacing: 6
            anchors.centerIn: parent
            SvgIcon {
                source: root.isFillArmed ? Theme.iconXmark : Theme.iconCrosshairs
                width: Theme.iconSizeMedium
                height: Theme.iconSizeMedium
                color: !fillBtn.enabled ? fillBtn._disText
                     : root.isFillArmed ? Theme.textOnAccent
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
                color: !fillBtn.enabled ? fillBtn._disText
                     : root.isFillArmed ? Theme.textOnAccent
                     : fillBtn.hovered ? Theme.btnFillTextHover : Theme.btnFillText
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
        }

        scale: pressed ? 0.97 : 1.0
        Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

        background: Rectangle {
            implicitWidth: 160
            implicitHeight: 38
            radius: Theme.radiusMedium
            clip: true
            // Separate color branches: armed (orange) vs normal (yellow-green).
            gradient: Gradient {
                GradientStop {
                    position: 0
                    color: root.isFillArmed
                        ? (fillBtn.pressed ? Theme.fillArmedPressTop : fillBtn.hovered ? Theme.fillArmedHoverTop : Theme.fillArmedTop)
                        : (!fillBtn.enabled ? fillBtn._disTop : fillBtn.pressed ? Theme.btnFillPressed : fillBtn.hovered ? Theme.btnFillHoverTop : Theme.btnFillTop)
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
                GradientStop {
                    position: 1
                    color: root.isFillArmed
                        ? (fillBtn.pressed ? Theme.fillArmedPressEnd : fillBtn.hovered ? Theme.fillArmedHoverEnd : Theme.fillArmedEnd)
                        : (!fillBtn.enabled ? fillBtn._disEnd : fillBtn.pressed ? Theme.btnFillPressed : fillBtn.hovered ? Theme.btnFillHoverEnd : Theme.btnFillEnd)
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
            }
            border.width: 1
            border.color: root.isFillArmed
                ? Theme.borderFillArmed
                : (!fillBtn.enabled ? Theme.borderDim
                    : fillBtn.hovered ? Theme.borderHover
                    : fillBtn._fillBorder)

            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

            RippleEffect { id: fillRipple; baseColor: root.isFillArmed ? Qt.rgba(Theme.fillArmedDot.r, Theme.fillArmedDot.g, Theme.fillArmedDot.b, 0.30) : Qt.rgba(Theme.btnFillText.r, Theme.btnFillText.g, Theme.btnFillText.b, 0.30) }
        }
        onPressed: fillRipple.trigger(fillHover.point.position.x, fillHover.point.position.y)
    }

    Item { Layout.fillWidth: true; visible: !root.isCompact }
}
