import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Command row below the accounts grid. Add, Edit and Delete disappear in compact
// mode; the Fill button stays and doubles as the cancel control while a fill is
// armed. Every action leaves as a signal: Main sends them to AppViewModel, except
// the cancel path, which goes to the Fill context property (TypeController).
RowLayout {
    id: root
    spacing: narrowLayout ? 8 : Theme.spacingSmall

    property bool hasSelection: false
    property bool isFillArmed: false
    property int fillCountdownSeconds: 0
    property bool isCompact: false
    property bool isBusy: false
    readonly property bool narrowLayout: width > 0 && width < 820

    signal addClicked()
    signal editClicked()
    signal deleteClicked()
    signal fillClicked()
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
            : Theme.opaqueBlend(Theme.btnFillText, Theme.btnFillEnd, 0.32)
        leftPadding: 14
        rightPadding: 14
        // Stays enabled while armed so the countdown can be cancelled. Otherwise it
        // needs a selected record and an idle view model.
        enabled: root.isFillArmed || (root.hasSelection && !root.isBusy)
        onClicked: {
            if (root.isFillArmed)
                root.cancelFillClicked();
            else
                root.fillClicked();
        }

        // Faded glass in dark mode; opaque, softly color-coded state in light mode.
        readonly property color _disText: Theme.dark
            ? Qt.rgba(Theme.btnFillText.r, Theme.btnFillText.g, Theme.btnFillText.b, 0.32)
            : Theme.opaqueBlend(Theme.btnFillText, Theme.textDisabled, 0.30)
        readonly property color _disTop: Theme.dark
            ? Qt.rgba(Theme.btnFillTop.r, Theme.btnFillTop.g, Theme.btnFillTop.b,
                      Theme.btnFillTop.a * 0.35)
            : Theme.opaqueBlend(Theme.btnFillTop, Theme.btnDisabledTop, 0.50)
        readonly property color _disEnd: Theme.dark
            ? Qt.rgba(Theme.btnFillEnd.r, Theme.btnFillEnd.g, Theme.btnFillEnd.b,
                      Theme.btnFillEnd.a * 0.35)
            : Theme.opaqueBlend(Theme.btnFillEnd, Theme.btnDisabledBot, 0.50)

        HoverHandler { id: fillHover; cursorShape: Qt.PointingHandCursor }

        // Crosshairs while idle, ban icon plus the remaining seconds while armed.
        contentItem: Row {
            spacing: 6
            anchors.centerIn: parent
            SvgIcon {
                source: root.isFillArmed ? Theme.iconBan : Theme.iconCrosshairs
                width: Theme.iconSizeMedium
                height: Theme.iconSizeMedium
                color: !fillBtn.enabled ? fillBtn._disText
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
                color: !fillBtn.enabled ? fillBtn._disText
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
            // Separate color branches: armed (saturated yellow-green, Theme.fillArmed*)
            // vs idle (muted yellow-green, Theme.btnFill*).
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
            border.width: Theme.strokeRegular
            border.color: root.isFillArmed
                ? Theme.borderFillArmed
                : (!fillBtn.enabled ? (Theme.dark
                                           ? Theme.borderDim
                                           : Theme.opaqueBlend(fillBtn._fillBorder,
                                                               Theme.borderDim, 0.36))
                    : fillBtn.hovered ? Theme.borderHover
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

    // Takes the spare width so the buttons stay left-aligned in wide mode.
    Item { Layout.fillWidth: true; visible: !root.isCompact }
}
