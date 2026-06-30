import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Vault credentials grid: a wrap-to-fit tag cloud of brand-icon chips.
//
// Replaces the old AccountsTable. Service / username / password columns are
// gone; each account is now a single chip showing its resolved brand icon
// (or a monogram fallback) plus its name. Single-click toggles selection,
// double-click arms autofill via AppViewModel.armFillForRow (which
// resolves the row and delegates to Fill.armFor).
//
// The card shell (background gradient, border, two decorative blobs) is
// preserved from the previous design so the visual frame around the data
// stays consistent. Empty-state panels (no vault, empty vault, no search
// match) are ported verbatim — they live inside the same Item that would
// otherwise host the chip flow.

Rectangle {
    id: root

    property var model              // VaultListModel instance from AppViewModel
    property int selectedRow: -1    // Visual index of the selected chip (-1 = none)
    property bool searchActive: false
    property bool vaultLoaded: false
    property bool isCompact: false

    readonly property bool showNoResultsState: chipRepeater.count === 0 && root.searchActive && root.vaultLoaded
    readonly property bool showNoVaultState: chipRepeater.count === 0 && !root.vaultLoaded
    readonly property bool showEmptyVaultState: chipRepeater.count === 0 && root.vaultLoaded && !root.searchActive

    signal rowClicked(int row)
    signal rowDoubleClicked(int row)
    signal addAccountRequested()
    signal clearSearchRequested()

    // Inline empty-state card shared by the empty-vault placeholder. Same
    // shape as the legacy version so visual continuity is preserved.
    component EmptyStatePanel: Rectangle {
        id: panel
        property string titleText: ""
        property string messageText: ""
        property string iconSource: ""
        property color tone: Theme.accent
        property real maximumPanelWidth: Theme.px(440)
        default property alias actions: actionRow.data

        width: parent ? Math.min(parent.width - 40, maximumPanelWidth) : maximumPanelWidth
        implicitHeight: contentColumn.implicitHeight + 48
        radius: Theme.radiusLarge
        gradient: Gradient {
            GradientStop { position: 0; color: Theme.bgInput }
            GradientStop { position: 1; color: Theme.bgCardEnd }
        }
        border.width: 1
        border.color: Theme.borderMedium
        clip: true

        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: 1
            color: Theme.surfaceHighlight
            opacity: 0.75
        }

        Rectangle {
            width: parent.width * 0.62
            height: parent.height * 0.90
            radius: width / 2
            anchors.horizontalCenter: parent.horizontalCenter
            y: -height * 0.38
            color: Qt.rgba(panel.tone.r, panel.tone.g, panel.tone.b, Theme.dark ? 0.12 : 0.08)
        }

        Column {
            id: contentColumn
            width: parent.width - 48
            anchors.centerIn: parent
            spacing: 12

            Rectangle {
                width: 46
                height: 46
                radius: width / 2
                anchors.horizontalCenter: parent.horizontalCenter
                color: "transparent"

                SvgIcon {
                    anchors.centerIn: parent
                    source: panel.iconSource
                    width: Theme.px(18)
                    height: Theme.px(18)
                    color: panel.tone
                }
            }

            Text {
                width: parent.width
                text: panel.titleText
                font.family: Theme.fontFamily
                font.pixelSize: Theme.px(18)
                font.weight: Font.DemiBold
                color: Theme.textPrimary
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            Text {
                width: parent.width
                text: panel.messageText
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.textSecondary
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            Row {
                id: actionRow
                spacing: 10
                anchors.horizontalCenter: parent.horizontalCenter
            }
        }
    }

    radius: Theme.radiusLarge
    // Deliberately transparent (bgGrid/bgGridEnd, not bgCard) so the animated
    // background blobs float visibly through the chip area — see Main.qml.
    gradient: Gradient {
        GradientStop { position: 0; color: Theme.bgGrid }
        GradientStop { position: 1; color: Theme.bgGridEnd }
    }
    border.width: 1
    border.color: Theme.dark ? Theme.borderMedium : Theme.borderSubtle
    clip: true

    Rectangle {
        width: parent.width * 0.40
        height: parent.height * 0.30
        radius: width / 2
        x: parent.width * 0.56
        y: -height * 0.35
        color: Theme.surfaceGlow
        opacity: 0.20
    }

    Rectangle {
        width: parent.width * 0.36
        height: parent.height * 0.26
        radius: width / 2
        x: parent.width * -0.06
        y: parent.height * 0.62
        color: Theme.surfaceGlow
        opacity: 0.10
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        AccountsToolbar {
            Layout.fillWidth: true
            Layout.topMargin: 1
            Layout.leftMargin: 1
            Layout.rightMargin: 1
            accountCount: root.model ? root.model.count : 0
            isCompact: root.isCompact
        }

        // Chip grid + empty states share this Item. Only one is meaningfully
        // visible at a time.
        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: 1
            Layout.rightMargin: 1
            Layout.bottomMargin: 1

            ScrollView {
                id: scroll
                anchors.fill: parent
                clip: true
                visible: chipRepeater.count > 0
                ScrollBar.vertical.policy: root.isCompact
                                             ? ScrollBar.AlwaysOff
                                             : ScrollBar.AsNeeded
                ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                // Padding lives on the ScrollView (a Control), not on the Flow.
                // Flow is a positioner that derives from Item and ignores any
                // `padding` property — that's why the previous version had an
                // asymmetric gap in compact mode.
                //
                // The 14px visual gutter is split 10px ScrollView padding +
                // 4px margin INSIDE the clipped viewport (the wrapper Item
                // below). The selected chip's outer glow ring draws ~3px
                // outside its delegate bounds; ScrollView clips at the padded
                // content area, so without the in-content margin the ring is
                // sliced off at the top/left for first-row / first-column
                // chips. 10 + 4 keeps the layout pixel-identical.
                topPadding: 10
                bottomPadding: 10
                leftPadding: 10
                rightPadding: 10

                contentWidth: availableWidth

                Item {
                    width: scroll.availableWidth
                    implicitHeight: chipFlow.implicitHeight + 8

                    Flow {
                        id: chipFlow
                        x: 4
                        y: 4
                        width: parent.width - 8
                        spacing: 8

                        Repeater {
                            id: chipRepeater
                            model: root.model

                            delegate: AccountChip {
                                selected: root.selectedRow === index
                                onClicked: root.rowClicked(index)
                                onDoubleClicked: root.rowDoubleClicked(index)
                            }
                        }
                    }
                }
            }

            // Snap-to-top when entering compact mode.
            Connections {
                target: root
                function onIsCompactChanged() {
                    if (root.isCompact) {
                        scroll.contentItem.contentY = 0;
                    }
                }
            }

            // ------- Empty states -------

            Column {
                anchors.centerIn: parent
                visible: root.showNoResultsState
                spacing: 10

                SvgIcon {
                    source: Theme.iconFilterSlash
                    width: Theme.px(32)
                    height: Theme.px(32)
                    color: Theme.accentMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "No accounts match this search"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLarge
                    font.weight: Font.Medium
                    color: Theme.textMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "Try a broader term or clear the filter to see every credential again."
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textDisabled
                    anchors.horizontalCenter: parent.horizontalCenter
                }
            }

            Column {
                anchors.centerIn: parent
                visible: root.showNoVaultState
                spacing: 10

                SvgIcon {
                    source: Theme.iconShieldHalved
                    width: Theme.px(32)
                    height: Theme.px(32)
                    color: Theme.accentMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "Load a vault to get started"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLarge
                    font.weight: Font.Medium
                    color: Theme.textMuted
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "Open an existing .seal vault or create your first credential locally."
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textDisabled
                    anchors.horizontalCenter: parent.horizontalCenter
                }
            }

            EmptyStatePanel {
                anchors.centerIn: parent
                visible: root.showEmptyVaultState
                iconSource: Theme.iconPlus
                tone: Theme.accent2
                titleText: "This vault is ready for its first account"
                messageText: "Add a credential and the grid, search, and autofill tools will activate."
            }
        }
    }
}
