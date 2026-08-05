import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Chip grid over VaultListModel: a Flow of AccountChip delegates plus the three
// empty states. The row numbers this grid emits are visual positions in the
// filtered, sorted model, never record indices. The grid reports gestures only;
// Main.qml forwards them to AppViewModel, which resolves the row and owns every
// mutation.
Rectangle {
    id: root

    property var model              // VaultListModel from AppViewModel, already filtered
    property int selectedRow: -1    // Visual row of the selected chip (-1 = none)
    property bool searchActive: false  // Search filter is non-empty
    property bool vaultLoaded: false   // A vault is open
    property bool isCompact: false     // Collapsed window: one chip strip, no scrollbar

    readonly property bool showNoResultsState: chipRepeater.count === 0 && root.searchActive && root.vaultLoaded
    readonly property bool showNoVaultState: chipRepeater.count === 0 && !root.vaultLoaded
    readonly property bool showEmptyVaultState: chipRepeater.count === 0 && root.vaultLoaded && !root.searchActive

    signal rowClicked(int row)
    signal rowDoubleClicked(int row)
    // Reserved hooks for the empty-state action row (EmptyStatePanel.actions).
    // No delegate emits them today; Main.qml already handles both.
    signal addAccountRequested()
    signal clearSearchRequested()

    // Card for the empty-vault state. Default children are appended to the
    // action row under the message text.
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
        border.width: Theme.strokeRegular
        border.color: Theme.borderMedium
        clip: true

        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: Theme.strokeDivider
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
    gradient: Gradient {
        GradientStop { position: 0; color: Theme.bgGrid }
        GradientStop { position: 1; color: Theme.bgGridEnd }
    }
    border.width: Theme.strokeRegular
    border.color: Theme.dark ? Theme.borderMedium : Theme.borderSubtle
    clip: true

    // Decorative corner glows behind the chips.
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

            // Compact mode shows a single chip strip and hides the scrollbar, so
            // reset the offset or the strip stays parked mid-list.
            Connections {
                target: root
                function onIsCompactChanged() {
                    if (root.isCompact) {
                        scroll.contentItem.contentY = 0;
                    }
                }
            }

            // ------- Empty states: search miss, no vault, empty vault -------

            Column {
                anchors.centerIn: parent
                visible: root.showNoResultsState
                spacing: root.isCompact ? 0 : 10

                SvgIcon {
                    visible: !root.isCompact
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
                    visible: !root.isCompact
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
                spacing: root.isCompact ? 0 : 10

                SvgIcon {
                    visible: !root.isCompact
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
                    visible: !root.isCompact
                    text: "Open an existing .seal vault or create your first credential locally."
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textDisabled
                    anchors.horizontalCenter: parent.horizontalCenter
                }
            }

            EmptyStatePanel {
                anchors.centerIn: parent
                visible: root.showEmptyVaultState && !root.isCompact
                iconSource: Theme.iconPlus
                tone: Theme.accent2
                titleText: "This vault is ready for its first account"
                messageText: "Add a credential and the grid, search, and autofill tools will activate."
            }

            Text {
                anchors.centerIn: parent
                visible: root.showEmptyVaultState && root.isCompact
                text: "No accounts yet"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeLarge
                font.weight: Font.Medium
                color: Theme.textMuted
            }
        }
    }
}
