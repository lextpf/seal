import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// The terminal panel embedded in the GUI. It is a pure view: it renders the
// transcript held by the `Cli` context property and hands each submitted line
// to Cli.executeCliCommand. The panel adds nothing to the transcript itself and
// the prompt it draws is a static label. Cli.executeCliCommand appends the echo
// line, and seal::CliEchoLine (src/CliHandler.cpp) masks it: a fixed set of safe
// commands echoes verbatim, anything else becomes `seal> [input hidden]`. That
// masking, not this view, keeps a mistyped secret out of the visible output.
Item {
    id: root

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Transcript. Read-only, but selectable so output can be copied out.
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: Theme.radiusMedium
            color: Theme.bgInput
            border.width: Theme.strokeRegular
            border.color: Theme.borderSubtle
            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

            ScrollView {
                id: outputScroll
                anchors.fill: parent
                anchors.margins: 10
                clip: true

                ScrollBar.vertical: ScrollBar {
                    policy: ScrollBar.AsNeeded
                    contentItem: Rectangle {
                        implicitWidth: 6
                        radius: 3
                        color: parent.hovered ? Theme.scrollThumbHover : Theme.scrollThumb
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }
                }

                TextArea {
                    id: outputArea
                    text: Cli.cliOutputText
                    // Stay pinned to the newest line. callLater defers the jump
                    // until the new text has been laid out, otherwise the scroll
                    // range is still the previous one and the view lags a line.
                    onTextChanged: Qt.callLater(function() {
                        outputScroll.ScrollBar.vertical.position =
                                1.0 - outputScroll.ScrollBar.vertical.size
                    })
                    readOnly: true
                    selectByMouse: true
                    selectionColor: Theme.btnGradBot
                    selectedTextColor: Theme.textOnAccent
                    font.family: Theme.fontMono
                    font.pixelSize: Theme.fontSizeMedium
                    color: Theme.textPrimary
                    wrapMode: Text.WrapAnywhere
                    textFormat: Text.PlainText

                    // Empty background: the enclosing Rectangle is the surface.
                    background: Item {}
                }
            }
        }

        // Prompt and command entry.
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: Theme.spacingSmall
            spacing: 8

            Text {
                text: "seal>"
                font.family: Theme.fontMono
                font.pixelSize: Theme.fontSizeMedium
                font.weight: Font.DemiBold
                color: Theme.accent
                Layout.alignment: Qt.AlignVCenter
                Behavior on color { ColorAnimation { duration: 350 } }
            }

            TextField {
                id: inputField
                Layout.fillWidth: true
                placeholderText: "Type a command... (:help for commands)"
                placeholderTextColor: Theme.textPlaceholder
                color: Theme.textPrimary
                font.family: Theme.fontMono
                font.pixelSize: Theme.fontSizeMedium
                selectByMouse: true
                selectionColor: Theme.btnGradBot
                selectedTextColor: Theme.textOnAccent

                background: Rectangle {
                    implicitHeight: 36
                    radius: Theme.radiusSmall
                    color: inputField.activeFocus ? Theme.bgInputFocus : Theme.bgInput
                    border.width: Theme.strokeRegular
                    border.color: inputField.activeFocus ? Theme.borderFocus
                                : inputField.hovered ? Theme.borderHover
                                : Theme.borderMedium
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }
                }

                Keys.onReturnPressed: submitCommand()
                Keys.onEnterPressed: submitCommand()

                function submitCommand() {
                    if (inputField.text.trim().length === 0)
                        return
                    Cli.executeCliCommand(inputField.text)
                    inputField.text = ""
                }
            }
        }
    }

    onVisibleChanged: {
        if (visible) inputField.forceActiveFocus()
    }
}
