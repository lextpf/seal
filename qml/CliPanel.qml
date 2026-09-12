import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

/*!
 * \qmltype CliPanel
 * \inqmlmodule seal
 * \brief Present the embedded command input and transcript.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * The Cli context property owns command dispatch, output, and command echo.
 * CliEchoLine masks unrecognized input before its echo reaches the transcript.
 * The input field itself remains ordinary visible text.
 *
 * Enter submits non-whitespace input unchanged to Cli, then clears the field.
 * Dispatch can block the GUI or defer through the password gate. The view does
 * not retain command history. Showing the panel focuses the input; transcript
 * updates scroll to the end after text layout completes.
 */
Item {
    id: root

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

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
                    // Defer scrolling until text layout updates the scroll range.
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

                    background: Item {}
                }
            }
        }

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

                // Ignore whitespace-only input. Keep the original text for dispatch and
                // clear the field after the command handler returns.
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
