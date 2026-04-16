import QtQuick
import QtQuick.Layouts

// Single row in the accounts list view.
//
// Security: no plaintext credentials ever reach this component. The C++ VaultListModel
// exposes only masked strings (e.g. "********") through its data roles. Decryption
// happens on-demand in Backend when the user explicitly triggers typeLogin/typePassword
// or opens the edit dialog.
//
// Required properties are injected by the ListView delegate system from the model's
// role names. `recordIndex` is the real index into Backend::m_Records (stable across
// filtering); `index` is the visual row position (changes when the filter narrows).

Item {
    id: root

    required property int index           // Visual position in the filtered list
    required property string platform     // Cleartext service name (decrypted on vault load)
    required property string maskedUsername
    required property string maskedPassword
    required property int recordIndex     // Stable index into Backend::m_Records
    required property bool selected       // Driven by parent's selectedRow binding
    property bool isHovered: mouseArea.containsMouse
    readonly property real contentShift: root.selected ? 2 : root.isHovered ? 1 : 0.0

    signal clicked()

    implicitHeight: 48

    Rectangle {
        anchors.fill: parent
        // Four-state background priority: selected (strongest) > hovered >
        // zebra stripe (odd rows get a subtle tint for readability) > transparent.
        // All transitions are animated via Behavior for smooth state changes.
        color: root.selected ? Theme.selectionActive
             : root.isHovered ? Theme.selectionHover
             : (root.index % 2 === 1) ? Theme.rowAlt
             : "transparent"
        border.width: 0

        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }

        Rectangle {
            anchors.fill: parent
            opacity: root.selected ? 0.58 : root.isHovered ? 0.72 : 0.0
            gradient: Gradient {
                orientation: Gradient.Horizontal
                GradientStop { position: 0.00; color: Theme.rowSpotlightEdge }
                GradientStop { position: 0.22; color: Theme.rowSpotlight }
                GradientStop { position: 0.54; color: Theme.rowSpotlightEdge }
                GradientStop { position: 1.00; color: Theme.rowSpotlightEdge }
            }
            Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
        }

        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: 1
            color: Theme.surfaceHighlight
            opacity: root.selected ? 0.50 : root.isHovered ? 0.22 : 0.05
            Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
        }

        // Selection glow pair (top + bottom). A 3px gradient fading from the
        // selection accent color to transparent creates a soft "lit edge" effect
        // that makes the selected row pop without a hard border. Opacity-animated
        // so it fades in/out smoothly on selection change.
        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: 3
            opacity: root.selected ? 1.0 : 0.0
            Behavior on opacity { NumberAnimation { duration: 200 } }
            gradient: Gradient {
                orientation: Gradient.Vertical
                GradientStop { position: 0.0; color: Theme.selectionGlow }
                GradientStop { position: 1.0; color: Theme.selectionGlowEdge }
            }
        }

        // Bottom selection glow (mirrored)
        Rectangle {
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            anchors.right: parent.right
            height: 3
            opacity: root.selected ? 1.0 : 0.0
            Behavior on opacity { NumberAnimation { duration: 200 } }
            gradient: Gradient {
                orientation: Gradient.Vertical
                GradientStop { position: 0.0; color: Theme.selectionGlowEdge }
                GradientStop { position: 1.0; color: Theme.selectionGlow }
            }
        }

        // Hover/selection rail on the left edge. Hover gets a slim rail;
        // selection widens and switches to the brighter stripe token.
        Rectangle {
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            width: root.selected ? 4 : root.isHovered ? 2 : 0
            color: root.selected ? Theme.selectionStripe : Theme.rowHoverRail
            opacity: root.selected || root.isHovered ? 1.0 : 0.0
            Behavior on width { NumberAnimation { duration: Theme.hoverDuration } }
            Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
        }

        // Row separator
        Rectangle {
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            anchors.right: parent.right
            height: 1
            color: Theme.borderDim
        }

        Item {
            id: contentWrap
            anchors.fill: parent
            anchors.leftMargin: 14
            anchors.rightMargin: 14
            property real shift: root.contentShift
            transform: Translate { x: contentWrap.shift }
            Behavior on shift { NumberAnimation { duration: Theme.hoverDuration; easing.type: Easing.OutCubic } }

            RowLayout {
                anchors.fill: parent
                spacing: 0

                // Platform name in accent color so the user can quickly scan the
                // list for a specific service. Brightens on hover for feedback.
                Text {
                    Layout.preferredWidth: 200
                    text: root.platform
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    color: root.selected || root.isHovered ? Theme.accentBright : Theme.accent
                    elide: Text.ElideRight
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }

                // Monospace font ensures masked characters ("********") align
                // consistently across rows regardless of the underlying value length.
                // Each column uses its own accent family (teal for username, rose/violet
                // for password) so the three data domains are visually distinct.
                Text {
                    Layout.preferredWidth: 200
                    text: root.maskedUsername
                    font.family: Theme.fontMono
                    font.pixelSize: Theme.fontSizeMedium
                    color: root.selected || root.isHovered ? Theme.accent2 : Theme.accent2Dim
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }

                Text {
                    Layout.fillWidth: true
                    text: root.maskedPassword
                    font.family: Theme.fontMono
                    font.pixelSize: Theme.fontSizeMedium
                    color: root.selected || root.isHovered ? Theme.accent3 : Theme.accent3Dim
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
            }
        }

        // Full-row click/hover area
        MouseArea {
            id: mouseArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.clicked()
        }
    }
}
