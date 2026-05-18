import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Single chip in the accounts grid.
//
// Security: no plaintext credentials reach this component. The model exposes
// only the platform name plus a derived `brandIconPath`. Username/password
// roles still exist on the model for compatibility but this chip ignores them
// — the redesign treats the chip as a launcher for the existing Fill / Edit
// flow, where decryption happens in C++ on demand.
//
// Visual: pill-shaped, content-sized width with a 280px cap (then ellipsis +
// tooltip), height controlled by Theme.chipSize (28 = Compact, else 36 =
// Comfortable). Background is Theme.chipColorFor(platform) at increasing alpha
// across idle → hover → selected states. When brandIconPath is empty a
// monogram circle with the first letter of `platform` replaces the SVG icon.

Item {
    id: root

    required property int index           // Visual position in the filtered grid
    required property string platform     // Cleartext service name
    required property string brandIconPath  // qrc path for the resolved brand icon, "" if no match
    required property string maskedUsername  // Kept for model-role compatibility
    required property string maskedPassword  // Kept for model-role compatibility
    required property int recordIndex     // Stable index into Backend::m_Records
    required property bool selected       // Driven by parent's selectedRow binding
    property bool isHovered: mouseArea.containsMouse

    readonly property string brandSlug: Theme.brandSlugFromPath(root.brandIconPath)
    readonly property color baseColor: Theme.chipColorFor(root.platform, root.brandSlug)
    readonly property color contrastText: Theme.chipTextOn(root.baseColor)
    readonly property int chipHeight: 36
    readonly property int iconFootprint: chipHeight - 14
    readonly property int maxTextWidth: 200

    signal clicked()
    signal doubleClicked()

    // Content-sized width: icon footprint + spacing + ellided text + horizontal padding.
    implicitWidth: contentRow.implicitWidth + 24
    implicitHeight: chipHeight + 2  // +2 for the hover-lift transform headroom

    // Hover lift via Translate so the layout doesn't reflow.
    transform: Translate { y: root.isHovered && !root.selected ? -1 : 0 }
    Behavior on transform { NumberAnimation { duration: Theme.hoverDuration; easing.type: Easing.OutCubic } }

    Rectangle {
        id: pill
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        width: parent.width
        height: root.chipHeight
        radius: height / 2

        // Idle / hover / selected fill alphas.
        color: {
            var c = root.baseColor;
            if (root.selected) return Qt.rgba(c.r, c.g, c.b, 0.80);
            if (root.isHovered) return Qt.rgba(c.r, c.g, c.b, 0.22);
            return Qt.rgba(c.r, c.g, c.b, 0.12);
        }
        border.width: 1
        border.color: {
            var c = root.baseColor;
            if (root.selected) return Qt.rgba(c.r, c.g, c.b, 1.0);
            if (root.isHovered) return Qt.rgba(c.r, c.g, c.b, 0.55);
            return Qt.rgba(c.r, c.g, c.b, 0.35);
        }

        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

        // Selection outer glow ring: adapts the technique from the legacy
        // AccountRow selection glow (gradient fade from colored to transparent)
        // but wraps the pill rather than running across the row.
        Rectangle {
            anchors.fill: parent
            anchors.margins: -3
            radius: height / 2
            color: "transparent"
            border.width: 3
            border.color: {
                var c = root.baseColor;
                return Qt.rgba(c.r, c.g, c.b, 0.35);
            }
            opacity: root.selected ? 1.0 : 0.0
            Behavior on opacity { NumberAnimation { duration: 200 } }
            z: -1
        }

        RowLayout {
            id: contentRow
            anchors.fill: parent
            anchors.leftMargin: 10
            anchors.rightMargin: 14
            spacing: 6

            // Icon slot: SvgIcon when brandIconPath is non-empty, else monogram circle.
            Item {
                Layout.preferredWidth: root.iconFootprint
                Layout.preferredHeight: root.iconFootprint
                Layout.alignment: Qt.AlignVCenter

                SvgIcon {
                    anchors.centerIn: parent
                    source: root.brandIconPath
                    width: parent.width
                    height: parent.height
                    color: root.selected ? root.contrastText : root.baseColor
                    visible: root.brandIconPath !== ""
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }

                // Monogram fallback: first letter of platform in a filled circle.
                Rectangle {
                    anchors.fill: parent
                    radius: width / 2
                    color: root.selected
                           ? root.contrastText
                           : root.baseColor
                    visible: root.brandIconPath === ""
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }

                    Text {
                        anchors.centerIn: parent
                        text: root.platform.length > 0
                              ? root.platform.charAt(0).toUpperCase()
                              : "?"
                        font.family: Theme.fontFamily
                        font.pixelSize: Math.max(8, parent.height - 8)
                        font.weight: Font.Bold
                        color: root.selected ? root.baseColor : root.contrastText
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }
                }
            }

            Text {
                Layout.alignment: Qt.AlignVCenter
                Layout.maximumWidth: root.maxTextWidth
                text: root.platform
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                font.weight: Font.Medium
                color: root.selected ? root.contrastText : Theme.textPrimary
                elide: Text.ElideRight
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }

                // Tooltip with the full name when the text was elided.
                ToolTip.visible: root.isHovered && truncated
                ToolTip.text: root.platform
                ToolTip.delay: 400
            }
        }

        // Full-pill click area with both single and double click handling.
        MouseArea {
            id: mouseArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            acceptedButtons: Qt.LeftButton
            onClicked: root.clicked()
            onDoubleClicked: root.doubleClicked()
        }
    }
}
