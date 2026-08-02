import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// One account pill in the grid: brand icon or monogram, shortened service label,
// and a warning marker when the record has no browser site binding. The chip is
// view-only. It emits clicked and doubleClicked; AccountsGrid and Main.qml turn
// those into AppViewModel calls.
Item {
    id: root

    required property int index               // Visual row in the filtered grid
    required property string platform         // Cleartext service name as stored
    required property string displayPlatform  // Chip label, subdomains and suffix removed
    required property string brandIconPath    // qrc path for the resolved brand icon, "" if no match
    required property string siteBinding      // Browser-binding host, "" when the label cannot bind
    required property string maskedUsername   // Bullet mask; model-role parity, not rendered
    required property string maskedPassword   // Bullet mask; model-role parity, not rendered
    required property int recordIndex         // Record index, stable across filter and sort
    required property bool selected           // Driven by the grid's selectedRow binding
    property bool isHovered: mouseArea.containsMouse

    readonly property string brandSlug: Theme.brandSlugFromPath(root.brandIconPath)
    readonly property color rawBaseColor: Theme.chipColorFor(root.platform, root.brandSlug)
    readonly property color baseColor: Theme.dark
                                       ? root.rawBaseColor
                                       : Theme.lightBrandColor(root.rawBaseColor,
                                                               root.brandSlug)
    readonly property color contrastText: Theme.chipTextOn(root.baseColor)
    readonly property int chipHeight: 36
    readonly property int iconFootprint: chipHeight - 12
    readonly property int maxTextWidth: 200

    signal clicked()
    signal doubleClicked()

    // Content-sized width: icon footprint + spacing + elided text + horizontal padding.
    implicitWidth: contentRow.implicitWidth + 24
    implicitHeight: chipHeight + 2  // +2 for the hover-lift transform headroom

    // Hover lift uses Translate so the surrounding Flow does not reflow.
    transform: Translate { y: root.isHovered && !root.selected ? -1 : 0 }
    Behavior on transform { NumberAnimation { duration: Theme.hoverDuration; easing.type: Easing.OutCubic } }

    Rectangle {
        id: pill
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        width: parent.width
        height: root.chipHeight
        radius: height / 2

        // Light mode uses higher alpha than dark so the brand tint stays visible
        // without washing out the account name.
        color: {
            var c = root.baseColor;
            if (Theme.dark) {
                if (root.selected) return Qt.rgba(c.r, c.g, c.b, 0.80);
                if (root.isHovered) return Qt.rgba(c.r, c.g, c.b, 0.22);
                return Qt.rgba(c.r, c.g, c.b, 0.12);
            }
            if (root.selected) return Qt.rgba(c.r, c.g, c.b, 0.88);
            if (root.isHovered) return Qt.rgba(c.r, c.g, c.b, 0.27);
            return Qt.rgba(c.r, c.g, c.b, 0.16);
        }
        border.width: Theme.strokeRegular
        border.color: {
            var c = root.baseColor;
            if (Theme.dark) {
                if (root.selected) return Qt.rgba(c.r, c.g, c.b, 1.0);
                if (root.isHovered) return Qt.rgba(c.r, c.g, c.b, 0.55);
                return Qt.rgba(c.r, c.g, c.b, 0.35);
            }
            if (root.selected) return c;
            if (root.isHovered) return Qt.rgba(c.r, c.g, c.b, 0.60);
            return Qt.rgba(c.r, c.g, c.b, 0.42);
        }

        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

        // Selection halo, drawn outside the pill and kept behind it with z: -1.
        Rectangle {
            anchors.fill: parent
            anchors.margins: -3
            radius: height / 2
            color: "transparent"
            border.width: Theme.strokeSelected
            border.color: {
                var c = root.baseColor;
                return Theme.dark
                    ? Qt.rgba(c.r, c.g, c.b, 0.35)
                    : Qt.rgba(c.r, c.g, c.b, 0.42);
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

                // Monogram fallback: first letter of the shortened display name.
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
                        text: root.displayPlatform.length > 0
                              ? root.displayPlatform.charAt(0).toUpperCase()
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
                text: root.displayPlatform
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                font.weight: Font.Medium
                color: root.selected ? root.contrastText : Theme.textPrimary
                elide: Text.ElideRight
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }

                // The label is shortened and may elide, so the tooltip carries the
                // stored service name.
                ToolTip.visible: root.isHovered &&
                                 (truncated || root.displayPlatform !== root.platform)
                ToolTip.text: root.platform
                ToolTip.delay: 400
            }

            // Warning marker for a record with no site binding. It can never release
            // into a browser, by auto-fill or by Ctrl+Click, because the strict host
            // gate refuses it. Only non-browser auto-type targets still fill.
            Item {
                visible: root.siteBinding === ""
                Layout.preferredWidth: visible ? Theme.px(12) : 0
                Layout.preferredHeight: Theme.px(12)
                Layout.alignment: Qt.AlignVCenter

                SvgIcon {
                    anchors.fill: parent
                    source: Theme.iconTriangleExclamation
                    color: root.selected ? root.contrastText : Theme.textWarning
                }

                HoverHandler { id: bindingHover }

                ToolTip.visible: bindingHover.hovered
                ToolTip.delay: 400
                ToolTip.text: "No site binding: browser auto-fill will not trigger for this " +
                              "label. Ctrl+Click auto-type still works; edit the service to " +
                              "a domain such as github.com to enable browser binding."
            }
        }

        // Covers the pill, not the lift headroom, and is the source of isHovered.
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
