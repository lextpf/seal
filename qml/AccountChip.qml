import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

/*!
 * \qmltype AccountChip
 * \inqmlmodule seal
 * \brief Display a credential label and emit selection gestures.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * The grid supplies non-secret model roles and the selection state.
 * This control displays the service label, brand icon, and site-binding warning.
 * It neither reads credentials nor starts a fill operation.
 *
 * Row and record indices belong to the current model snapshot. The owner must
 * refresh them after a workspace mutation, including save-time deletion compaction.
 */
Item {
    id: root

    /*!
     * Zero-based row in the filtered, sorted grid; changes when the model refreshes.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property int index
    /*!
     * Full stored service label, used for the tooltip and fallback brand color.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property string platform
    /*!
     * Short display label; an empty value uses a question mark in the fallback icon.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property string displayPlatform
    /*!
     * Resource path; an empty value selects a character as the fallback icon.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property string brandIconPath
    /*!
     * Validated browser host. An empty value shows the unbound-record warning.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property string siteBinding
    /*!
     * Fixed username mask from the model; accepted for role parity and not displayed.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property string maskedUsername
    /*!
     * Fixed password mask from the model; accepted for role parity and not displayed.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property string maskedPassword
    /*!
     * Backing record index. Filtering and sorting preserve it; workspace mutations may not.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property int recordIndex
    /*!
     * Owner-supplied selection state; gestures do not change it locally.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    required property bool selected
    /*!
     * Pointer is inside the pill's hit area, which excludes the hover-lift headroom.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool isHovered: mouseArea.containsMouse

    readonly property string brandSlug: Theme.brandSlugFromPath(root.brandIconPath)
    readonly property color rawBaseColor: Theme.chipColorFor(root.platform, root.brandSlug)
    readonly property color baseColor: Theme.dark
                                       ? root.rawBaseColor
                                       : Theme.lightBrandColor(root.rawBaseColor,
                                                               root.brandSlug)
    readonly property color contrastText: Theme.chipTextOn(root.baseColor)
    /*!
     * Pill height in logical pixels, excluding the two-pixel hover-lift headroom.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int chipHeight: 36
    /*!
     * Reserved icon width and height in logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int iconFootprint: chipHeight - 12
    /*!
     * Maximum label width in logical pixels; longer labels elide on the right.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int maxTextWidth: 200

    /*!
     * \brief Notify the owner of a left-button click inside the pill.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal clicked()
    /*!
     * \brief Notify the owner of a left-button double-click inside the pill.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal doubleClicked()

    implicitWidth: contentRow.implicitWidth + 24
    implicitHeight: chipHeight + 2  // Reserve headroom for the hover-lift transform.

    // Translate lifts the chip without reflowing its Flow.
    transform: Translate { y: root.isHovered && !root.selected ? -1 : 0 }
    Behavior on transform { NumberAnimation { duration: Theme.hoverDuration; easing.type: Easing.OutCubic } }

    Rectangle {
        id: pill
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        width: parent.width
        height: root.chipHeight
        radius: height / 2

        // Higher light-mode alpha keeps the brand tint visible.
        color: {
            var c = root.baseColor;
            if (Theme.dark) {
                if (root.selected) return Qt.rgba(c.r, c.g, c.b, 0.80);
                if (root.isHovered) return Qt.rgba(c.r, c.g, c.b, 0.32);
                return Qt.rgba(c.r, c.g, c.b, 0.22);
            }
            if (root.selected) return Qt.rgba(c.r, c.g, c.b, 0.88);
            if (root.isHovered) return Qt.rgba(c.r, c.g, c.b, 0.34);
            return Qt.rgba(c.r, c.g, c.b, 0.24);
        }

        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }

        RowLayout {
            id: contentRow
            anchors.fill: parent
            anchors.leftMargin: 10
            anchors.rightMargin: 14
            spacing: 6

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

                // Preserve the full stored label when display text is shortened.
                ToolTip.visible: root.isHovered &&
                                 (truncated || root.displayPlatform !== root.platform)
                ToolTip.text: root.platform
                ToolTip.delay: 400
            }

            // An unbound record cannot fill browser fields; non-browser auto-type remains
            // available.
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

        // Exclude the lift headroom from the hit area.
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
