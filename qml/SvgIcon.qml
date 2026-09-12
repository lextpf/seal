import QtQuick
import QtQuick.Controls.impl as Impl

/*!
 * \qmltype SvgIcon
 * \inqmlmodule seal
 * \brief Render a tinted SVG at the screen device pixel ratio.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Set the inherited source, color, width, and height. Width and height use logical
 * pixels; source rasterization multiplies them by the screen device pixel ratio.
 * The image preserves its aspect ratio within that area.
 *
 * This wrapper contains the dependency on the private QtQuick.Controls.impl IconImage
 * type. Check its inherited properties when upgrading Qt.
 */
Impl.IconImage {
    sourceSize: Qt.size(width * Screen.devicePixelRatio,
                        height * Screen.devicePixelRatio)
    fillMode: Image.PreserveAspectFit
}
