import QtQuick
import QtQuick.Controls.impl as Impl

// Tintable icon: set `source` to an SVG path and `color` to recolor it. The SVG
// is rasterised at the screen device pixel ratio, so it stays sharp above 100%
// Windows scaling. IconImage lives in QtQuick.Controls.impl, a private Qt
// module, so a Qt upgrade can change it - keep this wrapper as the only user.
Impl.IconImage {
    sourceSize: Qt.size(width * Screen.devicePixelRatio,
                        height * Screen.devicePixelRatio)
    fillMode: Image.PreserveAspectFit
}
