import QtQuick
import QtQuick.Controls.impl as Impl

Impl.IconImage {
    sourceSize: Qt.size(width * Screen.devicePixelRatio,
                        height * Screen.devicePixelRatio)
    fillMode: Image.PreserveAspectFit
}
