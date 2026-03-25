import QtQuick
import QtQuick.Controls.impl as Impl

// Thin wrapper around Qt's IconImage for runtime SVG color tinting.
//
// Why not plain Image? Image renders SVGs at their intrinsic size and rasterizes
// at load time, so recoloring requires a different asset per color. IconImage
// (from QtQuick.Controls.impl) supports a `color` property that tints the SVG
// at render time, allowing a single monochrome SVG asset to be reused across
// themes and states (normal, hover, disabled, accent, etc.).
//
// sourceSize is scaled by the device pixel ratio so the SVG rasterizes at
// native pixel density - sharp on HiDPI displays, no overdraw on 1x screens.

Impl.IconImage {
    sourceSize: Qt.size(width * Screen.devicePixelRatio,
                        height * Screen.devicePixelRatio)
    fillMode: Image.PreserveAspectFit
}
