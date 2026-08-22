pragma Singleton
import QtQuick

// The shared clock for decorative motion. Blobs, motes and dialog ripples bind
// to these phases instead of running their own animations, so the whole window
// stays in step and the drifting field costs two running animations instead of
// one per item. Singleton
// status needs both the pragma above and QT_QML_SINGLETON_TYPE TRUE on
// qml/Ambient.qml in CMakeLists.txt.
QtObject {
    id: root

    property real tidePhase: 0   // Main clock: 0 -> 2*PI every 50 s.

    property real driftPhase: 0  // Second, out-of-step clock: 0 -> 2*PI every 40 s.

    // Main.qml binds this to window visibility and the loading overlay. False
    // stops both animations, so a hidden, minimised or covered window renders
    // no decorative frames and every bound item freezes at its current pose.
    property bool awake: true

    property NumberAnimation _tide: NumberAnimation {
        target: root; property: "tidePhase"
        running: root.awake
        from: 0; to: 2 * Math.PI
        duration: 50000
        loops: Animation.Infinite
    }

    property NumberAnimation _drift: NumberAnimation {
        target: root; property: "driftPhase"
        running: root.awake
        from: 0; to: 2 * Math.PI
        duration: 40000
        loops: Animation.Infinite
    }
}
