pragma Singleton
import QtQuick

QtObject {
    id: root

    property real tidePhase: 0

    property real driftPhase: 0

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
