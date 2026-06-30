pragma Singleton
import QtQuick

// Shared ambient-motion clock. One source of "tide" so every idle surface
// (background blobs, narwhal, glass sheen, chips) breathes to the same rhythm
// rather than each running its own timer -- coherence is what keeps app-wide
// ambient motion reading as calm instead of busy.
//
// Registered as a singleton in TWO places (exactly like Theme): `pragma
// Singleton` above AND QT_QML_SINGLETON_TYPE on this file in CMakeLists.txt.
// Animations are declared as object-valued properties (the same trick Theme
// uses for its FontLoader/Settings) because QtObject has no default child list.
QtObject {
    id: root

    // Master swell. Consumers read Math.sin(tidePhase * k + phi) with INTEGER k
    // so the value lands on its start at the 2*pi wrap (seamless loop). Very
    // slow (~50s) so the blobs drift at a calm, barely-there pace.
    property real tidePhase: 0

    // Slower, lazier rhythm for things that should glide rather than bob: the
    // caustic light wash and the glass sheen. A separate period stops the whole
    // scene pulsing in unison.
    property real driftPhase: 0

    // Gate. Bound by Main to window visibility so the clocks (and everything
    // reading them) idle when the window is hidden or minimized.
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
