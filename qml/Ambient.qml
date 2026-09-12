pragma Singleton
import QtQuick

/*!
 * \qmltype Ambient
 * \inqmlmodule seal
 * \brief Supply shared animation phases for decorative motion.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Bind decorative items to these phases to share two animation clocks. Main controls
 * \c awake when the window visibility changes. Consumers must handle reduced motion.
 * Singleton registration requires \c QT_QML_SINGLETON_TYPE in CMakeLists.txt.
 */
QtObject {
    id: root

    /*!
     * Phase in radians. Advances from 0 to 2 * pi every 50 seconds while awake.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property real tidePhase: 0

    /*!
     * Phase in radians. Advances from 0 to 2 * pi every 40 seconds while awake.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property real driftPhase: 0

    /*!
     * When false, stop both clocks. Main disables motion when hidden or minimized.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
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
