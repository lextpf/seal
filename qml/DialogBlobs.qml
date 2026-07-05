import QtQuick

Item {
    anchors.fill: parent
    z: -1

    Rectangle {
        width: 150; height: 150; radius: 75
        x: parent.width * 0.62; y: parent.height * -0.12
        color: Theme.dialogBlobColor2
        Behavior on color { ColorAnimation { duration: 350 } }
    }
    Rectangle {
        width: 180; height: 180; radius: 90
        x: parent.width * 0.04; y: parent.height * 0.55
        color: Theme.dialogBlobColor3
        Behavior on color { ColorAnimation { duration: 350 } }
    }
    Rectangle {
        width: 140; height: 140; radius: 70
        x: parent.width * 0.72; y: parent.height * 0.48
        color: Theme.dialogBlobColor1
        Behavior on color { ColorAnimation { duration: 350 } }
    }
    Rectangle {
        width: 120; height: 120; radius: 60
        x: parent.width * 0.38; y: parent.height * 0.80
        color: Theme.dialogBlobColor2
        Behavior on color { ColorAnimation { duration: 350 } }
    }
}
