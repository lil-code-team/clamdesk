import QtQuick
import QtQuick.Effects

Item {
    id: root

    property string name: "chevron-right"
    property color strokeColor: "#43167F"
    property real strokeWidth: 2
    property real iconSize: 24
    readonly property string iconSource: name.endsWith(".svg")
                                       ? Qt.resolvedUrl("assets/feather/" + name)
                                       : Qt.resolvedUrl("assets/feather/" + name + ".svg")

    width: iconSize
    height: iconSize

    Image {
        id: iconImage
        anchors.fill: parent
        source: root.iconSource
        fillMode: Image.PreserveAspectFit
        smooth: true
        mipmap: true
        sourceSize.width: root.width
        sourceSize.height: root.height
        visible: false
    }

    MultiEffect {
        anchors.fill: parent
        source: iconImage
        colorization: 1.0
        colorizationColor: root.strokeColor
    }
}