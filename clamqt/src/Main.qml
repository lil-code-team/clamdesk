import QtQuick
import QtQuick.Window
import QtQuick.Controls

Window {
    id: root
    visible: true
    title: "ClamDesk"
    width: 1000
    height: 640
    minimumWidth: 1000
    minimumHeight: 640
    maximumWidth: 1000
    maximumHeight: 640
    color: theme.black

    QtObject {
        id: theme

        readonly property color white: "#fff"
        readonly property color white_50: "#f9f9fb"
        readonly property color white_100: "#f4f4f7"
        readonly property color white_200: "#ededf3"
        readonly property color white_300: "#e6e6ec"
        readonly property color white_400: "#dddddf"

        readonly property color border_50: "#d9d9d9"

        readonly property color gray_50: "#d4cce2"
        readonly property color gray_100: "#beb6ca"
        readonly property color gray_200: "#b3aabe"
        readonly property color gray_300: "#a79db2"
        readonly property color gray_400: "#9a8fa5"
        readonly property color gray_500: "#8c8197"
        readonly property color gray_600: "#766c80"
        readonly property color gray_700: "#5e5667"
        readonly property color gray_800: "#47414e"
        readonly property color gray_900: "#2a292c"

        readonly property color black: "#242127"

        readonly property color green_50: "#e5f6f2"
        readonly property color green_100: "#c9ece4"
        readonly property color green_200: "#9fdccd"
        readonly property color green_300: "#75ccb6"
        readonly property color green_400: "#4dbca0"
        readonly property color green_500: "#2f8f7a"
        readonly property color green_600: "#277b6a"
        readonly property color green_700: "#206759"
        readonly property color green_800: "#1a5248"
        readonly property color green_900: "#143f39"

        readonly property color purple_50: "#faf5ff"
        readonly property color purple_100: "#e9d8fd"
        readonly property color purple_200: "#d6bcfa"
        readonly property color purple_300: "#b794f4"
        readonly property color purple_400: "#9f7aea"
        readonly property color purple_500: "#8a38f5"
        readonly property color purple_600: "#7c3aed"
        readonly property color purple_700: "#6b21cc"
        readonly property color purple_800: "#5b1ea8"
        readonly property color purple_900: "#43167f"

        readonly property color blue_50: "#e1ecfa"
        readonly property color blue_100: "#b9d1f0"
        readonly property color blue_200: "#97bff0"
        readonly property color blue_300: "#6aa5e8"
        readonly property color blue_400: "#4389df"
        readonly property color blue_500: "#266ecd"
        readonly property color blue_600: "#205eb1"
        readonly property color blue_700: "#1b4f96"
        readonly property color blue_800: "#153e77"
        readonly property color blue_900: "#102e5a"

        readonly property color yellow_50: "#fff8e1"
        readonly property color yellow_100: "#ffecb3"
        readonly property color yellow_200: "#ffe082"
        readonly property color yellow_300: "#ffd54f"
        readonly property color yellow_400: "#ffca28"
        readonly property color yellow_500: "#f5c542"
        readonly property color yellow_600: "#e0ac2f"
        readonly property color yellow_700: "#c6921f"
        readonly property color yellow_800: "#9c7212"
        readonly property color yellow_900: "#7a570b"

        readonly property color red_100: "#fee2e2"
        readonly property color red_200: "#fecaca"
        readonly property color red_300: "#fca5a5"
        readonly property color red_500: "#f43f5e"
    }

    property int currentScreen: 0
    property var profileItems: [
        {
            key: "low",
            label: "Baixo",
            cardColor: theme.blue_100,
            strokeColor: theme.blue_800
        },
        {
            key: "balanced",
            label: "Balanceado",
            cardColor: theme.yellow_100,
            strokeColor: theme.yellow_800
        },
        {
            key: "rigorous",
            label: "Rigoroso",
            cardColor: theme.purple_100,
            strokeColor: theme.purple_800
        }
    ]
    property string manualScanPath: ""

    Component.onCompleted: {
        scanController.selectProfile(scanController.selectedProfile)
        scanController.refreshDashboard()
    }

    Item {
        id: homeScreen
        anchors.fill: parent
        visible: root.currentScreen === 0
        opacity: visible ? 1.0 : 0.0

        Behavior on opacity {
            NumberAnimation { duration: 140 }
        }

        Column {
            anchors.fill: parent
            anchors.margins: 22
            spacing: 14

            Row {
                spacing: 12

                Image {
                    source: "qrc:/qt/qml/ClamQt/src/assets/clam-desk.png"
                    width: 72
                    height: 72
                    fillMode: Image.PreserveAspectFit
                }

                Column {
                    spacing: 6

                    Text {
                        color: theme.white_100
                        font.family: "Roboto Mono"
                        font.pixelSize: 20
                        font.weight: Font.Bold
                        text: "Central do ClamAV"
                    }

                    Text {
                        color: theme.gray_100
                        font.family: "Roboto Mono"
                        font.pixelSize: 10
                        text: "Scans, firewall e operacoes do antivirus em um unico painel"
                    }

                    Text {
                        color: theme.gray_300
                        font.family: "Roboto Mono"
                        font.pixelSize: 10
                        text: "Perfil ativo: " + scanController.selectedProfile
                    }
                }
            }

            Row {
                spacing: 8

                Button {
                    text: "Scan Home"
                    enabled: !scanController.commandRunning
                    onClicked: scanController.runAction("scan-home")
                }

                Button {
                    text: "Scan Completo"
                    enabled: !scanController.commandRunning
                    onClicked: scanController.runAction("scan-full")
                }

                Button {
                    text: "Scan Pasta"
                    enabled: !scanController.commandRunning
                    onClicked: scanController.scanFolder(root.manualScanPath)
                }

                Button {
                    text: "Atualizar DB"
                    enabled: !scanController.commandRunning
                    onClicked: scanController.runAction("update-db")
                }

                Button {
                    text: "Versao"
                    enabled: !scanController.commandRunning
                    onClicked: scanController.runAction("check-version")
                }

                Button {
                    text: "Daemon"
                    enabled: !scanController.commandRunning
                    onClicked: scanController.runAction("start-daemon")
                }

                Button {
                    text: "Perfis"
                    onClicked: root.currentScreen = 1
                }
            }

            Row {
                spacing: 8

                TextField {
                    id: scanPathField
                    width: 460
                    placeholderText: "Digite o caminho da pasta (ex: C:/Users/migue/Documents)"
                    text: root.manualScanPath
                    onTextChanged: root.manualScanPath = text
                }

                Button {
                    text: "Usar Home"
                    onClicked: {
                        root.manualScanPath = ""
                        scanPathField.text = ""
                    }
                }
            }

            Row {
                spacing: 12

                Rectangle {
                    width: (root.width - 56) * 0.58
                    height: 360
                    radius: 12
                    color: theme.gray_900
                    border.width: 1
                    border.color: theme.gray_700

                    Column {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 8

                        Text {
                            color: theme.white_100
                            font.family: "Roboto Mono"
                            font.pixelSize: 13
                            font.weight: Font.Bold
                            text: "Historico de scans"
                        }

                        Rectangle {
                            width: parent.width
                            height: 1
                            color: theme.gray_700
                        }

                        ListView {
                            id: scanHistoryList
                            width: parent.width
                            height: parent.height - 46
                            clip: true
                            spacing: 6
                            model: scanController.scanHistory

                            delegate: Rectangle {
                                width: scanHistoryList.width
                                height: 58
                                radius: 8
                                color: theme.black
                                border.width: 1
                                border.color: theme.gray_700

                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 8
                                    spacing: 2

                                    Row {
                                        spacing: 8
                                        Text {
                                            color: theme.white_300
                                            font.family: "Roboto Mono"
                                            font.pixelSize: 10
                                            text: modelData.time
                                        }
                                        Text {
                                            color: modelData.result === "ok" ? theme.green_300 : (modelData.result === "infectado" ? theme.red_300 : theme.yellow_300)
                                            font.family: "Roboto Mono"
                                            font.pixelSize: 10
                                            font.weight: Font.Bold
                                            text: modelData.result
                                        }
                                    }

                                    Text {
                                        color: theme.gray_100
                                        font.family: "Roboto Mono"
                                        font.pixelSize: 10
                                        elide: Text.ElideRight
                                        text: modelData.target
                                    }

                                    Text {
                                        color: theme.gray_300
                                        font.family: "Roboto Mono"
                                        font.pixelSize: 9
                                        elide: Text.ElideRight
                                        text: modelData.details
                                    }
                                }
                            }

                            Text {
                                anchors.centerIn: parent
                                visible: scanHistoryList.count === 0
                                color: theme.gray_400
                                font.family: "Roboto Mono"
                                font.pixelSize: 10
                                text: "Sem historico de scans ainda."
                            }
                        }
                    }
                }

                Rectangle {
                    width: (root.width - 56) * 0.42
                    height: 360
                    radius: 12
                    color: theme.gray_900
                    border.width: 1
                    border.color: theme.gray_700

                    Column {
                        anchors.fill: parent
                        anchors.margins: 10
                        spacing: 8

                        Text {
                            color: theme.white_100
                            font.family: "Roboto Mono"
                            font.pixelSize: 13
                            font.weight: Font.Bold
                            text: "Relatorio de firewall"
                        }

                        Rectangle {
                            width: parent.width
                            height: 1
                            color: theme.gray_700
                        }

                        ListView {
                            id: firewallList
                            width: parent.width
                            height: 232
                            clip: true
                            spacing: 6
                            model: scanController.firewallReport

                            delegate: Rectangle {
                                width: firewallList.width
                                height: 52
                                radius: 8
                                color: theme.black
                                border.width: 1
                                border.color: theme.gray_700

                                Column {
                                    anchors.fill: parent
                                    anchors.margins: 8
                                    spacing: 2

                                    Text {
                                        color: theme.white_300
                                        font.family: "Roboto Mono"
                                        font.pixelSize: 10
                                        text: modelData.time
                                    }

                                    Text {
                                        color: theme.gray_100
                                        font.family: "Roboto Mono"
                                        font.pixelSize: 10
                                        elide: Text.ElideRight
                                        text: modelData.event + " | " + modelData.severity
                                    }

                                    Text {
                                        color: theme.gray_300
                                        font.family: "Roboto Mono"
                                        font.pixelSize: 9
                                        elide: Text.ElideRight
                                        text: modelData.details
                                    }
                                }
                            }

                            Text {
                                anchors.centerIn: parent
                                visible: firewallList.count === 0
                                color: theme.gray_400
                                font.family: "Roboto Mono"
                                font.pixelSize: 10
                                text: "Sem eventos de firewall no momento."
                            }
                        }

                        Button {
                            text: "Atualizar painel"
                            onClicked: scanController.refreshDashboard()
                        }
                    }
                }
            }

            Rectangle {
                width: parent.width
                height: 78
                radius: 10
                color: theme.gray_900
                border.width: 1
                border.color: theme.gray_700

                Column {
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 4

                    Text {
                        color: theme.white_200
                        font.family: "Roboto Mono"
                        font.pixelSize: 11
                        font.weight: Font.Bold
                        text: scanController.commandRunning ? "Saida em tempo real do ultimo comando" : "Resumo do ultimo comando"
                    }

                    Text {
                        color: theme.gray_100
                        font.family: "Roboto Mono"
                        font.pixelSize: 9
                        wrapMode: Text.WordWrap
                        elide: Text.ElideRight
                        text: scanController.lastCommandOutput.length > 0 ? scanController.lastCommandOutput : "Nenhum comando executado ainda."
                    }
                }
            }
        }

    }

    Item {
        id: profileScreen
        anchors.fill: parent
        visible: root.currentScreen === 1
        opacity: visible ? 1.0 : 0.0

        Behavior on opacity {
            NumberAnimation { duration: 140 }
        }

        Column {
            anchors.centerIn: parent
            spacing: 47

            Column {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: 30

                Row {
                    anchors.horizontalCenter: parent.horizontalCenter
                    spacing: 50

                    Repeater {
                        model: root.profileItems

                        delegate: Rectangle {
                            width: 80
                            height: 80
                            radius: 20
                            color: modelData.cardColor
                            border.width: scanController.selectedProfile === modelData.key ? 4 : 0
                            border.color: theme.gray_900

                            FeatherIcon {
                                anchors.centerIn: parent
                                name: "shield"
                                iconSize: 40
                                strokeColor: modelData.strokeColor
                                strokeWidth: 2.5
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    scanController.selectProfile(modelData.key)
                                }
                            }
                        }
                    }
                }

                Row {
                    anchors.horizontalCenter: parent.horizontalCenter
                    spacing: 50

                    Repeater {
                        model: root.profileItems

                        delegate: Text {
                            width: 80
                            horizontalAlignment: Text.AlignHCenter
                            color: scanController.selectedProfile === modelData.key ? theme.white : theme.white_200
                            font.family: "Roboto Mono"
                            font.pixelSize: 30 * 0.47
                            font.weight: Font.Bold
                            text: modelData.label
                        }
                    }
                }

                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    color: "transparent"
                    radius: 8
                    border.width: 1
                    border.color: theme.gray_700
                    width: advancedRow.implicitWidth + 20
                    height: advancedRow.implicitHeight + 12

                    Row {
                        id: advancedRow
                        anchors.centerIn: parent
                        spacing: 5

                        Text {
                            color: theme.gray_100
                            font.family: "Roboto Mono"
                            font.pixelSize: 10
                            font.weight: Font.Bold
                            text: "configuração avançada"
                        }

                        FeatherIcon {
                            name: "chevron-right"
                            iconSize: 10
                            strokeColor: theme.gray_100
                            strokeWidth: 1.5
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.currentScreen = 2
                    }
                }
            }

            Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                width: 35
                height: 35
                radius: 12
                color: theme.purple_300

                FeatherIcon {
                    anchors.centerIn: parent
                    name: "chevron-right"
                    iconSize: 24
                    strokeColor: theme.purple_900
                    strokeWidth: 2
                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.currentScreen = 0
                }
            }
        }
    }

    Item {
        id: advancedScreen
        anchors.fill: parent
        visible: root.currentScreen === 2
        opacity: visible ? 1.0 : 0.0

        Behavior on opacity {
            NumberAnimation { duration: 140 }
        }

        Rectangle {
            anchors.fill: parent
            color: theme.black

            Column {
                anchors.fill: parent
                anchors.margins: 24
                spacing: 14

                Text {
                    color: theme.white_200
                    font.family: "Roboto Mono"
                    font.pixelSize: 18
                    font.weight: Font.Bold
                    text: "Configuracoes avancadas"
                }

                Text {
                    color: theme.gray_100
                    font.family: "Roboto Mono"
                    font.pixelSize: 10
                    font.weight: Font.Light
                    text: "Ajuste parametro por parametro. As alteracoes sao aplicadas no arquivo gerado automaticamente."
                }

                Rectangle {
                    width: parent.width
                    height: 1
                    color: theme.gray_700
                }

                Flickable {
                    id: optionsFlick
                    width: parent.width
                    height: parent.height - 150
                    clip: true
                    contentWidth: width
                    contentHeight: optionsColumn.implicitHeight

                    Column {
                        id: optionsColumn
                        width: optionsFlick.width
                        spacing: 10

                        Repeater {
                            model: scanController.advancedOptions

                            delegate: Rectangle {
                                width: optionsColumn.width
                                color: theme.gray_900
                                radius: 10
                                border.width: 1
                                border.color: theme.gray_700
                                implicitHeight: contentColumn.implicitHeight + 16

                                Column {
                                    id: contentColumn
                                    anchors.fill: parent
                                    anchors.margins: 8
                                    spacing: 6

                                    Text {
                                        color: theme.white_100
                                        font.family: "Roboto Mono"
                                        font.pixelSize: 12
                                        font.weight: Font.Bold
                                        text: modelData.label
                                    }

                                    Text {
                                        color: theme.gray_100
                                        font.family: "Roboto Mono"
                                        font.pixelSize: 10
                                        font.weight: Font.Light
                                        wrapMode: Text.WordWrap
                                        text: modelData.description
                                    }

                                    Row {
                                        spacing: 8

                                        Text {
                                            color: theme.gray_400
                                            font.family: "Roboto Mono"
                                            font.pixelSize: 10
                                            font.weight: Font.Light
                                            text: modelData.key
                                        }

                                        Rectangle {
                                            width: 1
                                            height: 12
                                            color: theme.gray_700
                                        }

                                        Loader {
                                            sourceComponent: modelData.type === "bool" ? boolControl : textControl

                                            property var optionData: modelData
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                Row {
                    spacing: 10

                    Button {
                        text: "Voltar"
                        onClicked: root.currentScreen = 1
                    }

                    Button {
                        text: "Restaurar perfil"
                        onClicked: scanController.resetAdvancedOptions()
                    }

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        color: theme.gray_400
                        font.family: "Roboto Mono"
                        font.pixelSize: 9
                        font.weight: Font.Light
                        text: "Arquivo: " + scanController.generatedConfigPath
                    }
                }
            }
        }
    }

    Component {
        id: boolControl

        Switch {
            checked: !!parent.optionData.value
            onToggled: {
                scanController.setAdvancedOption(parent.optionData.key, checked)
            }
        }
    }

    Component {
        id: textControl

        TextField {
            width: 140
            text: String(parent.optionData.value)
            color: theme.white_100
            placeholderTextColor: theme.gray_400
            selectedTextColor: theme.white
            selectionColor: theme.purple_800
            background: Rectangle {
                radius: 6
                border.color: theme.gray_700
                color: theme.black
            }

            onEditingFinished: {
                if (parent.optionData.type === "int") {
                    scanController.setAdvancedOption(parent.optionData.key, Number(text))
                } else {
                    scanController.setAdvancedOption(parent.optionData.key, text)
                }
            }
        }
    }

    Text {
        anchors.left: parent.left
        anchors.leftMargin: 14
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 14
        color: theme.gray_400
        font.family: "Roboto Mono"
        font.pixelSize: 10
        font.weight: Font.Light
        text: scanController.statusText
    }

    Text {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 14
        color: theme.gray_400
        font.family: "Roboto Mono"
        font.pixelSize: 10
        font.weight: Font.Light
        textFormat: Text.RichText
        text: "powered by <a href=\"https://lilcode.team\" style=\"color:" + String(theme.purple_300) + ";text-decoration:none;\">lilcode.team</a>"
        onLinkActivated: function(link) {
            Qt.openUrlExternally(link)
        }
    }
}