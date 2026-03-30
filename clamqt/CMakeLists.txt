cmake_minimum_required(VERSION 3.21)

project(clamqt VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 6.5 REQUIRED COMPONENTS Quick Qml QuickControls2)

file(GLOB FEATHER_ICON_RESOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/assets/feather/*.svg")

qt_standard_project_setup(REQUIRES 6.5)

qt_add_executable(clamqt
    src/main.cpp
    src/backend/ScanController.h
    src/backend/ScanController.cpp
)

qt_add_qml_module(clamqt
    URI ClamQt
    VERSION 1.0
    QML_FILES
        src/Main.qml
        src/FeatherIcon.qml
    RESOURCES
        src/assets/clam-desk.png
        src/assets/icon.png
        ${FEATHER_ICON_RESOURCES}
)

target_link_libraries(clamqt
    PRIVATE
        Qt6::Quick
        Qt6::Qml
        Qt6::QuickControls2
)

set_target_properties(clamqt PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)

install(TARGETS clamqt
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)
