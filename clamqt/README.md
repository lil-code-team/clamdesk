# clamqt

GUI moderna em Qt 6 + QML para o ecossistema ClamAV.

## Estado atual

- Janela inicial com layout moderno.
- Fluxo de Quick Scan simulado via `ScanController`.
- Base pronta para integrar `clamscan`/`clamd` na proxima etapa.

## Requisitos

- Qt 6.5+ (Quick, Qml, QuickControls2)
- CMake 3.21+
- Compilador C++17

## Build (Windows)

```powershell
cmake -S clamqt -B build/clamqt -G Ninja -D CMAKE_BUILD_TYPE=Release
cmake --build build/clamqt --config Release
```

## Executar

```powershell
./build/clamqt/clamqt.exe
```
