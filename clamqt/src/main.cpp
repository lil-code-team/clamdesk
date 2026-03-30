#include <QGuiApplication>
#include <QDir>
#include <QFile>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQmlError>
#include <QStandardPaths>
#include <QTextStream>

#include "backend/ScanController.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    app.setWindowIcon(QIcon(QStringLiteral(":/qt/qml/ClamQt/src/assets/icon.png")));

    QQmlApplicationEngine engine;

    QString logDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (logDir.isEmpty()) {
        logDir = QDir::tempPath() + QStringLiteral("/clamqt");
    }
    QDir().mkpath(logDir);
    const QString logPath = QDir(logDir).filePath(QStringLiteral("startup-errors.log"));

    auto appendLog = [logPath](const QString &line) {
        QFile file(logPath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
            return;
        }
        QTextStream stream(&file);
        stream << line << '\n';
    };

    QFile::remove(logPath);

    QObject::connect(&engine, &QQmlApplicationEngine::warnings, &app, [appendLog](const QList<QQmlError> &warnings) {
        for (const QQmlError &warning : warnings) {
            appendLog(warning.toString());
        }
    });

    ScanController scanController;
    engine.rootContext()->setContextProperty(QStringLiteral("scanController"), &scanController);

    engine.loadFromModule(QStringLiteral("ClamQt"), QStringLiteral("Main"));
    if (engine.rootObjects().isEmpty()) {
        appendLog(QStringLiteral("rootObjects is empty after loadFromModule"));
        return -1;
    }

    return app.exec();
}
