#pragma once

#include <QObject>
#include <QProcess>
#include <QVariantList>

class QDir;

class ScanController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool scanning READ scanning NOTIFY scanningChanged)
    Q_PROPERTY(QString lastScanPath READ lastScanPath NOTIFY lastScanPathChanged)
    Q_PROPERTY(QString selectedProfile READ selectedProfile NOTIFY selectedProfileChanged)
    Q_PROPERTY(QVariantList advancedOptions READ advancedOptions NOTIFY advancedOptionsChanged)
    Q_PROPERTY(QString generatedConfigPath READ generatedConfigPath NOTIFY generatedConfigPathChanged)
    Q_PROPERTY(QVariantList scanHistory READ scanHistory NOTIFY scanHistoryChanged)
    Q_PROPERTY(QVariantList firewallReport READ firewallReport NOTIFY firewallReportChanged)
    Q_PROPERTY(QString lastCommandOutput READ lastCommandOutput NOTIFY lastCommandOutputChanged)
    Q_PROPERTY(bool commandRunning READ commandRunning NOTIFY commandRunningChanged)

public:
    explicit ScanController(QObject *parent = nullptr);

    QString statusText() const;
    bool scanning() const;
    QString lastScanPath() const;
    QString selectedProfile() const;
    QVariantList advancedOptions() const;
    QString generatedConfigPath() const;
    QVariantList scanHistory() const;
    QVariantList firewallReport() const;
    QString lastCommandOutput() const;
    bool commandRunning() const;

    Q_INVOKABLE void quickScan(const QString &path);
    Q_INVOKABLE void selectProfile(const QString &profile);
    Q_INVOKABLE void setAdvancedOption(const QString &key, const QVariant &value);
    Q_INVOKABLE void resetAdvancedOptions();
    Q_INVOKABLE void refreshDashboard();
    Q_INVOKABLE void scanFolder(const QString &path);
    Q_INVOKABLE void runAction(const QString &action);

signals:
    void scanningChanged();
    void lastScanPathChanged();
    void selectedProfileChanged();
    void advancedOptionsChanged();
    void generatedConfigPathChanged();
    void scanHistoryChanged();
    void firewallReportChanged();
    void lastCommandOutputChanged();
    void commandRunningChanged();

private:
    struct AdvancedOption {
        QString key;
        QString label;
        QString description;
        QString type;
        QVariant value;
    };

    void initAdvancedOptions();
    void applyProfileDefaults(const QString &profile);
    void updateAdvancedOption(const QString &key, const QVariant &value);
    QString normalizeProfile(const QString &profile) const;
    QString profileDisplayName() const;
    QString boolToYesNo(bool value) const;
    QString ensureConfigDirectory() const;
    QString historyFilePath() const;
    QString firewallFilePath() const;
    void loadScanHistory();
    void loadFirewallReport();
    void appendScanHistory(const QString &target, const QString &result, const QString &details);
    void runClamCommand(const QString &program, const QStringList &arguments, const QString &action, const QString &target = QString());
    QString summarizeOutput(const QString &output) const;
    QString executableName(const QString &name) const;
    bool isScanAction(const QString &action) const;
    QString defaultScanPath() const;
    void writeGeneratedConfig();
    void finishCommand(const QString &action, const QString &target, int exitCode, QProcess::ExitStatus exitStatus, const QString &output);

    QString m_statusText;
    bool m_scanning = false;
    bool m_commandRunning = false;
    QString m_lastScanPath;
    QString m_selectedProfile = QStringLiteral("balanced");
    QVector<AdvancedOption> m_advancedOptions;
    QString m_generatedConfigPath;
    QVariantList m_scanHistory;
    QVariantList m_firewallReport;
    QString m_lastCommandOutput;
    QProcess *m_process = nullptr;
    QString m_currentAction;
    QString m_currentTarget;
    QString m_processOutput;
};
