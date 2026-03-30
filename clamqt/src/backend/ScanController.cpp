#include "ScanController.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QTextStream>

namespace {
constexpr const char *kLowProfile = "low";
constexpr const char *kBalancedProfile = "balanced";
constexpr const char *kRigorousProfile = "rigorous";
}

ScanController::ScanController(QObject *parent)
    : QObject(parent)
{
    m_statusText = QStringLiteral("Ready");
    initAdvancedOptions();
    applyProfileDefaults(m_selectedProfile);
    writeGeneratedConfig();
    refreshDashboard();
}

QString ScanController::statusText() const
{
    return m_statusText;
}

bool ScanController::scanning() const
{
    return m_scanning;
}

QString ScanController::lastScanPath() const
{
    return m_lastScanPath;
}

QString ScanController::selectedProfile() const
{
    return m_selectedProfile;
}

QVariantList ScanController::advancedOptions() const
{
    QVariantList list;
    list.reserve(m_advancedOptions.size());

    for (const auto &option : m_advancedOptions) {
        QVariantMap item;
        item.insert(QStringLiteral("key"), option.key);
        item.insert(QStringLiteral("label"), option.label);
        item.insert(QStringLiteral("description"), option.description);
        item.insert(QStringLiteral("type"), option.type);
        item.insert(QStringLiteral("value"), option.value);
        list.append(item);
    }

    return list;
}

QString ScanController::generatedConfigPath() const
{
    return m_generatedConfigPath;
}

QVariantList ScanController::scanHistory() const
{
    return m_scanHistory;
}

QVariantList ScanController::firewallReport() const
{
    return m_firewallReport;
}

QString ScanController::lastCommandOutput() const
{
    return m_lastCommandOutput;
}

bool ScanController::commandRunning() const
{
    return m_commandRunning;
}

void ScanController::quickScan(const QString &path)
{
    scanFolder(path.isEmpty() ? defaultScanPath() : path);
}

void ScanController::selectProfile(const QString &profile)
{
    const QString normalized = normalizeProfile(profile);
    const bool changed = (normalized != m_selectedProfile);

    m_selectedProfile = normalized;
    if (changed) {
        emit selectedProfileChanged();
    }

    applyProfileDefaults(m_selectedProfile);
    emit advancedOptionsChanged();
    writeGeneratedConfig();
}

void ScanController::setAdvancedOption(const QString &key, const QVariant &value)
{
    updateAdvancedOption(key, value);
    emit advancedOptionsChanged();
    writeGeneratedConfig();
}

void ScanController::resetAdvancedOptions()
{
    applyProfileDefaults(m_selectedProfile);
    emit advancedOptionsChanged();
    writeGeneratedConfig();
}

void ScanController::refreshDashboard()
{
    loadScanHistory();
    loadFirewallReport();
}

void ScanController::scanFolder(const QString &path)
{
    if (m_commandRunning) {
        return;
    }

    const QString normalizedPath = path.trimmed().isEmpty() ? defaultScanPath() : path.trimmed();
    if (!QFileInfo::exists(normalizedPath)) {
        return;
    }

    m_lastScanPath = normalizedPath;
    emit lastScanPathChanged();

    runClamCommand(executableName(QStringLiteral("clamscan")),
                   {QStringLiteral("--recursive=yes"), normalizedPath},
                   QStringLiteral("scan-folder"),
                   normalizedPath);
}

void ScanController::runAction(const QString &action)
{

    if (action == QStringLiteral("scan-home")) {
        scanFolder(defaultScanPath());
        return;
    }

    if (action == QStringLiteral("scan-full")) {
#ifdef _WIN32
        const QString target = QStringLiteral("C:/");
#else
        const QString target = QStringLiteral("/");
#endif
        scanFolder(target);
        return;
    }

    if (action == QStringLiteral("update-db")) {
        runClamCommand(executableName(QStringLiteral("freshclam")), {}, action);
        return;
    }

    if (action == QStringLiteral("check-version")) {
        runClamCommand(executableName(QStringLiteral("clamscan")), {QStringLiteral("--version")}, action);
        return;
    }

    if (action == QStringLiteral("start-daemon")) {
        runClamCommand(executableName(QStringLiteral("clamd")), {}, action);
        return;
    }

    if (action == QStringLiteral("reload-daemon")) {
        runClamCommand(executableName(QStringLiteral("clamdscan")), {QStringLiteral("--reload")}, action);
        return;
    }

    if (action == QStringLiteral("stop-daemon")) {
        runClamCommand(executableName(QStringLiteral("clamdscan")), {QStringLiteral("--shutdown")}, action);
        return;
    }
}

void ScanController::initAdvancedOptions()
{
    m_advancedOptions = {
        {QStringLiteral("detect-pua"), QStringLiteral("Detectar PUA"), QStringLiteral("Detecta aplicativos potencialmente indesejados."), QStringLiteral("bool"), false},
        {QStringLiteral("heuristic-scan-precedence"), QStringLiteral("Precedencia Heuristica"), QStringLiteral("Para no primeiro alerta heuristico para reduzir tempo de scan."), QStringLiteral("bool"), false},
        {QStringLiteral("detect-structured"), QStringLiteral("DLP Estruturado"), QStringLiteral("Ativa deteccao de dados sensiveis estruturados."), QStringLiteral("bool"), false},
        {QStringLiteral("alert-encrypted-archive"), QStringLiteral("Alertar Arquivo Criptografado"), QStringLiteral("Gera alerta para arquivos compactados criptografados."), QStringLiteral("bool"), false},
        {QStringLiteral("alert-encrypted-doc"), QStringLiteral("Alertar Documento Criptografado"), QStringLiteral("Gera alerta para documentos PDF criptografados."), QStringLiteral("bool"), false},
        {QStringLiteral("alert-macros"), QStringLiteral("Alertar Macros OLE2"), QStringLiteral("Marca arquivos Office com macros suspeitas."), QStringLiteral("bool"), false},
        {QStringLiteral("network-firewall"), QStringLiteral("Firewall de Rede"), QStringLiteral("Ativa modulo de protecao e analise de trafego."), QStringLiteral("bool"), false},
        {QStringLiteral("allow-port-scanning"), QStringLiteral("Permitir Port Scanning"), QStringLiteral("Quando desativado, detecta varredura de portas."), QStringLiteral("bool"), true},
        {QStringLiteral("block-scanned-ports"), QStringLiteral("Bloquear Scanner de Porta"), QStringLiteral("Bloqueia automaticamente origem detectada em varredura."), QStringLiteral("bool"), false},
        {QStringLiteral("enable-ip-reputation"), QStringLiteral("Reputacao de IP"), QStringLiteral("Ativa classificacao de reputacao para IPs de origem."), QStringLiteral("bool"), false},
        {QStringLiteral("homograph-detection"), QStringLiteral("Deteccao Homograph"), QStringLiteral("Detecta spoofing Unicode em dominios e URLs."), QStringLiteral("bool"), false},
        {QStringLiteral("validate-ssl"), QStringLiteral("Validar TLS"), QStringLiteral("Sinaliza protocolos/cifras TLS inseguros."), QStringLiteral("bool"), false},
        {QStringLiteral("detect-c2"), QStringLiteral("Deteccao C2"), QStringLiteral("Detecta padroes de comunicacao de Command & Control."), QStringLiteral("bool"), false},
        {QStringLiteral("enable-ml-models"), QStringLiteral("Modelos de ML"), QStringLiteral("Ativa modelos de anomalia para rede maliciosa."), QStringLiteral("bool"), false},
        {QStringLiteral("ml-confidence"), QStringLiteral("Confianca ML"), QStringLiteral("Limiar de confianca (0-100) para alerta de ML."), QStringLiteral("int"), 85},
        {QStringLiteral("max-scantime"), QStringLiteral("Tempo Maximo de Scan (ms)"), QStringLiteral("Tempo maximo por scan, 0 desativa limite."), QStringLiteral("int"), 120000},
        {QStringLiteral("max-filesize"), QStringLiteral("Tamanho Maximo de Arquivo"), QStringLiteral("Limite de tamanho por arquivo analisado."), QStringLiteral("string"), QStringLiteral("100M")},
        {QStringLiteral("max-scansize"), QStringLiteral("Tamanho Maximo de Scan"), QStringLiteral("Limite total de dados processados por input."), QStringLiteral("string"), QStringLiteral("400M")},
        {QStringLiteral("max-recursion"), QStringLiteral("Recursao Maxima"), QStringLiteral("Nivel maximo de recursao em conteineres/arquivos."), QStringLiteral("int"), 17}
    };
}

void ScanController::applyProfileDefaults(const QString &profile)
{
    const QString normalized = normalizeProfile(profile);

    // Baseline.
    updateAdvancedOption(QStringLiteral("detect-pua"), false);
    updateAdvancedOption(QStringLiteral("heuristic-scan-precedence"), false);
    updateAdvancedOption(QStringLiteral("detect-structured"), false);
    updateAdvancedOption(QStringLiteral("alert-encrypted-archive"), false);
    updateAdvancedOption(QStringLiteral("alert-encrypted-doc"), false);
    updateAdvancedOption(QStringLiteral("alert-macros"), false);
    updateAdvancedOption(QStringLiteral("network-firewall"), false);
    updateAdvancedOption(QStringLiteral("allow-port-scanning"), true);
    updateAdvancedOption(QStringLiteral("block-scanned-ports"), false);
    updateAdvancedOption(QStringLiteral("enable-ip-reputation"), false);
    updateAdvancedOption(QStringLiteral("homograph-detection"), false);
    updateAdvancedOption(QStringLiteral("validate-ssl"), false);
    updateAdvancedOption(QStringLiteral("detect-c2"), false);
    updateAdvancedOption(QStringLiteral("enable-ml-models"), false);
    updateAdvancedOption(QStringLiteral("ml-confidence"), 85);
    updateAdvancedOption(QStringLiteral("max-scantime"), 120000);
    updateAdvancedOption(QStringLiteral("max-filesize"), QStringLiteral("100M"));
    updateAdvancedOption(QStringLiteral("max-scansize"), QStringLiteral("400M"));
    updateAdvancedOption(QStringLiteral("max-recursion"), 17);

    if (normalized == QString::fromLatin1(kBalancedProfile)) {
        updateAdvancedOption(QStringLiteral("detect-pua"), true);
        updateAdvancedOption(QStringLiteral("heuristic-scan-precedence"), true);
        updateAdvancedOption(QStringLiteral("detect-structured"), true);
        updateAdvancedOption(QStringLiteral("alert-encrypted-archive"), true);
        updateAdvancedOption(QStringLiteral("alert-encrypted-doc"), true);
        updateAdvancedOption(QStringLiteral("alert-macros"), true);
        updateAdvancedOption(QStringLiteral("network-firewall"), true);
        updateAdvancedOption(QStringLiteral("allow-port-scanning"), false);
        updateAdvancedOption(QStringLiteral("enable-ip-reputation"), true);
        updateAdvancedOption(QStringLiteral("homograph-detection"), true);
        updateAdvancedOption(QStringLiteral("detect-c2"), true);
        updateAdvancedOption(QStringLiteral("ml-confidence"), 90);
    } else if (normalized == QString::fromLatin1(kRigorousProfile)) {
        updateAdvancedOption(QStringLiteral("detect-pua"), true);
        updateAdvancedOption(QStringLiteral("heuristic-scan-precedence"), true);
        updateAdvancedOption(QStringLiteral("detect-structured"), true);
        updateAdvancedOption(QStringLiteral("alert-encrypted-archive"), true);
        updateAdvancedOption(QStringLiteral("alert-encrypted-doc"), true);
        updateAdvancedOption(QStringLiteral("alert-macros"), true);
        updateAdvancedOption(QStringLiteral("network-firewall"), true);
        updateAdvancedOption(QStringLiteral("allow-port-scanning"), false);
        updateAdvancedOption(QStringLiteral("block-scanned-ports"), true);
        updateAdvancedOption(QStringLiteral("enable-ip-reputation"), true);
        updateAdvancedOption(QStringLiteral("homograph-detection"), true);
        updateAdvancedOption(QStringLiteral("validate-ssl"), true);
        updateAdvancedOption(QStringLiteral("detect-c2"), true);
        updateAdvancedOption(QStringLiteral("enable-ml-models"), true);
        updateAdvancedOption(QStringLiteral("ml-confidence"), 85);
        updateAdvancedOption(QStringLiteral("max-scantime"), 90000);
        updateAdvancedOption(QStringLiteral("max-filesize"), QStringLiteral("50M"));
        updateAdvancedOption(QStringLiteral("max-scansize"), QStringLiteral("200M"));
        updateAdvancedOption(QStringLiteral("max-recursion"), 12);
    }
}

void ScanController::updateAdvancedOption(const QString &key, const QVariant &value)
{
    for (auto &option : m_advancedOptions) {
        if (option.key != key) {
            continue;
        }

        if (option.type == QStringLiteral("bool")) {
            option.value = value.toBool();
        } else if (option.type == QStringLiteral("int")) {
            option.value = value.toInt();
        } else {
            option.value = value.toString();
        }
        return;
    }
}

QString ScanController::normalizeProfile(const QString &profile) const
{
    const QString lower = profile.trimmed().toLower();
    if (lower == QStringLiteral("low") || lower == QStringLiteral("baixo")) {
        return QStringLiteral("low");
    }
    if (lower == QStringLiteral("rigorous") || lower == QStringLiteral("rigoroso")) {
        return QStringLiteral("rigorous");
    }
    return QStringLiteral("balanced");
}

QString ScanController::profileDisplayName() const
{
    if (m_selectedProfile == QStringLiteral("low")) {
        return QStringLiteral("Baixo");
    }
    if (m_selectedProfile == QStringLiteral("rigorous")) {
        return QStringLiteral("Rigoroso");
    }
    return QStringLiteral("Balanceado");
}

QString ScanController::boolToYesNo(bool value) const
{
    return value ? QStringLiteral("yes") : QStringLiteral("no");
}

QString ScanController::ensureConfigDirectory() const
{
    QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (baseDir.isEmpty()) {
        baseDir = QDir::tempPath() + QStringLiteral("/clamqt");
    }

    QDir dir(baseDir);
    if (!dir.exists()) {
        dir.mkpath(QStringLiteral("."));
    }

    return dir.absolutePath();
}

QString ScanController::historyFilePath() const
{
    return QDir(ensureConfigDirectory()).filePath(QStringLiteral("scan-history.jsonl"));
}

QString ScanController::firewallFilePath() const
{
    return QDir(ensureConfigDirectory()).filePath(QStringLiteral("firewall-report.jsonl"));
}

void ScanController::loadScanHistory()
{
    QVariantList list;
    QFile file(historyFilePath());
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        while (!file.atEnd()) {
            const QByteArray line = file.readLine().trimmed();
            if (line.isEmpty()) {
                continue;
            }

            const auto doc = QJsonDocument::fromJson(line);
            if (!doc.isObject()) {
                continue;
            }

            const QJsonObject obj = doc.object();
            QVariantMap row;
            row.insert(QStringLiteral("time"), obj.value(QStringLiteral("time")).toString());
            row.insert(QStringLiteral("target"), obj.value(QStringLiteral("target")).toString());
            row.insert(QStringLiteral("result"), obj.value(QStringLiteral("result")).toString());
            row.insert(QStringLiteral("details"), obj.value(QStringLiteral("details")).toString());
            list.append(row);
        }
    }

    QVariantList reversed;
    reversed.reserve(list.size());
    for (int i = list.size() - 1; i >= 0; --i) {
        reversed.append(list.at(i));
        if (reversed.size() >= 25) {
            break;
        }
    }

    m_scanHistory = reversed;
    emit scanHistoryChanged();
}

void ScanController::loadFirewallReport()
{
    QVariantList list;
    QFile file(firewallFilePath());
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        while (!file.atEnd()) {
            const QByteArray line = file.readLine().trimmed();
            if (line.isEmpty()) {
                continue;
            }

            const auto doc = QJsonDocument::fromJson(line);
            if (!doc.isObject()) {
                continue;
            }

            const QJsonObject obj = doc.object();
            QVariantMap row;
            row.insert(QStringLiteral("time"), obj.value(QStringLiteral("time")).toString());
            row.insert(QStringLiteral("event"), obj.value(QStringLiteral("event")).toString());
            row.insert(QStringLiteral("severity"), obj.value(QStringLiteral("severity")).toString());
            row.insert(QStringLiteral("details"), obj.value(QStringLiteral("details")).toString());
            list.append(row);
        }
    }

    QVariantList reversed;
    reversed.reserve(list.size());
    for (int i = list.size() - 1; i >= 0; --i) {
        reversed.append(list.at(i));
        if (reversed.size() >= 25) {
            break;
        }
    }

    m_firewallReport = reversed;
    emit firewallReportChanged();
}

void ScanController::appendScanHistory(const QString &target, const QString &result, const QString &details)
{
    QFile file(historyFilePath());
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        return;
    }

    QJsonObject obj;
    obj.insert(QStringLiteral("time"), QDateTime::currentDateTime().toString(Qt::ISODate));
    obj.insert(QStringLiteral("target"), target);
    obj.insert(QStringLiteral("result"), result);
    obj.insert(QStringLiteral("details"), details);

    file.write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
    file.write("\n");
    file.close();
}

void ScanController::runClamCommand(const QString &program, const QStringList &arguments, const QString &action, const QString &target)
{
    m_process = new QProcess(this);
    m_processOutput.clear();
    m_currentAction = action;
    m_currentTarget = target;
    m_commandRunning = true;
    m_scanning = isScanAction(action);
    emit commandRunningChanged();
    emit scanningChanged();

    connect(m_process, &QProcess::readyReadStandardOutput, this, [this]() {
        m_processOutput += QString::fromLocal8Bit(m_process->readAllStandardOutput());
    });

    connect(m_process, &QProcess::readyReadStandardError, this, [this]() {
        m_processOutput += QString::fromLocal8Bit(m_process->readAllStandardError());
    });

    connect(m_process, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus exitStatus) {
        const QString output = m_processOutput;
        finishCommand(m_currentAction, m_currentTarget, exitCode, exitStatus, output);

        m_process->deleteLater();
        m_process = nullptr;
        m_processOutput.clear();
        m_currentAction.clear();
        m_currentTarget.clear();
        m_commandRunning = false;
        m_scanning = false;
        emit commandRunningChanged();
        emit scanningChanged();
    });

    m_process->setProgram(program);
    m_process->setArguments(arguments);
    m_process->start();

    if (!m_process->waitForStarted()) {
        m_lastCommandOutput = QStringLiteral("Falha ao iniciar comando: %1").arg(program);
        emit lastCommandOutputChanged();

        m_process->deleteLater();
        m_process = nullptr;
        m_commandRunning = false;
        m_scanning = false;
        emit commandRunningChanged();
        emit scanningChanged();
    }
}

QString ScanController::summarizeOutput(const QString &output) const
{
    const QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    if (lines.isEmpty()) {
        return QStringLiteral("Sem detalhes de saida.");
    }

    QString summary = lines.first().trimmed();
    if (summary.size() > 180) {
        summary = summary.left(177) + QStringLiteral("...");
    }
    return summary;
}

QString ScanController::executableName(const QString &name) const
{
#ifdef _WIN32
    if (name.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive)) {
        return name;
    }
    return name + QStringLiteral(".exe");
#else
    return name;
#endif
}

bool ScanController::isScanAction(const QString &action) const
{
    return action == QStringLiteral("scan-folder") ||
           action == QStringLiteral("scan-home") ||
           action == QStringLiteral("scan-full");
}

QString ScanController::defaultScanPath() const
{
    QString home = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
    if (home.isEmpty()) {
        home = QDir::homePath();
    }
    return home;
}

void ScanController::writeGeneratedConfig()
{
    const QString dirPath = ensureConfigDirectory();
    const QString cfgPath = QDir(dirPath).filePath(QStringLiteral("clamav-profile.conf"));

    QFile file(cfgPath);

    QTextStream out(&file);
    out << "# Auto-generated by ClamDesk\n";
    out << "# Generated: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
    out << "# Profile: " << m_selectedProfile << "\n\n";

    out << "# Base profile\n";
    out << "Profile " << m_selectedProfile << "\n\n";

    out << "# Advanced options\n";
    for (const auto &option : m_advancedOptions) {
        out << option.key << ' ';
        if (option.type == QStringLiteral("bool")) {
            out << boolToYesNo(option.value.toBool());
        } else {
            out << option.value.toString();
        }
        out << "\n";
    }

    file.close();

    if (m_generatedConfigPath != cfgPath) {
        m_generatedConfigPath = cfgPath;
        emit generatedConfigPathChanged();
    }
}

void ScanController::finishCommand(const QString &action, const QString &target, int exitCode, QProcess::ExitStatus exitStatus, const QString &output)
{
    m_lastCommandOutput = output.trimmed();
    emit lastCommandOutputChanged();

    QString result;
    if (exitStatus != QProcess::NormalExit) {
        result = QStringLiteral("erro");
    } else if (isScanAction(action) && exitCode == 1) {
        result = QStringLiteral("infectado");
    } else if (exitCode == 0) {
        result = QStringLiteral("ok");
    } else {
        result = QStringLiteral("erro");
    }

    const QString summary = summarizeOutput(output);

    if (isScanAction(action)) {
        appendScanHistory(target.isEmpty() ? defaultScanPath() : target, result, summary);
        loadScanHistory();
    }

    if (action == QStringLiteral("update-db")) {
        m_statusText = result == QStringLiteral("ok")
                           ? QStringLiteral("Atualizacao de assinaturas concluida.")
                           : QStringLiteral("Falha ao atualizar assinaturas.");
    } else if (action == QStringLiteral("check-version")) {
        m_statusText = QStringLiteral("Versao do ClamAV consultada.");
    } else if (action == QStringLiteral("start-daemon")) {
        m_statusText = result == QStringLiteral("ok")
                           ? QStringLiteral("Comando para iniciar o daemon executado.")
                           : QStringLiteral("Falha ao iniciar daemon.");
    } else if (action == QStringLiteral("reload-daemon")) {
        m_statusText = result == QStringLiteral("ok")
                           ? QStringLiteral("Daemon recarregado.")
                           : QStringLiteral("Falha ao recarregar daemon.");
    } else if (action == QStringLiteral("stop-daemon")) {
        m_statusText = result == QStringLiteral("ok")
                           ? QStringLiteral("Comando de parada do daemon executado.")
                           : QStringLiteral("Falha ao parar daemon.");
    } else {
        m_statusText = result == QStringLiteral("ok")
                           ? QStringLiteral("Scan concluido sem deteccao.")
                           : (result == QStringLiteral("infectado")
                                  ? QStringLiteral("Scan concluido com deteccoes.")
                                  : QStringLiteral("Scan finalizado com erro."));
    }
}
