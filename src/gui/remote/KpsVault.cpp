/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "KpsVault.h"
#include "KpsClient.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>

namespace
{
    const QString StateFile = QStringLiteral("state.json");

    QString accountFile()
    {
        return KpsVault::rootDir() + QStringLiteral("/account.json");
    }

    bool writePrivateFile(const QString& path, const QByteArray& data)
    {
        QDir().mkpath(QFileInfo(path).absolutePath());
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly)) {
            return false;
        }
        file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        file.write(data);
        return file.commit();
    }

    QString safeFileName(const QString& name)
    {
        auto cleaned = name;
        cleaned.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9 ._-]")), QStringLiteral("_"));
        cleaned = cleaned.trimmed().left(60);
        return (cleaned.isEmpty() ? QStringLiteral("database") : cleaned) + QStringLiteral(".kdbx");
    }
} // namespace

KpsAccount KpsAccount::load()
{
    QFile file(accountFile());
    KpsAccount account;
    if (!file.open(QIODevice::ReadOnly)) {
        return account;
    }
    const auto json = QJsonDocument::fromJson(file.readAll()).object();
    account.serverUrl = json.value(QStringLiteral("serverUrl")).toString();
    account.username = json.value(QStringLiteral("username")).toString();
    account.token = json.value(QStringLiteral("token")).toString();
    return account;
}

void KpsAccount::save(const KpsAccount& account)
{
    QJsonObject json{{QStringLiteral("serverUrl"), account.serverUrl},
                     {QStringLiteral("username"), account.username},
                     {QStringLiteral("token"), account.token}};
    writePrivateFile(accountFile(), QJsonDocument(json).toJson());
}

void KpsAccount::signOut()
{
    auto account = load();
    account.token.clear();
    save(account);
}

QString KpsVault::rootDir()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + QStringLiteral("/keepass-server");
}

KpsVault::KpsVault(QString dir)
    : m_dir(std::move(dir))
{
}

QSharedPointer<KpsVault> KpsVault::fromPath(const QString& filePath)
{
    if (filePath.isEmpty()) {
        return {};
    }
    QFileInfo info(filePath);
    const auto dir = info.absoluteDir();
    QDir parent(dir.absolutePath());
    if (!parent.cdUp()) {
        return {};
    }
    const auto root = QFileInfo(rootDir()).canonicalFilePath();
    if (root.isEmpty() || QFileInfo(parent.absolutePath()).canonicalFilePath() != root) {
        return {};
    }
    QSharedPointer<KpsVault> vault(new KpsVault(dir.absolutePath()));
    if (!vault->reload() || vault->m_state.fileName != info.fileName()) {
        return {};
    }
    return vault;
}

QSharedPointer<KpsVault>
KpsVault::getOrCreate(const QString& serverUrl, const QString& vaultId, const QString& vaultName)
{
    static const QRegularExpression idPattern(QStringLiteral("^[0-9a-fA-F-]{36}$"));
    if (!idPattern.match(vaultId).hasMatch()) {
        return {};
    }
    const auto dir = rootDir() + QStringLiteral("/") + vaultId;
    QSharedPointer<KpsVault> vault(new KpsVault(dir));
    if (vault->reload()) {
        return vault;
    }
    QDir().mkpath(dir);
    vault->m_state.serverUrl = KpsClient::normalizeUrl(serverUrl);
    vault->m_state.vaultId = vaultId;
    vault->m_state.vaultName = vaultName;
    vault->m_state.fileName = safeFileName(vaultName);
    if (!vault->save()) {
        return {};
    }
    return vault;
}

QList<QSharedPointer<KpsVault>> KpsVault::all()
{
    QList<QSharedPointer<KpsVault>> vaults;
    const auto entries = QDir(rootDir()).entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const auto& entry : entries) {
        QSharedPointer<KpsVault> vault(new KpsVault(entry.absoluteFilePath()));
        if (vault->reload()) {
            vaults.append(vault);
        }
    }
    return vaults;
}

QString KpsVault::dir() const
{
    return m_dir;
}

QString KpsVault::filePath() const
{
    return m_dir + QStringLiteral("/") + m_state.fileName;
}

bool KpsVault::hasLocalCopy() const
{
    QFileInfo info(filePath());
    return info.exists() && info.size() > 0;
}

KpsVault::State& KpsVault::state()
{
    return m_state;
}

bool KpsVault::save()
{
    QJsonObject json{{QStringLiteral("serverUrl"), m_state.serverUrl},
                     {QStringLiteral("vaultId"), m_state.vaultId},
                     {QStringLiteral("vaultName"), m_state.vaultName},
                     {QStringLiteral("fileName"), m_state.fileName},
                     {QStringLiteral("baseRevision"), m_state.baseRevision},
                     {QStringLiteral("baseSha256"), m_state.baseSha256},
                     {QStringLiteral("dirty"), m_state.dirty},
                     {QStringLiteral("workOffline"), m_state.workOffline},
                     {QStringLiteral("needsReopen"), m_state.needsReopen}};
    return writePrivateFile(m_dir + QStringLiteral("/") + StateFile, QJsonDocument(json).toJson());
}

bool KpsVault::reload()
{
    QFile file(m_dir + QStringLiteral("/") + StateFile);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
    const auto json = QJsonDocument::fromJson(file.readAll()).object();
    if (json.isEmpty()) {
        return false;
    }
    m_state.serverUrl = json.value(QStringLiteral("serverUrl")).toString();
    m_state.vaultId = json.value(QStringLiteral("vaultId")).toString();
    m_state.vaultName = json.value(QStringLiteral("vaultName")).toString();
    m_state.fileName = json.value(QStringLiteral("fileName")).toString();
    m_state.baseRevision = json.value(QStringLiteral("baseRevision")).toInt();
    m_state.baseSha256 = json.value(QStringLiteral("baseSha256")).toString();
    m_state.dirty = json.value(QStringLiteral("dirty")).toBool();
    m_state.workOffline = json.value(QStringLiteral("workOffline")).toBool();
    m_state.needsReopen = json.value(QStringLiteral("needsReopen")).toBool();
    return !m_state.vaultId.isEmpty() && !m_state.fileName.isEmpty();
}

bool KpsVault::adopt(const QByteArray& data, int revision, const QString& sha256, QString* error)
{
    QSaveFile file(filePath());
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit()) {
        if (error) {
            *error = file.errorString();
        }
        return false;
    }
    m_state.baseRevision = revision;
    m_state.baseSha256 = sha256;
    m_state.dirty = false;
    return save();
}

QString KpsVault::keepConflictCopy() const
{
    const auto stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"));
    const auto copy = m_dir + QStringLiteral("/conflict-%1.kdbx").arg(stamp);
    QFile::remove(copy);
    return QFile::copy(filePath(), copy) ? copy : QString();
}
