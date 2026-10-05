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

#include "KpsSyncEngine.h"
#include "KpsClient.h"
#include "KpsVault.h"

#include "core/Database.h"
#include "core/Merger.h"

#include <QFile>
#include <QObject>
#include <QTemporaryFile>

namespace
{
    constexpr int MaxAttempts = 5;

    using Outcome = KpsSyncEngine::Outcome;
    using Result = KpsSyncEngine::Result;

    Result result(Outcome outcome, int revision, const QString& detail = {})
    {
        return {outcome, revision, detail};
    }

    /** Maps an unsuccessful response to an outcome. */
    Result failure(const KpsClient::Response& response, int revision)
    {
        if (response.offline) {
            return result(Outcome::Offline, revision, response.describe());
        }
        switch (response.status) {
        case 401:
            return result(Outcome::NotSignedIn, revision, response.describe());
        case 403:
            return result(Outcome::ReadOnly, revision, response.describe());
        case 404:
            return result(Outcome::NotFound, revision, response.describe());
        default:
            return result(Outcome::Error, revision, response.describe());
        }
    }

    QByteArray readFile(const QString& path)
    {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
    }
} // namespace

KpsSyncEngine::Result KpsSyncEngine::sync(const QSharedPointer<Database>& db,
                                          KpsVault& vault,
                                          KpsClient& client,
                                          bool readOnly,
                                          const Runner& run,
                                          const Saver& save)
{
    auto& state = vault.state();
    if (state.needsReopen) {
        return result(Outcome::NeedsReopen, state.baseRevision);
    }
    if (state.workOffline) {
        return result(Outcome::WorkOffline, state.baseRevision);
    }

    // Unsaved edits are part of what gets uploaded
    if (db->isModified() && !readOnly) {
        QString error;
        if (!save(&error)) {
            return result(Outcome::Error, state.baseRevision, error);
        }
        state.dirty = true;
        vault.save();
    }

    bool merged = false;
    for (int attempt = 0; attempt < MaxAttempts; ++attempt) {
        if (state.dirty && !readOnly) {
            const auto data = readFile(vault.filePath());
            if (data.isEmpty()) {
                return result(Outcome::Error, state.baseRevision, QObject::tr("Cannot read %1").arg(vault.filePath()));
            }
            KpsClient::Response upload;
            if (!run([&] { upload = client.upload(state.vaultId, data, state.baseRevision, KpsClient::defaultDeviceName()); })) {
                return result(Outcome::Aborted, state.baseRevision);
            }
            if (upload.ok()) {
                state.baseRevision = upload.json().value(QStringLiteral("revision")).toInt();
                state.baseSha256 = upload.json().value(QStringLiteral("sha256")).toString();
                state.dirty = false;
                vault.save();
                return result(merged ? Outcome::Merged : Outcome::Pushed, state.baseRevision);
            }
            if (upload.status != 412) {
                return failure(upload, state.baseRevision);
            }
        }

        // Fetch the server version: all of it after a conflict, otherwise only if newer
        const int known = state.dirty || !vault.hasLocalCopy() ? 0 : state.baseRevision;
        KpsClient::Download download;
        if (!run([&] { download = client.download(state.vaultId, known); })) {
            return result(Outcome::Aborted, state.baseRevision);
        }
        if (download.response.status == 404 && download.response.errorCode == QStringLiteral("empty_vault")) {
            return result(Outcome::UpToDate, 0);
        }
        if (download.response.status != 304 && !download.response.ok()) {
            return failure(download.response, state.baseRevision);
        }
        if (!download.changed) {
            return result(merged ? Outcome::Merged : Outcome::UpToDate, state.baseRevision);
        }

        QTemporaryFile remoteFile(vault.dir() + QStringLiteral("/remote-XXXXXX.kdbx"));
        if (!remoteFile.open() || remoteFile.write(download.data) != download.data.size() || !remoteFile.flush()) {
            return result(Outcome::Error, state.baseRevision, remoteFile.errorString());
        }
        remoteFile.close();

        auto remoteDb = QSharedPointer<Database>::create();
        QString openError;
        if (!remoteDb->open(remoteFile.fileName(), db->key(), &openError)) {
            // Different master key: keep ours as a conflict copy, continue with the server version
            const auto local = readFile(vault.filePath());
            KpsClient::Response conflict;
            run([&] {
                conflict = client.uploadConflict(state.vaultId,
                                                 local,
                                                 state.baseRevision,
                                                 QObject::tr("Could not merge on %1 (master key changed?)")
                                                     .arg(KpsClient::defaultDeviceName()));
            });
            const auto copy = vault.keepConflictCopy();
            QString adoptError;
            if (!vault.adopt(download.data, download.revision, download.sha256, &adoptError)) {
                return result(Outcome::Error, state.baseRevision, adoptError);
            }
            state.needsReopen = true;
            vault.save();
            return result(Outcome::KeyChanged, download.revision, copy);
        }
        remoteDb->markAsTemporaryDatabase();

        const bool hadLocalChanges = state.dirty;
        Merger merger(remoteDb.data(), db.data());
        const auto changes = merger.merge();
        if (!changes.isEmpty() || db->isModified()) {
            QString error;
            if (!save(&error)) {
                return result(Outcome::Error, state.baseRevision, error);
            }
        }
        state.baseRevision = download.revision;
        state.baseSha256 = download.sha256;
        if (!hadLocalChanges) {
            // Only the server changed: the local file now has the same entries as the server
            state.dirty = false;
            vault.save();
            return result(Outcome::Pulled, download.revision);
        }
        state.dirty = true;
        vault.save();
        merged = true;
    }
    return result(Outcome::Error, state.baseRevision, QObject::tr("Other devices keep uploading at the same time, try again"));
}

QString KpsSyncEngine::describe(const Result& result)
{
    switch (result.outcome) {
    case Outcome::UpToDate:
        return QObject::tr("Up to date with KeePass Server (revision %1)").arg(result.revision);
    case Outcome::Pulled:
        return QObject::tr("Updated from KeePass Server (revision %1)").arg(result.revision);
    case Outcome::Pushed:
        return QObject::tr("Saved to KeePass Server (revision %1)").arg(result.revision);
    case Outcome::Merged:
        return QObject::tr("Merged with changes from another device and saved to KeePass Server (revision %1)")
            .arg(result.revision);
    case Outcome::Offline:
        return QObject::tr("KeePass Server not reachable: changes are kept on this computer and uploaded later (%1)")
            .arg(result.detail);
    case Outcome::WorkOffline:
        return QObject::tr("Working offline: changes are kept on this computer");
    case Outcome::ReadOnly:
        return QObject::tr("Read-only access on KeePass Server: changes are only kept on this computer");
    case Outcome::NotSignedIn:
        return QObject::tr("Not signed in to KeePass Server: use Database > KeePass Server to sign in");
    case Outcome::NotFound:
        return QObject::tr("This database no longer exists on KeePass Server, or your access was removed");
    case Outcome::KeyChanged:
        return QObject::tr("The master key was changed on another device. Your changes were kept as a conflict copy "
                           "(%1). Lock and unlock the database with the new master key.")
            .arg(result.detail);
    case Outcome::NeedsReopen:
        return QObject::tr("The master key was changed on another device. Lock and unlock the database with the new "
                           "master key to continue syncing.");
    case Outcome::Aborted:
        return {};
    case Outcome::Error:
        return QObject::tr("KeePass Server sync failed: %1").arg(result.detail);
    }
    return {};
}
