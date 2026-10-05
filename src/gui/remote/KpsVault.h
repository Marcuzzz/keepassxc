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

#ifndef KEEPASSXC_KPSVAULT_H
#define KEEPASSXC_KPSVAULT_H

#include <QList>
#include <QSharedPointer>
#include <QString>

/**
 * The signed-in keepass-server account. Only the device token is stored, never the password.
 */
struct KpsAccount
{
    QString serverUrl;
    QString username;
    QString token;

    bool isValid() const
    {
        return !serverUrl.isEmpty() && !token.isEmpty();
    }

    static KpsAccount load();
    static void save(const KpsAccount& account);
    /** Forgets the token, keeps URL and username to prefill the next sign-in. */
    static void signOut();
};

/**
 * Local copy of a keepass-server vault: <app data>/keepass-server/<vault id>/<name>.kdbx plus
 * state.json. KeePassXC opens the local file like any other database, so it works offline.
 */
class KpsVault
{
public:
    struct State
    {
        QString serverUrl;
        QString vaultId;
        QString vaultName;
        QString fileName;
        /** Server revision the local file is based on (0 = nothing uploaded yet). */
        int baseRevision = 0;
        QString baseSha256;
        /** The local file has changes the server has not accepted yet. */
        bool dirty = false;
        /** User choice: never contact the server for this database. */
        bool workOffline = false;
        /** The server copy has another master key; uploads stop until the database is unlocked again. */
        bool needsReopen = false;
    };

    static QString rootDir();
    /** The vault whose local file is filePath, or null for any other database. */
    static QSharedPointer<KpsVault> fromPath(const QString& filePath);
    static QSharedPointer<KpsVault> getOrCreate(const QString& serverUrl, const QString& vaultId, const QString& vaultName);
    static QList<QSharedPointer<KpsVault>> all();

    QString dir() const;
    QString filePath() const;
    bool hasLocalCopy() const;
    State& state();

    bool save();
    /** Re-reads state.json (another sync may have changed it). */
    bool reload();
    /** Replaces the local file with data from the server as revision `revision`. */
    bool adopt(const QByteArray& data, int revision, const QString& sha256, QString* error = nullptr);
    /** Copies the local file next to it as conflict-<timestamp>.kdbx; returns the copy's path. */
    QString keepConflictCopy() const;

private:
    explicit KpsVault(QString dir);

    QString m_dir;
    State m_state;
};

#endif // KEEPASSXC_KPSVAULT_H
