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

#ifndef KEEPASSXC_KPSCLIENT_H
#define KEEPASSXC_KPSCLIENT_H

#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QString>

/**
 * Blocking client for keepass-server (API v1). The server stores encrypted .kdbx files as
 * revisions; uploads carry If-Match with the base revision and stale uploads are refused (412).
 *
 * Every call creates its own QNetworkAccessManager and waits in a local event loop, so calls
 * must run in a worker thread (see AsyncTask) or in tests.
 */
class KpsClient
{
public:
    struct Response
    {
        int status = 0;
        /** Server not reachable (network error, timeout or 5xx): continue offline. */
        bool offline = false;
        QString errorCode;
        QString errorMessage;
        int currentRevision = -1;
        QByteArray body;
        QHash<QByteArray, QByteArray> headers;

        bool ok() const
        {
            return !offline && status >= 200 && status < 300;
        }
        QJsonObject json() const;
        QString describe() const;
    };

    struct VaultInfo
    {
        QString id;
        QString name;
        QString role;
        int revision = 0;
        int conflicts = 0;

        bool canWrite() const
        {
            return role != QStringLiteral("reader");
        }
    };

    struct Download
    {
        Response response;
        /** False when the server is still at the known revision (304). */
        bool changed = false;
        int revision = 0;
        QString sha256;
        QByteArray data;
    };

    struct ConnectionTest
    {
        enum Step
        {
            Reach,
            Server,
            Login,
            Done
        };
        bool ok = false;
        Step step = Reach;
        QString message;
    };

    explicit KpsClient(const QString& baseUrl, const QString& token = {});

    QString baseUrl() const;
    QString token() const;

    Response status();
    /** Logs in and keeps the returned device token. */
    Response login(const QString& username, const QString& password, const QString& deviceName);
    Response logout();
    Response me();
    Response listVaults(QList<VaultInfo>& vaults);
    Response getVault(const QString& vaultId, VaultInfo& vault);
    Response createVault(const QString& name, VaultInfo& vault);
    /** Downloads the current database; with knownRevision > 0 returns changed=false on 304. */
    Download download(const QString& vaultId, int knownRevision = 0);
    /** Uploads data as the revision after baseRevision; 412 with currentRevision when stale. */
    Response upload(const QString& vaultId, const QByteArray& data, int baseRevision, const QString& note = {});
    Response uploadConflict(const QString& vaultId, const QByteArray& data, int baseRevision, const QString& reason);

    static QString normalizeUrl(const QString& url);
    /** Plain http outside the local network. */
    static bool isInsecure(const QString& url);
    static QString sha256(const QByteArray& data);
    static ConnectionTest testConnection(const QString& url,
                                         const QString& username,
                                         const QString& password,
                                         const QString& deviceName);
    static QString defaultDeviceName();

private:
    Response request(const QByteArray& method,
                     const QString& path,
                     const QByteArray& body = {},
                     const QHash<QByteArray, QByteArray>& headers = {});
    static VaultInfo vaultFromJson(const QJsonObject& json);

    QString m_baseUrl;
    QString m_token;
};

#endif // KEEPASSXC_KPSCLIENT_H
