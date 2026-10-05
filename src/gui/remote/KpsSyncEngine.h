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

#ifndef KEEPASSXC_KPSSYNCENGINE_H
#define KEEPASSXC_KPSSYNCENGINE_H

#include <QSharedPointer>
#include <QString>

#include <functional>

class Database;
class KpsClient;
class KpsVault;

/**
 * Brings an open database stored in a KpsVault in line with keepass-server.
 *
 * - Local changes (dirty): upload with If-Match = base revision. On 412 another device was
 *   first: download its version, merge it into the open database (KeePassXC Merger, per entry),
 *   save, and upload again.
 * - No local changes: download a newer revision (If-None-Match) and merge it in.
 * - Server unreachable: nothing is lost, the local file stays dirty for the next sync.
 * - Merge impossible (other master key): the local file goes to the server as a conflict copy,
 *   is kept next to the database, and the server version replaces the local file.
 */
class KpsSyncEngine
{
public:
    enum class Outcome
    {
        UpToDate,
        Pulled,
        Pushed,
        Merged,
        Offline,
        WorkOffline,
        ReadOnly,
        NotSignedIn,
        NotFound,
        KeyChanged,
        NeedsReopen,
        Aborted,
        Error
    };

    struct Result
    {
        Outcome outcome = Outcome::UpToDate;
        int revision = 0;
        QString detail;
    };

    /** Runs a network step (possibly in a worker thread); returns false when the sync must stop. */
    using Runner = std::function<bool(const std::function<void()>&)>;
    /** Writes the open database to the vault's local file. */
    using Saver = std::function<bool(QString* error)>;

    static Result sync(const QSharedPointer<Database>& db,
                       KpsVault& vault,
                       KpsClient& client,
                       bool readOnly,
                       const Runner& run,
                       const Saver& save);

    static QString describe(const Result& result);
};

#endif // KEEPASSXC_KPSSYNCENGINE_H
