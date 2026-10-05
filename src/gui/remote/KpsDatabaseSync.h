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

#ifndef KEEPASSXC_KPSDATABASESYNC_H
#define KEEPASSXC_KPSDATABASESYNC_H

#include <QObject>
#include <QPointer>
#include <QTimer>

class DatabaseWidget;
class KpsVault;

/**
 * Keeps a database opened from keepass-server in sync: after unlocking, after every save,
 * every minute while unlocked, and on request. Attached to every DatabaseWidget; does nothing
 * for databases that are not KeePass Server copies.
 */
class KpsDatabaseSync : public QObject
{
    Q_OBJECT

public:
    explicit KpsDatabaseSync(DatabaseWidget* parent);

    static KpsDatabaseSync* forWidget(DatabaseWidget* widget);

    bool isServerDatabase() const;
    bool workOffline() const;
    void setWorkOffline(bool workOffline);

public slots:
    /** userInitiated: also report "up to date" and network errors. */
    void syncNow(bool userInitiated = true);

private slots:
    void onUnlocked();
    void onSaved();
    void onPoll();

private:
    QSharedPointer<KpsVault> vault() const;

    QPointer<DatabaseWidget> m_widget;
    QTimer m_pollTimer;
    bool m_running = false;
    bool m_again = false;
    bool m_selfSave = false;
};

#endif // KEEPASSXC_KPSDATABASESYNC_H
