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

#ifndef KEEPASSXC_KPSSERVERDIALOG_H
#define KEEPASSXC_KPSSERVERDIALOG_H

#include <QDialog>

class KpsConnectionWidget;
class QLabel;
class QListWidget;
class QPushButton;

/**
 * "Open from KeePass Server": sign in, pick a vault and open its local copy (downloaded the
 * first time), or start a new database on the server.
 */
class KpsServerDialog : public QDialog
{
    Q_OBJECT

public:
    enum class Action
    {
        None,
        /** Open the local copy at path(). */
        Open,
        /** Create a new database; path() is set when it goes into an existing empty vault. */
        NewDatabase
    };

    explicit KpsServerDialog(QWidget* parent = nullptr);

    Action action() const;
    QString path() const;

private slots:
    void refreshVaults();
    void openSelected();
    void newDatabase();

private:
    KpsConnectionWidget* m_connection;
    QListWidget* m_vaults;
    QLabel* m_info;
    QPushButton* m_openButton;
    QPushButton* m_newButton;
    QPushButton* m_refreshButton;
    Action m_action = Action::None;
    QString m_path;
};

#endif // KEEPASSXC_KPSSERVERDIALOG_H
