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

#ifndef KEEPASSXC_NEWDATABASEWIZARDPAGESTORAGE_H
#define KEEPASSXC_NEWDATABASEWIZARDPAGESTORAGE_H

#include "NewDatabaseWizardPage.h"
#include "gui/dbsettings/DatabaseSettingsWidget.h"

class KpsConnectionWidget;
class QLabel;
class QRadioButton;

/**
 * Where to store a new database: a file on this computer (asked when saving) or KeePass Server,
 * with sign-in and "Test connection". Choosing the server creates the vault on Finish.
 */
class DatabaseSettingsWidgetStorage : public DatabaseSettingsWidget
{
    Q_OBJECT

public:
    explicit DatabaseSettingsWidgetStorage(QWidget* parent = nullptr);

    void setPreferServer(bool preferServer);
    /** Local copy of the vault created on the server, empty for a file on this computer. */
    QString serverVaultPath() const;

public slots:
    void initialize() override;
    void uninitialize() override;
    bool saveSettings() override;

private:
    void updateEnabled();

    QRadioButton* m_localOption;
    QRadioButton* m_serverOption;
    KpsConnectionWidget* m_connection;
    QLabel* m_error;
    QString m_serverVaultPath;
};

class NewDatabaseWizardPageStorage : public NewDatabaseWizardPage
{
    Q_OBJECT

public:
    explicit NewDatabaseWizardPageStorage(QWidget* parent = nullptr);
    Q_DISABLE_COPY(NewDatabaseWizardPageStorage);
    ~NewDatabaseWizardPageStorage() override;

    DatabaseSettingsWidgetStorage* storageWidget() const;

private:
    DatabaseSettingsWidgetStorage* m_storage;
};

#endif // KEEPASSXC_NEWDATABASEWIZARDPAGESTORAGE_H
