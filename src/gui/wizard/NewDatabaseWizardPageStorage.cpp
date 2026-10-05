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

#include "NewDatabaseWizardPageStorage.h"

#include "core/AsyncTask.h"
#include "core/Database.h"
#include "core/Metadata.h"
#include "gui/remote/KpsClient.h"
#include "gui/remote/KpsConnectionWidget.h"
#include "gui/remote/KpsVault.h"

#include <QLabel>
#include <QRadioButton>
#include <QVBoxLayout>

DatabaseSettingsWidgetStorage::DatabaseSettingsWidgetStorage(QWidget* parent)
    : DatabaseSettingsWidget(parent)
    , m_localOption(new QRadioButton(tr("On this computer (choose a file when saving)"), this))
    , m_serverOption(new QRadioButton(tr("On KeePass Server (synced, also works offline)"), this))
    , m_connection(new KpsConnectionWidget(this))
    , m_error(new QLabel(this))
{
    m_localOption->setChecked(true);
    m_error->setWordWrap(true);
    m_error->setStyleSheet(QStringLiteral("color: #c0392b;"));
    m_error->setVisible(false);

    auto serverBox = new QWidget(this);
    auto serverLayout = new QVBoxLayout(serverBox);
    serverLayout->setContentsMargins(24, 0, 0, 0);
    serverLayout->addWidget(m_connection);

    auto layout = new QVBoxLayout(this);
    layout->addWidget(m_localOption);
    layout->addWidget(m_serverOption);
    layout->addWidget(serverBox);
    layout->addWidget(m_error);
    layout->addStretch();

    connect(m_serverOption, &QRadioButton::toggled, this, [this] { updateEnabled(); });
    updateEnabled();
}

void DatabaseSettingsWidgetStorage::setPreferServer(bool preferServer)
{
    (preferServer ? m_serverOption : m_localOption)->setChecked(true);
}

QString DatabaseSettingsWidgetStorage::serverVaultPath() const
{
    return m_serverVaultPath;
}

void DatabaseSettingsWidgetStorage::updateEnabled()
{
    m_connection->setEnabled(m_serverOption->isChecked());
    m_error->setVisible(false);
}

void DatabaseSettingsWidgetStorage::initialize()
{
}

void DatabaseSettingsWidgetStorage::uninitialize()
{
}

bool DatabaseSettingsWidgetStorage::saveSettings()
{
    m_serverVaultPath.clear();
    if (!m_serverOption->isChecked()) {
        return true;
    }
    if (!m_connection->signIn()) {
        return false;
    }
    const auto account = KpsAccount::load();
    auto name = m_db ? m_db->metadata()->name().trimmed() : QString();
    if (name.isEmpty()) {
        name = tr("Passwords");
    }
    struct Created
    {
        KpsClient::Response response;
        KpsClient::VaultInfo vault;
    };
    const auto created = AsyncTask::runAndWaitForFuture([account, name] {
        Created c;
        c.response = KpsClient(account.serverUrl, account.token).createVault(name, c.vault);
        return c;
    });
    if (!created.response.ok()) {
        m_error->setText(tr("Could not create the database on KeePass Server: %1").arg(created.response.describe()));
        m_error->setVisible(true);
        return false;
    }
    auto vault = KpsVault::getOrCreate(account.serverUrl, created.vault.id, created.vault.name);
    if (!vault) {
        m_error->setText(tr("Cannot create the local copy in %1").arg(KpsVault::rootDir()));
        m_error->setVisible(true);
        return false;
    }
    m_serverVaultPath = vault->filePath();
    return true;
}

NewDatabaseWizardPageStorage::NewDatabaseWizardPageStorage(QWidget* parent)
    : NewDatabaseWizardPage(parent)
    , m_storage(new DatabaseSettingsWidgetStorage())
{
    setPageWidget(m_storage);
    setTitle(tr("Storage Location"));
    setSubTitle(tr("Keep the database in a file on this computer, or on a KeePass Server to use it on several "
                   "devices and with other people."));
}

NewDatabaseWizardPageStorage::~NewDatabaseWizardPageStorage() = default;

DatabaseSettingsWidgetStorage* NewDatabaseWizardPageStorage::storageWidget() const
{
    return m_storage;
}
