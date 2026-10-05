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

#include "KpsServerDialog.h"
#include "KpsClient.h"
#include "KpsConnectionWidget.h"
#include "KpsVault.h"

#include "core/AsyncTask.h"

#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

namespace
{
    enum Roles
    {
        IdRole = Qt::UserRole,
        NameRole,
        RevisionRole,
        WritableRole
    };
} // namespace

KpsServerDialog::KpsServerDialog(QWidget* parent)
    : QDialog(parent)
    , m_connection(new KpsConnectionWidget(this))
    , m_vaults(new QListWidget(this))
    , m_info(new QLabel(this))
    , m_openButton(new QPushButton(tr("Open"), this))
    , m_newButton(new QPushButton(tr("New database…"), this))
    , m_refreshButton(new QPushButton(tr("Refresh"), this))
{
    setWindowTitle(tr("KeePass Server"));
    setMinimumWidth(480);

    m_info->setWordWrap(true);
    m_info->setText(tr("Databases are kept on this computer and synced with the server, so they also open "
                       "without a connection."));

    auto vaultButtons = new QHBoxLayout();
    vaultButtons->addWidget(m_refreshButton);
    vaultButtons->addStretch();
    vaultButtons->addWidget(m_newButton);
    vaultButtons->addWidget(m_openButton);

    auto closeBox = new QDialogButtonBox(QDialogButtonBox::Close, this);

    auto layout = new QVBoxLayout(this);
    layout->addWidget(m_connection);
    layout->addWidget(new QLabel(tr("Databases on the server:"), this));
    layout->addWidget(m_vaults, 1);
    layout->addLayout(vaultButtons);
    layout->addWidget(m_info);
    layout->addWidget(closeBox);

    m_openButton->setDefault(true);

    connect(closeBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_refreshButton, &QPushButton::clicked, this, &KpsServerDialog::refreshVaults);
    connect(m_openButton, &QPushButton::clicked, this, &KpsServerDialog::openSelected);
    connect(m_newButton, &QPushButton::clicked, this, &KpsServerDialog::newDatabase);
    connect(m_vaults, &QListWidget::itemActivated, this, &KpsServerDialog::openSelected);
    connect(m_connection, &KpsConnectionWidget::signedIn, this, &KpsServerDialog::refreshVaults);
    connect(m_connection, &KpsConnectionWidget::signedOut, this, &KpsServerDialog::refreshVaults);

    // Shown while signed out
    auto signInButton = new QPushButton(tr("Sign in"), this);
    vaultButtons->insertWidget(1, signInButton);
    connect(signInButton, &QPushButton::clicked, m_connection, &KpsConnectionWidget::signIn);
    connect(m_connection, &KpsConnectionWidget::signedIn, signInButton, &QWidget::hide);
    connect(m_connection, &KpsConnectionWidget::signedOut, signInButton, &QWidget::show);
    signInButton->setVisible(!m_connection->isSignedIn());

    refreshVaults();
}

KpsServerDialog::Action KpsServerDialog::action() const
{
    return m_action;
}

QString KpsServerDialog::path() const
{
    return m_path;
}

void KpsServerDialog::refreshVaults()
{
    m_vaults->clear();
    const auto account = KpsAccount::load();
    const bool signedIn = account.isValid();
    m_vaults->setEnabled(signedIn);
    m_openButton->setEnabled(signedIn);
    m_newButton->setEnabled(signedIn);
    m_refreshButton->setEnabled(signedIn);
    if (!signedIn) {
        return;
    }

    struct Listing
    {
        KpsClient::Response response;
        QList<KpsClient::VaultInfo> vaults;
    };
    const auto listing = AsyncTask::runAndWaitForFuture([account] {
        Listing l;
        KpsClient client(account.serverUrl, account.token);
        l.response = client.listVaults(l.vaults);
        return l;
    });

    QHash<QString, QSharedPointer<KpsVault>> local;
    for (const auto& vault : KpsVault::all()) {
        if (KpsClient::normalizeUrl(vault->state().serverUrl) == KpsClient::normalizeUrl(account.serverUrl)) {
            local.insert(vault->state().vaultId, vault);
        }
    }

    auto addItem = [this](const QString& id, const QString& name, const QString& details, int revision, bool writable) {
        auto item = new QListWidgetItem(QStringLiteral("%1  —  %2").arg(name, details), m_vaults);
        item->setData(IdRole, id);
        item->setData(NameRole, name);
        item->setData(RevisionRole, revision);
        item->setData(WritableRole, writable);
    };

    if (listing.response.status == 401) {
        KpsAccount::signOut();
        m_info->setText(tr("Your session expired, sign in again."));
        m_connection->signIn();
        return;
    }
    if (!listing.response.ok()) {
        // Offline: show the copies on this computer
        m_info->setText(tr("Server not reachable (%1). Showing the copies on this computer.")
                            .arg(listing.response.describe()));
        m_newButton->setEnabled(false);
        for (const auto& vault : local) {
            const auto& state = vault->state();
            addItem(state.vaultId,
                    state.vaultName,
                    tr("revision %1%2").arg(state.baseRevision).arg(state.dirty ? tr(", unsynced changes") : QString()),
                    state.baseRevision,
                    true);
        }
        return;
    }

    for (const auto& vault : listing.vaults) {
        QStringList details{vault.role, tr("revision %1").arg(vault.revision)};
        if (vault.conflicts > 0) {
            details << tr("%n conflict copies", "", vault.conflicts);
        }
        if (local.contains(vault.id)) {
            const auto& state = local.value(vault.id)->state();
            if (state.dirty) {
                details << tr("unsynced changes");
            }
            if (state.workOffline) {
                details << tr("working offline");
            }
        }
        addItem(vault.id, vault.name, details.join(QStringLiteral(", ")), vault.revision, vault.canWrite());
    }
    if (listing.vaults.isEmpty()) {
        m_info->setText(tr("No databases on this server yet. Use \"New database…\" to create one."));
    } else {
        m_vaults->setCurrentRow(0);
    }
}

void KpsServerDialog::openSelected()
{
    auto item = m_vaults->currentItem();
    const auto account = KpsAccount::load();
    if (!item || !account.isValid()) {
        return;
    }
    auto vault = KpsVault::getOrCreate(
        account.serverUrl, item->data(IdRole).toString(), item->data(NameRole).toString());
    if (!vault) {
        m_info->setText(tr("Cannot create the local copy in %1").arg(KpsVault::rootDir()));
        return;
    }
    if (!vault->hasLocalCopy()) {
        if (item->data(RevisionRole).toInt() == 0) {
            if (!item->data(WritableRole).toBool()) {
                m_info->setText(tr("This database is empty and you have read-only access."));
                return;
            }
            // Empty vault: this computer creates the first version
            m_action = Action::NewDatabase;
            m_path = vault->filePath();
            accept();
            return;
        }
        m_info->setText(tr("Downloading…"));
        const auto vaultId = vault->state().vaultId;
        const auto download = AsyncTask::runAndWaitForFuture(
            [account, vaultId] { return KpsClient(account.serverUrl, account.token).download(vaultId); });
        QString error;
        if (!download.changed || !vault->adopt(download.data, download.revision, download.sha256, &error)) {
            m_info->setText(tr("Download failed: %1").arg(error.isEmpty() ? download.response.describe() : error));
            return;
        }
    }
    m_action = Action::Open;
    m_path = vault->filePath();
    accept();
}

void KpsServerDialog::newDatabase()
{
    m_action = Action::NewDatabase;
    m_path.clear();
    accept();
}
