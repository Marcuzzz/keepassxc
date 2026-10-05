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

#include "KpsDatabaseSync.h"
#include "KpsClient.h"
#include "KpsSyncEngine.h"
#include "KpsVault.h"

#include "core/AsyncTask.h"
#include "core/Database.h"
#include "gui/DatabaseWidget.h"

namespace
{
    constexpr int PollIntervalMs = 60 * 1000;
}

KpsDatabaseSync::KpsDatabaseSync(DatabaseWidget* parent)
    : QObject(parent)
    , m_widget(parent)
{
    setObjectName(QStringLiteral("KpsDatabaseSync"));
    m_pollTimer.setInterval(PollIntervalMs);
    connect(&m_pollTimer, &QTimer::timeout, this, &KpsDatabaseSync::onPoll);
    connect(parent, &DatabaseWidget::databaseUnlocked, this, &KpsDatabaseSync::onUnlocked);
    connect(parent, &DatabaseWidget::databaseSaved, this, &KpsDatabaseSync::onSaved);
    connect(parent, &DatabaseWidget::databaseLocked, &m_pollTimer, &QTimer::stop);

    // A database created on the server and saved before this object existed
    if (!parent->isLocked() && isServerDatabase()) {
        QTimer::singleShot(0, this, [this] { onUnlocked(); });
    }
}

KpsDatabaseSync* KpsDatabaseSync::forWidget(DatabaseWidget* widget)
{
    return widget ? widget->findChild<KpsDatabaseSync*>(QStringLiteral("KpsDatabaseSync"), Qt::FindDirectChildrenOnly)
                  : nullptr;
}

QSharedPointer<KpsVault> KpsDatabaseSync::vault() const
{
    if (!m_widget || !m_widget->database()) {
        return {};
    }
    return KpsVault::fromPath(m_widget->database()->filePath());
}

bool KpsDatabaseSync::isServerDatabase() const
{
    return !vault().isNull();
}

bool KpsDatabaseSync::workOffline() const
{
    auto v = vault();
    return v && v->state().workOffline;
}

void KpsDatabaseSync::setWorkOffline(bool workOffline)
{
    auto v = vault();
    if (!v || !m_widget) {
        return;
    }
    v->state().workOffline = workOffline;
    v->save();
    if (workOffline) {
        m_widget->showMessage(tr("Working offline: KeePass Server is not contacted for this database"),
                              MessageWidget::Information);
    } else {
        syncNow(true);
    }
}

void KpsDatabaseSync::onUnlocked()
{
    auto v = vault();
    if (!v) {
        return;
    }
    // Unlocking reads the local file again, which holds the server version after a key change
    if (v->state().needsReopen) {
        v->state().needsReopen = false;
        v->save();
    }
    m_pollTimer.start();
    syncNow(false);
}

void KpsDatabaseSync::onSaved()
{
    if (m_selfSave) {
        return;
    }
    auto v = vault();
    if (!v) {
        return;
    }
    v->state().dirty = true;
    v->save();
    QTimer::singleShot(0, this, [this] { syncNow(false); });
}

void KpsDatabaseSync::onPoll()
{
    if (m_widget && !m_widget->isLocked() && !m_running) {
        syncNow(false);
    }
}

void KpsDatabaseSync::syncNow(bool userInitiated)
{
    if (m_running) {
        m_again = true;
        return;
    }
    auto v = vault();
    if (!v || !m_widget || m_widget->isLocked()) {
        return;
    }
    const auto account = KpsAccount::load();
    if (!account.isValid() || KpsClient::normalizeUrl(account.serverUrl) != KpsClient::normalizeUrl(v->state().serverUrl)) {
        if (userInitiated || v->state().dirty) {
            m_widget->showMessage(KpsSyncEngine::describe({KpsSyncEngine::Outcome::NotSignedIn, 0, {}}),
                                  MessageWidget::Warning);
        }
        return;
    }

    m_running = true;
    QPointer<KpsDatabaseSync> self(this);
    const auto db = m_widget->database();
    KpsClient client(account.serverUrl, account.token);

    // Network steps run in a worker thread; stop if the tab was closed or locked meanwhile.
    auto run = [self, db](const std::function<void()>& step) {
        AsyncTask::runAndWaitForFuture([step] {
            step();
            return true;
        });
        return self && self->m_widget && !self->m_widget->isLocked() && self->m_widget->database() == db;
    };
    auto save = [self, db](QString* error) {
        if (!self || !self->m_widget || self->m_widget->database() != db) {
            *error = tr("The database was closed");
            return false;
        }
        self->m_selfSave = true;
        const bool saved = self->m_widget->save();
        self->m_selfSave = false;
        if (!saved) {
            *error = tr("Writing the database failed");
        }
        return saved;
    };

    const auto result = KpsSyncEngine::sync(db, *v, client, false, run, save);
    if (!self) {
        return;
    }
    m_running = false;

    using Outcome = KpsSyncEngine::Outcome;
    const auto message = KpsSyncEngine::describe(result);
    switch (result.outcome) {
    case Outcome::Aborted:
        break;
    case Outcome::UpToDate:
        if (userInitiated) {
            m_widget->showMessage(message, MessageWidget::Positive);
        }
        break;
    case Outcome::Pulled:
    case Outcome::Pushed:
    case Outcome::Merged:
        m_widget->showMessage(message, MessageWidget::Positive);
        break;
    case Outcome::Offline:
    case Outcome::WorkOffline:
        if (userInitiated || v->state().dirty) {
            m_widget->showMessage(message, MessageWidget::Warning);
        }
        break;
    case Outcome::KeyChanged:
    case Outcome::NeedsReopen:
    case Outcome::Error:
        m_widget->showMessage(message, MessageWidget::Error, true, MessageWidget::DisableAutoHide);
        break;
    default:
        m_widget->showMessage(message, MessageWidget::Warning);
        break;
    }

    if (m_again) {
        m_again = false;
        QTimer::singleShot(0, this, [this] { syncNow(false); });
    }
}
