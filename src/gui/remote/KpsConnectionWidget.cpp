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

#include "KpsConnectionWidget.h"
#include "KpsClient.h"
#include "KpsVault.h"

#include "core/AsyncTask.h"

#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

KpsConnectionWidget::KpsConnectionWidget(QWidget* parent)
    : QWidget(parent)
    , m_form(new QWidget(this))
    , m_signedInRow(new QWidget(this))
    , m_signedInLabel(new QLabel(m_signedInRow))
    , m_url(new QLineEdit(m_form))
    , m_username(new QLineEdit(m_form))
    , m_password(new QLineEdit(m_form))
    , m_testButton(new QPushButton(tr("Test connection"), m_form))
    , m_status(new QLabel(this))
{
    m_url->setPlaceholderText(QStringLiteral("https://vault.example.com"));
    m_password->setEchoMode(QLineEdit::Password);

    auto formLayout = new QFormLayout(m_form);
    formLayout->setContentsMargins(0, 0, 0, 0);
    formLayout->addRow(tr("Server URL:"), m_url);
    formLayout->addRow(tr("Username:"), m_username);
    formLayout->addRow(tr("Account password:"), m_password);
    formLayout->addRow(QString(), m_testButton);

    auto signOutButton = new QPushButton(tr("Sign out"), m_signedInRow);
    auto rowLayout = new QHBoxLayout(m_signedInRow);
    rowLayout->setContentsMargins(0, 0, 0, 0);
    rowLayout->addWidget(m_signedInLabel, 1);
    rowLayout->addWidget(signOutButton);

    m_status->setWordWrap(true);
    m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_status->setVisible(false);

    auto layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(m_signedInRow);
    layout->addWidget(m_form);
    layout->addWidget(m_status);

    connect(m_testButton, &QPushButton::clicked, this, &KpsConnectionWidget::testConnection);
    connect(signOutButton, &QPushButton::clicked, this, &KpsConnectionWidget::signOut);

    const auto account = KpsAccount::load();
    m_url->setText(account.serverUrl);
    m_username->setText(account.username);
    refresh();
}

bool KpsConnectionWidget::isSignedIn() const
{
    return KpsAccount::load().isValid();
}

void KpsConnectionWidget::refresh()
{
    const auto account = KpsAccount::load();
    const bool signedIn = account.isValid();
    m_form->setVisible(!signedIn);
    m_signedInRow->setVisible(signedIn);
    if (signedIn) {
        m_signedInLabel->setText(tr("Signed in as <b>%1</b> on %2")
                                     .arg(account.username.toHtmlEscaped(),
                                          QUrl(account.serverUrl).host().toHtmlEscaped()));
    }
}

void KpsConnectionWidget::showStatus(const QString& text, bool error)
{
    m_status->setText(text);
    m_status->setStyleSheet(error ? QStringLiteral("color: #c0392b;") : QString());
    m_status->setVisible(!text.isEmpty());
}

bool KpsConnectionWidget::readFields(QString& url, QString& username, QString& password)
{
    url = m_url->text().trimmed();
    username = m_username->text().trimmed();
    password = m_password->text();
    if (url.isEmpty() || username.isEmpty() || password.isEmpty()) {
        showStatus(tr("Fill in server URL, username and password."), true);
        return false;
    }
    return true;
}

void KpsConnectionWidget::testConnection()
{
    QString url, username, password;
    if (!readFields(url, username, password)) {
        return;
    }
    showStatus(tr("Connecting…"), false);
    m_testButton->setEnabled(false);
    const auto test = AsyncTask::runAndWaitForFuture(
        [=] { return KpsClient::testConnection(url, username, password, KpsClient::defaultDeviceName()); });
    m_testButton->setEnabled(true);

    QString text;
    switch (test.step) {
    case KpsClient::ConnectionTest::Done:
        text = tr("Connected as %1.").arg(test.message);
        break;
    case KpsClient::ConnectionTest::Reach:
        text = tr("Server not reachable: %1").arg(test.message);
        break;
    case KpsClient::ConnectionTest::Server:
        text = tr("This URL is not a KeePass Server.");
        break;
    case KpsClient::ConnectionTest::Login:
        text = tr("Wrong username or password (%1).").arg(test.message);
        break;
    }
    if (KpsClient::isInsecure(url)) {
        text += QStringLiteral("\n")
                + tr("Warning: plain HTTP outside your local network sends your account password unencrypted. "
                     "Use https.");
    }
    showStatus(text, !test.ok);
}

bool KpsConnectionWidget::signIn()
{
    if (isSignedIn()) {
        return true;
    }
    QString url, username, password;
    if (!readFields(url, username, password)) {
        return false;
    }
    showStatus(tr("Connecting…"), false);
    struct Outcome
    {
        KpsClient::Response response;
        QString baseUrl;
        QString token;
        bool isServer = false;
    };
    const auto outcome = AsyncTask::runAndWaitForFuture([=] {
        Outcome o;
        KpsClient client(url);
        const auto status = client.status();
        o.isServer = status.ok()
                     && status.json().value(QStringLiteral("server")).toString() == QStringLiteral("keepass-server");
        if (!o.isServer) {
            o.response = status;
            return o;
        }
        o.response = client.login(username, password, KpsClient::defaultDeviceName());
        o.baseUrl = client.baseUrl();
        o.token = client.token();
        return o;
    });
    if (outcome.response.offline) {
        showStatus(tr("Server not reachable: %1").arg(outcome.response.describe()), true);
        return false;
    }
    if (!outcome.isServer) {
        showStatus(tr("This URL is not a KeePass Server."), true);
        return false;
    }
    if (!outcome.response.ok()) {
        showStatus(tr("Wrong username or password (%1).").arg(outcome.response.describe()), true);
        return false;
    }
    KpsAccount::save({outcome.baseUrl, username, outcome.token});
    m_password->clear();
    showStatus({}, false);
    refresh();
    emit signedIn();
    return true;
}

void KpsConnectionWidget::signOut()
{
    const auto account = KpsAccount::load();
    if (account.isValid()) {
        AsyncTask::runAndWaitForFuture([account] {
            KpsClient(account.serverUrl, account.token).logout();
            return true;
        });
    }
    KpsAccount::signOut();
    refresh();
    emit signedOut();
}
