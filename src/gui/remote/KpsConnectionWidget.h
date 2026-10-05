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

#ifndef KEEPASSXC_KPSCONNECTIONWIDGET_H
#define KEEPASSXC_KPSCONNECTIONWIDGET_H

#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QWidget;

/**
 * Sign in to keepass-server: URL, username, password and "Test connection".
 * When an account is stored it shows "Signed in as …" with a "Sign out" button instead.
 */
class KpsConnectionWidget : public QWidget
{
    Q_OBJECT

public:
    explicit KpsConnectionWidget(QWidget* parent = nullptr);

    bool isSignedIn() const;
    /** Tests the entered credentials and stores a device token; shows the result. */
    bool signIn();

signals:
    void signedIn();
    void signedOut();

private slots:
    void testConnection();
    void signOut();

private:
    void refresh();
    void showStatus(const QString& text, bool error);
    bool readFields(QString& url, QString& username, QString& password);

    QWidget* m_form;
    QWidget* m_signedInRow;
    QLabel* m_signedInLabel;
    QLineEdit* m_url;
    QLineEdit* m_username;
    QLineEdit* m_password;
    QPushButton* m_testButton;
    QLabel* m_status;
};

#endif // KEEPASSXC_KPSCONNECTIONWIDGET_H
