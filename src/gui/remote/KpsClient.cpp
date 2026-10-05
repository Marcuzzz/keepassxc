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

#include "KpsClient.h"

#include <QCryptographicHash>
#include <QEventLoop>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSysInfo>
#include <QUrl>

namespace
{
    constexpr int TransferTimeoutMs = 30000;

    QByteArray percentEncode(const QString& value)
    {
        return QUrl::toPercentEncoding(value);
    }
} // namespace

QJsonObject KpsClient::Response::json() const
{
    return QJsonDocument::fromJson(body).object();
}

QString KpsClient::Response::describe() const
{
    if (!errorMessage.isEmpty()) {
        return errorMessage;
    }
    return QObject::tr("HTTP %1").arg(status);
}

KpsClient::KpsClient(const QString& baseUrl, const QString& token)
    : m_baseUrl(normalizeUrl(baseUrl))
    , m_token(token)
{
}

QString KpsClient::baseUrl() const
{
    return m_baseUrl;
}

QString KpsClient::token() const
{
    return m_token;
}

QString KpsClient::normalizeUrl(const QString& url)
{
    auto trimmed = url.trimmed();
    while (trimmed.endsWith('/')) {
        trimmed.chop(1);
    }
    if (!trimmed.startsWith(QStringLiteral("http://"), Qt::CaseInsensitive)
        && !trimmed.startsWith(QStringLiteral("https://"), Qt::CaseInsensitive)) {
        trimmed.prepend(QStringLiteral("https://"));
    }
    return trimmed;
}

bool KpsClient::isInsecure(const QString& url)
{
    QUrl parsed(normalizeUrl(url));
    if (parsed.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) != 0) {
        return false;
    }
    const auto host = parsed.host();
    if (host == QStringLiteral("localhost") || host.endsWith(QStringLiteral(".local"))) {
        return false;
    }
    QHostAddress address(host);
    if (address.isNull()) {
        return true;
    }
    return !(address.isLoopback() || address.isInSubnet(QHostAddress(QStringLiteral("10.0.0.0")), 8)
             || address.isInSubnet(QHostAddress(QStringLiteral("172.16.0.0")), 12)
             || address.isInSubnet(QHostAddress(QStringLiteral("192.168.0.0")), 16));
}

QString KpsClient::sha256(const QByteArray& data)
{
    return QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
}

QString KpsClient::defaultDeviceName()
{
    return QStringLiteral("KeePassXC on %1").arg(QSysInfo::machineHostName());
}

KpsClient::Response KpsClient::request(const QByteArray& method,
                                       const QString& path,
                                       const QByteArray& body,
                                       const QHash<QByteArray, QByteArray>& headers)
{
    Response response;
    QNetworkAccessManager manager;
    QNetworkRequest request(QUrl(m_baseUrl + path));
    request.setTransferTimeout(TransferTimeoutMs);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    request.setRawHeader("Accept", "application/json");
    if (!m_token.isEmpty()) {
        request.setRawHeader("Authorization", "Bearer " + m_token.toUtf8());
    }
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
        request.setRawHeader(it.key(), it.value());
    }

    QNetworkReply* reply = manager.sendCustomRequest(request, method, body);
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    response.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (reply->isOpen()) {
        response.body = reply->readAll();
    }
    for (const auto& pair : reply->rawHeaderPairs()) {
        response.headers.insert(pair.first.toLower(), pair.second);
    }
    if (response.status == 0) {
        response.offline = true;
        response.errorMessage = QObject::tr("Cannot reach %1: %2").arg(QUrl(m_baseUrl).host(), reply->errorString());
    } else if (response.status >= 500 && response.status != 501) {
        response.offline = true;
        response.errorMessage = QObject::tr("Server unavailable (%1)").arg(response.status);
    } else if (response.status >= 400) {
        const auto error = response.json().value(QStringLiteral("error")).toObject();
        response.errorCode = error.value(QStringLiteral("code")).toString(QStringLiteral("http_error"));
        response.errorMessage = error.value(QStringLiteral("message")).toString();
        response.currentRevision = error.value(QStringLiteral("currentRevision")).toInt(-1);
    }
    reply->deleteLater();
    return response;
}

KpsClient::Response KpsClient::status()
{
    return request("GET", QStringLiteral("/api/v1/status"));
}

KpsClient::Response KpsClient::login(const QString& username, const QString& password, const QString& deviceName)
{
    QJsonObject body{{QStringLiteral("username"), username},
                     {QStringLiteral("password"), password},
                     {QStringLiteral("deviceName"), deviceName}};
    auto response = request("POST",
                            QStringLiteral("/api/v1/auth/login"),
                            QJsonDocument(body).toJson(QJsonDocument::Compact),
                            {{"Content-Type", "application/json"}});
    if (response.ok()) {
        m_token = response.json().value(QStringLiteral("token")).toString();
    }
    return response;
}

KpsClient::Response KpsClient::logout()
{
    auto response = request("POST", QStringLiteral("/api/v1/auth/logout"));
    m_token.clear();
    return response;
}

KpsClient::Response KpsClient::me()
{
    return request("GET", QStringLiteral("/api/v1/me"));
}

KpsClient::VaultInfo KpsClient::vaultFromJson(const QJsonObject& json)
{
    VaultInfo vault;
    vault.id = json.value(QStringLiteral("id")).toString();
    vault.name = json.value(QStringLiteral("name")).toString();
    vault.role = json.value(QStringLiteral("role")).toString(QStringLiteral("reader"));
    vault.revision = json.value(QStringLiteral("revision")).toInt();
    vault.conflicts = json.value(QStringLiteral("conflicts")).toInt();
    return vault;
}

KpsClient::Response KpsClient::listVaults(QList<VaultInfo>& vaults)
{
    auto response = request("GET", QStringLiteral("/api/v1/vaults"));
    vaults.clear();
    if (response.ok()) {
        for (const auto& value : QJsonDocument::fromJson(response.body).array()) {
            vaults.append(vaultFromJson(value.toObject()));
        }
    }
    return response;
}

KpsClient::Response KpsClient::getVault(const QString& vaultId, VaultInfo& vault)
{
    auto response = request("GET", QStringLiteral("/api/v1/vaults/%1").arg(QString::fromLatin1(percentEncode(vaultId))));
    if (response.ok()) {
        vault = vaultFromJson(response.json());
    }
    return response;
}

KpsClient::Response KpsClient::createVault(const QString& name, VaultInfo& vault)
{
    QJsonObject body{{QStringLiteral("name"), name}};
    auto response = request("POST",
                            QStringLiteral("/api/v1/vaults"),
                            QJsonDocument(body).toJson(QJsonDocument::Compact),
                            {{"Content-Type", "application/json"}});
    if (response.ok()) {
        vault = vaultFromJson(response.json());
    }
    return response;
}

KpsClient::Download KpsClient::download(const QString& vaultId, int knownRevision)
{
    Download download;
    QHash<QByteArray, QByteArray> headers{{"Accept", "application/octet-stream"}};
    if (knownRevision > 0) {
        headers.insert("If-None-Match", "\"" + QByteArray::number(knownRevision) + "\"");
    }
    download.response =
        request("GET", QStringLiteral("/api/v1/vaults/%1/content").arg(QString::fromLatin1(percentEncode(vaultId))), {}, headers);
    if (download.response.status == 304) {
        download.revision = knownRevision;
        return download;
    }
    if (!download.response.ok()) {
        return download;
    }
    download.data = download.response.body;
    download.response.body.clear();
    download.sha256 = sha256(download.data);
    download.revision = download.response.headers.value("x-kps-revision").toInt();
    const auto expected = QString::fromLatin1(download.response.headers.value("x-kps-sha256"));
    if (download.revision <= 0 || expected.compare(download.sha256, Qt::CaseInsensitive) != 0) {
        // Truncated or altered on the way: treat like a network failure and retry later
        download.response.offline = true;
        download.response.errorMessage = QObject::tr("Download was incomplete (checksum mismatch)");
        download.data.clear();
        return download;
    }
    download.changed = true;
    return download;
}

KpsClient::Response
KpsClient::upload(const QString& vaultId, const QByteArray& data, int baseRevision, const QString& note)
{
    QHash<QByteArray, QByteArray> headers{{"Content-Type", "application/octet-stream"},
                                          {"If-Match", "\"" + QByteArray::number(baseRevision) + "\""},
                                          {"X-KPS-SHA256", sha256(data).toLatin1()}};
    if (!note.isEmpty()) {
        headers.insert("X-KPS-Note", percentEncode(note));
    }
    return request(
        "PUT", QStringLiteral("/api/v1/vaults/%1/content").arg(QString::fromLatin1(percentEncode(vaultId))), data, headers);
}

KpsClient::Response
KpsClient::uploadConflict(const QString& vaultId, const QByteArray& data, int baseRevision, const QString& reason)
{
    return request("POST",
                   QStringLiteral("/api/v1/vaults/%1/conflicts").arg(QString::fromLatin1(percentEncode(vaultId))),
                   data,
                   {{"Content-Type", "application/octet-stream"},
                    {"X-KPS-Base-Revision", QByteArray::number(baseRevision)},
                    {"X-KPS-Reason", percentEncode(reason)}});
}

KpsClient::ConnectionTest KpsClient::testConnection(const QString& url,
                                                    const QString& username,
                                                    const QString& password,
                                                    const QString& deviceName)
{
    ConnectionTest test;
    KpsClient client(url);
    auto status = client.status();
    if (status.offline) {
        test.step = ConnectionTest::Reach;
        test.message = status.describe();
        return test;
    }
    if (!status.ok() || status.json().value(QStringLiteral("server")).toString() != QStringLiteral("keepass-server")) {
        test.step = ConnectionTest::Server;
        test.message = QObject::tr("This URL is not a KeePass Server");
        return test;
    }
    auto login = client.login(username, password, deviceName + QStringLiteral(" (connection test)"));
    if (!login.ok()) {
        test.step = login.offline ? ConnectionTest::Reach : ConnectionTest::Login;
        test.message = login.describe();
        return test;
    }
    auto me = client.me();
    client.logout();
    test.ok = me.ok();
    test.step = ConnectionTest::Done;
    test.message = me.json().value(QStringLiteral("username")).toString();
    return test;
}
