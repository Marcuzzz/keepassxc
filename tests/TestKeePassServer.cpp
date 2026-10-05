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

#include "TestKeePassServer.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QStandardPaths>
#include <QTest>

#include "config-keepassx-tests.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "crypto/Crypto.h"
#include "gui/remote/KpsClient.h"
#include "gui/remote/KpsSyncEngine.h"
#include "gui/remote/KpsVault.h"
#include "keys/PasswordKey.h"

QTEST_GUILESS_MAIN(TestKeePassServer)

namespace
{
    using Outcome = KpsSyncEngine::Outcome;

    QString url()
    {
        return qEnvironmentVariable("KPS_TEST_URL");
    }

    QSharedPointer<CompositeKey> passwordKey(const QString& password)
    {
        auto key = QSharedPointer<CompositeKey>::create();
        key->addKey(QSharedPointer<PasswordKey>::create(password));
        return key;
    }

    /** A "device" is a separate app data directory with its own local copies. */
    void useDevice(const QString& name)
    {
        QCoreApplication::setApplicationName(QStringLiteral("kps-test-") + name);
    }

    KpsClient signedIn()
    {
        KpsClient client(url());
        client.login(qEnvironmentVariable("KPS_TEST_USER"), qEnvironmentVariable("KPS_TEST_PASSWORD"), "test");
        return client;
    }

    KpsSyncEngine::Result sync(const QSharedPointer<Database>& db, KpsVault& vault, KpsClient& client)
    {
        return KpsSyncEngine::sync(
            db,
            vault,
            client,
            false,
            [](const std::function<void()>& step) {
                step();
                return true;
            },
            [db](QString* error) { return db->save(Database::Atomic, {}, error); });
    }

    void addEntry(const QSharedPointer<Database>& db, const QString& title)
    {
        auto entry = new Entry();
        entry->setUuid(QUuid::createUuid());
        entry->setTitle(title);
        entry->setGroup(db->rootGroup());
    }

    QStringList titles(const QSharedPointer<Database>& db)
    {
        QStringList list;
        for (const auto* entry : db->rootGroup()->entriesRecursive()) {
            if (!entry->group()->isRecycled() && entry->group() != db->metadata()->recycleBin()) {
                list << entry->title();
            }
        }
        list.sort();
        return list;
    }

    /** Device saves a local change: like KpsDatabaseSync::onSaved. */
    void saveLocally(const QSharedPointer<Database>& db, KpsVault& vault)
    {
        QString error;
        QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
        vault.state().dirty = true;
        vault.save();
    }

    /** Creates a vault on the server with a fresh database from device "A". */
    struct Setup
    {
        QString vaultId;
        QSharedPointer<KpsVault> vaultA;
        QSharedPointer<Database> dbA;
    };

    Setup createVault(KpsClient& client, const QString& name)
    {
        Setup setup;
        KpsClient::VaultInfo info;
        client.createVault(name, info);
        setup.vaultId = info.id;
        useDevice("A");
        setup.vaultA = KpsVault::getOrCreate(url(), info.id, name);
        setup.dbA = QSharedPointer<Database>::create();
        setup.dbA->open(QStringLiteral(KEEPASSX_TEST_DATA_DIR).append("/NewDatabase.kdbx"), passwordKey("a"));
        setup.dbA->saveAs(setup.vaultA->filePath());
        addEntry(setup.dbA, "shared");
        saveLocally(setup.dbA, *setup.vaultA);
        return setup;
    }

    /** Device "B" downloads the vault and opens it. */
    QSharedPointer<Database> cloneOnB(KpsClient& client, const QString& vaultId, QSharedPointer<KpsVault>& vaultB)
    {
        useDevice("B");
        vaultB = KpsVault::getOrCreate(url(), vaultId, "clone");
        auto download = client.download(vaultId);
        vaultB->adopt(download.data, download.revision, download.sha256);
        auto db = QSharedPointer<Database>::create();
        db->open(vaultB->filePath(), passwordKey("a"));
        return db;
    }
} // namespace

void TestKeePassServer::initTestCase()
{
    QVERIFY(Crypto::init());
    QStandardPaths::setTestModeEnabled(true);
    if (url().isEmpty()) {
        QSKIP("Set KPS_TEST_URL, KPS_TEST_USER and KPS_TEST_PASSWORD to run against a keepass-server");
    }
    for (const auto& device : {"A", "B"}) {
        useDevice(device);
        QDir(KpsVault::rootDir()).removeRecursively();
    }
}

void TestKeePassServer::testConnection()
{
    const auto ok = KpsClient::testConnection(
        url(), qEnvironmentVariable("KPS_TEST_USER"), qEnvironmentVariable("KPS_TEST_PASSWORD"), "test");
    QVERIFY2(ok.ok, qPrintable(ok.message));
    const auto wrong = KpsClient::testConnection(url(), qEnvironmentVariable("KPS_TEST_USER"), "wrong-password", "test");
    QCOMPARE(wrong.step, KpsClient::ConnectionTest::Login);
    const auto unreachable = KpsClient::testConnection("http://127.0.0.1:1", "x", "y", "test");
    QCOMPARE(unreachable.step, KpsClient::ConnectionTest::Reach);
}

void TestKeePassServer::testTwoDevicesOfflineMerge()
{
    auto client = signedIn();
    auto setup = createVault(client, "merge");
    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::Pushed);

    QSharedPointer<KpsVault> vaultB;
    auto dbB = cloneOnB(client, setup.vaultId, vaultB);
    QVERIFY(titles(dbB).contains("shared"));

    // Both devices edit "offline"
    useDevice("A");
    addEntry(setup.dbA, "from A");
    saveLocally(setup.dbA, *setup.vaultA);
    useDevice("B");
    addEntry(dbB, "from B");
    saveLocally(dbB, *vaultB);

    useDevice("A");
    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::Pushed);
    useDevice("B");
    const auto merged = sync(dbB, *vaultB, client);
    QCOMPARE(merged.outcome, Outcome::Merged);
    QVERIFY(titles(dbB).contains("from A") && titles(dbB).contains("from B"));
    QVERIFY(!vaultB->state().dirty);

    useDevice("A");
    const auto pulled = sync(setup.dbA, *setup.vaultA, client);
    QCOMPARE(pulled.outcome, Outcome::Pulled);
    QCOMPARE(pulled.revision, merged.revision);
    QCOMPARE(titles(setup.dbA), titles(dbB));
    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::UpToDate);
}

void TestKeePassServer::testServerUnreachable()
{
    auto client = signedIn();
    auto setup = createVault(client, "unreachable");
    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::Pushed);

    addEntry(setup.dbA, "written offline");
    saveLocally(setup.dbA, *setup.vaultA);
    KpsClient down(QStringLiteral("http://127.0.0.1:1"), client.token());
    QCOMPARE(sync(setup.dbA, *setup.vaultA, down).outcome, Outcome::Offline);
    QVERIFY(setup.vaultA->state().dirty);

    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::Pushed);
    QVERIFY(!setup.vaultA->state().dirty);
}

void TestKeePassServer::testWorkOffline()
{
    auto client = signedIn();
    auto setup = createVault(client, "work offline");
    setup.vaultA->state().workOffline = true;
    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::WorkOffline);
    KpsClient::VaultInfo info;
    client.getVault(setup.vaultId, info);
    QCOMPARE(info.revision, 0);
    setup.vaultA->state().workOffline = false;
    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::Pushed);
}

void TestKeePassServer::testMasterKeyChangedElsewhere()
{
    auto client = signedIn();
    auto setup = createVault(client, "key change");
    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::Pushed);
    QSharedPointer<KpsVault> vaultB;
    auto dbB = cloneOnB(client, setup.vaultId, vaultB);

    useDevice("A");
    setup.dbA->setKey(passwordKey("a brand new password"));
    saveLocally(setup.dbA, *setup.vaultA);
    QCOMPARE(sync(setup.dbA, *setup.vaultA, client).outcome, Outcome::Pushed);

    useDevice("B");
    addEntry(dbB, "unsynced on B");
    saveLocally(dbB, *vaultB);
    const auto result = sync(dbB, *vaultB, client);
    QCOMPARE(result.outcome, Outcome::KeyChanged);
    QVERIFY(QFile::exists(result.detail));
    QVERIFY(vaultB->state().needsReopen);
    QCOMPARE(sync(dbB, *vaultB, client).outcome, Outcome::NeedsReopen);

    KpsClient::VaultInfo info;
    client.getVault(setup.vaultId, info);
    QCOMPARE(info.conflicts, 1);
    // The local file now holds the server version with the new key
    auto reopened = QSharedPointer<Database>::create();
    QVERIFY(reopened->open(vaultB->filePath(), passwordKey("a brand new password")));
}
