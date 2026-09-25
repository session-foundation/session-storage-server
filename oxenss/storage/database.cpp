#include "database.hpp"
#include <SQLiteCpp/Database.h>
#include <SQLiteCpp/Exception.h>
#include <SQLiteCpp/Statement.h>
#include <SQLiteCpp/Transaction.h>
#include <session/sqlite.hpp>
#include <oxenss/logging/oxen_logger.h>
#include <oxenss/utils/string_utils.hpp>
#include <oxenss/utils/time.hpp>
#include <oxenss/common/format.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <limits>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include "oxenss/crypto/keys.h"

#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>

namespace oxenss {

static auto logcat = log::Cat("db");

constexpr std::chrono::milliseconds SQLite_busy_timeout = 15s;

namespace {
    using namespace session::sqlite;
    using util::to_span;

    // session-sqlite's get_all yields tuples for multi-column results; several of our signatures
    // predate that and use pairs.
    template <typename A, typename B, typename... Bind>
    std::vector<std::pair<A, B>> get_all_pairs(SQLite::Statement& st, const Bind&... bind) {
        std::vector<std::pair<A, B>> results;
        for (auto& [a, b] : get_all<A, B>(st, bind...))
            results.emplace_back(std::move(a), std::move(b));
        return results;
    }

}  // namespace

user_pubkey load_pubkey(uint8_t type, std::string pk) {
    return {type, std::move(pk)};
}

void sqlite_swarm_space(
        sqlite3_context* sqlite_context, [[maybe_unused]] int argc, sqlite3_value** argv, bool hi) {
    assert(argc == 1);
    assert(sqlite3_value_bytes(argv[0]));
    auto* key_blob = sqlite3_value_blob(argv[0]);
    auto pubkey = load_pubkey(0 /* irrelevant */, {reinterpret_cast<const char*>(key_blob), 32});
    auto swarm_space = pubkey_to_swarm_space(pubkey);

    if (hi)
        swarm_space = swarm_space >> 32;
    else
        swarm_space = swarm_space & 0xffffffff;

    sqlite3_result_int64(sqlite_context, swarm_space);
}

void sqlite_swarm_space_hi(sqlite3_context* sqlite_context, int argc, sqlite3_value** argv) {
    sqlite_swarm_space(sqlite_context, argc, argv, true);
}

void sqlite_swarm_space_lo(sqlite3_context* sqlite_context, int argc, sqlite3_value** argv) {
    sqlite_swarm_space(sqlite_context, argc, argv, false);
}

/// Schema creation and migration.  This runs once, against the first connection the pool opens;
/// everything else goes through session::sqlite::Connection directly.
class DatabaseImpl {
  public:
    oxenss::Database& parent;
    SQLite::Database& db;

    DatabaseImpl(Database& parent, SQLite::Database& db) : parent{parent}, db{db} {}

    void initialize_database() {
        // state_kv arrived with the swarm sync schema changes, so its absence marks a database
        // from before them.
        const bool pre_swarm_sync = !db.tableExists("state_kv");

        if (!db.tableExists("owners")) {
            create_schema();
        }

        bool have_namespace = false;
        SQLite::Statement msg_cols{db, "PRAGMA main.table_info(messages)"};
        while (msg_cols.executeStep()) {
            auto [cid, name] = get<int64_t, std::string>(msg_cols);
            if (name == "namespace")
                have_namespace = true;
        }

        if (!have_namespace) {
            log::info(logcat, "Upgrading database schema: adding namespace column");
            db.exec(R"(
DROP INDEX IF EXISTS messages_owner;
DROP VIEW IF EXISTS owned_messages;
ALTER TABLE messages ADD COLUMN namespace INTEGER NOT NULL DEFAULT 0;
            )");
        }

        if (db.tableExists("revoked_subkeys")) {
            log::info(logcat, "Upgrading database schema: dropping revoked_subkeys");
            db.exec("DROP TABLE revoked_subkeys");
        }
        if (!db.tableExists("revoked_subaccounts")) {
            log::info(logcat, "Upgrading database schema: adding revoked_subaccounts");
            db.exec(R"(
CREATE TABLE revoked_subaccounts (
    owner INTEGER REFERENCES owners(id) ON DELETE CASCADE,
    token BLOB NOT NULL,
    timestamp INTEGER NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5)*86400000 AS INTEGER)),

    PRIMARY Key(owner, token)
);

CREATE TRIGGER IF NOT EXISTS revoked_autoclean
    AFTER INSERT ON revoked_subaccounts WHEN (SELECT COUNT(*) FROM revoked_subaccounts WHERE owner = NEW.owner) > 50
    BEGIN
        DELETE FROM revoked_subaccounts
            WHERE owner = NEW.owner and token NOT IN (
                SELECT token FROM revoked_subaccounts
                WHERE owner = NEW.owner
                ORDER BY timestamp DESC LIMIT 50
        );
    END;
            )");
        }

        if (pre_swarm_sync) {
            log::info(
                    logcat,
                    "Upgrading database schema: adding swarm space cache, runtime state, "
                    "retryable requests, and public namespace unique constraint");

            // All or nothing: the guard above is the existence of state_kv, created last, so a
            // partial upgrade would fail on the ALTER TABLE at every subsequent start.
            SQLite::Transaction transaction{db, SQLite::TransactionBehavior::IMMEDIATE};

            // swarm space is 64-bit unsigned, which means unfortunately we can't do queries
            // on it with arithmetic properly (sqlite INTEGER is 64-bit signed).  As such, we
            // store it as two separate columns so we can query on it.
            //
            // The added trigger will automatically populate these two columns on insert, and the
            // existing rows will have these columns populated by the UPDATE query after this.
            db.exec(R"(
ALTER TABLE owners ADD COLUMN swarm_space_hi INTEGER NOT NULL DEFAULT -1;
ALTER TABLE owners ADD COLUMN swarm_space_lo INTEGER NOT NULL DEFAULT -1;

CREATE TRIGGER swarm_space_trigger
AFTER INSERT ON owners
FOR EACH ROW
WHEN NEW.swarm_space_hi = -1 OR NEW.swarm_space_lo = -1
BEGIN
    UPDATE owners SET
    swarm_space_hi = func_swarm_space_hi(NEW.pubkey), swarm_space_lo = func_swarm_space_lo(NEW.pubkey)
    WHERE owners.id = NEW.id;
END;
            )");

            db.exec(R"(
UPDATE owners
SET swarm_space_hi = func_swarm_space_hi(pubkey),
swarm_space_lo = func_swarm_space_lo(pubkey)
WHERE swarm_space_hi = -1;
            )");

            db.exec(R"(
CREATE TABLE retry_requests (
    id INTEGER PRIMARY KEY,
    command TEXT NOT NULL,
    payload BLOB NOT NULL,
    -- 2440587.5 is the julian day of the unix epoch, so this is unix time with the subsecond part
    -- retained.  Switch to the more legible `unixepoch('now', 'subsec')` once we require sqlite
    -- 3.42+: `subsec` arrived in 3.42, and Debian bookworm has 3.40, where an unrecognized date
    -- modifier makes the whole expression NULL rather than raising, so the breakage would surface
    -- only as a NOT NULL failure at insertion time.
    created DOUBLE PRECISION NOT NULL DEFAULT ((julianday('now') - 2440587.5) * 86400.0)
);

CREATE TABLE retry_pubkeys (
    id INTEGER PRIMARY KEY,
    pubkey BLOB NOT NULL,
    UNIQUE(pubkey)
);

CREATE TABLE retry_node_requests (
    id INTEGER PRIMARY KEY,
    rr_id INTEGER NOT NULL REFERENCES retry_requests(id) ON DELETE CASCADE,
    pk_id INTEGER NOT NULL REFERENCES retry_pubkeys(id) ON DELETE CASCADE,
    next_retry DOUBLE PRECISION NOT NULL,
    UNIQUE(rr_id, pk_id)
);

CREATE INDEX retry_node_requests_pk_idx ON retry_node_requests(pk_id);

CREATE VIEW retry_node_reqs AS
    SELECT retry_node_requests.id AS rr_id, retry_requests.command, retry_requests.payload,
    retry_pubkeys.pubkey AS pubkey, next_retry
    FROM retry_node_requests
    JOIN retry_requests ON retry_node_requests.rr_id = retry_requests.id
    JOIN retry_pubkeys ON pk_id = retry_pubkeys.id;

CREATE TRIGGER retry_node_add
INSTEAD OF INSERT ON retry_node_reqs
BEGIN
    -- Allows insertion into the view (with the raw pubkey value) to automatically do the pubkey
    -- lookup (with autovivification) for you.
    INSERT OR IGNORE INTO retry_pubkeys (pubkey) VALUES (NEW.pubkey);
    INSERT INTO retry_node_requests (rr_id, pk_id, next_retry)
    VALUES (NEW.rr_id, (SELECT id FROM retry_pubkeys WHERE retry_pubkeys.pubkey = NEW.pubkey), NEW.next_retry);
END;

CREATE TRIGGER rr_cleanup
AFTER DELETE ON retry_node_requests
BEGIN
    -- After deleting a node request record this trigger handles cleaning up any pubkeys or request
    -- commands that are no longer referenced.
    DELETE FROM retry_pubkeys
    WHERE id = OLD.pk_id
        AND NOT EXISTS (
            SELECT 1 FROM retry_node_requests WHERE pk_id = OLD.pk_id
        );
    DELETE FROM retry_requests
    WHERE id = OLD.rr_id
        AND NOT EXISTS (
            SELECT 1 FROM retry_node_requests WHERE rr_id = OLD.rr_id
        );
END;

-- Persistent state that is not messages, e.g. which swarm we were in before a restart.  STRICT so
-- that ANY stores values exactly as given: whoever writes a key knows what type it holds.
CREATE TABLE state_kv (
    key TEXT PRIMARY KEY,
    value ANY
) STRICT, WITHOUT ROWID;

-- A public outbox holds one message, and from here on the unique index below enforces that with
-- the newest message winning.  Older versions applied the rule only on a direct store, not on
-- messages pushed by peers, so an outbox can hold several; keep the newest of each (by timestamp,
-- then id) so the index can be created.
DELETE FROM messages WHERE id IN (
    SELECT id FROM (
        SELECT id, row_number() OVER (PARTITION BY owner, namespace ORDER BY timestamp DESC, id DESC) AS rn
        FROM messages WHERE namespace < 0 AND namespace % 20 = -1
    ) WHERE rn > 1
);

CREATE UNIQUE INDEX message_outbox_singleton
ON messages(owner, namespace)
WHERE namespace < 0 AND namespace % 20 = -1;

            )");

            transaction.commit();
        }

        // Unreleased development builds created state_kv with a TEXT value column holding a
        // bt-encoded swarm id.  Nothing in it is worth converting: losing the swarm id only means
        // one restart cannot tell whether our swarm dissolved while we were down.
        if (db.execAndGet(
                      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'state_kv'")
                    .getString()
                    .find("STRICT") == std::string::npos) {
            log::info(logcat, "Upgrading database schema: recreating state_kv");
            db.exec(R"(
DROP TABLE state_kv;
CREATE TABLE state_kv (
    key TEXT PRIMARY KEY,
    value ANY
) STRICT, WITHOUT ROWID;
            )");
        }

        SQLite::Transaction transaction{db, SQLite::TransactionBehavior::IMMEDIATE};

        // Unreleased development builds keyed pending_dumps and pending_deliveries by the
        // recipient's pubkey itself.  Such tables are moved aside so that the current ones can be
        // created, then their rows are carried over below.
        auto keyed_by_pubkey = [this](const char* table) {
            SQLite::Statement st{db, "SELECT 1 FROM pragma_table_info(?) WHERE name = 'pubkey'"};
            st.bind(1, table);
            return st.executeStep();
        };
        const bool old_dumps = keyed_by_pubkey("pending_dumps");
        const bool old_deliveries = keyed_by_pubkey("pending_deliveries");
        if (old_dumps || old_deliveries)
            log::info(logcat, "Upgrading database schema: keying pending dumps/deliveries by id");
        if (old_dumps)
            db.exec("ALTER TABLE pending_dumps RENAME TO pending_dumps_old");
        if (old_deliveries)
            db.exec(R"(
DROP INDEX pending_deliveries_message;
ALTER TABLE pending_deliveries RENAME TO pending_deliveries_old;
            )");

        // Not part of the pre_swarm_sync upgrade: databases that already went through it exist, and
        // this is cheap to apply unconditionally.
        db.exec(R"(
-- The nodes that pending dumps and deliveries go to, so that those rows refer to their recipient by
-- id rather than each repeating its pubkey.  Recipients that neither table refers to any more are
-- removed by Database::clean_pending_recipients.
CREATE TABLE IF NOT EXISTS pending_recipients (
    id INTEGER PRIMARY KEY,
    pubkey BLOB NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS pending_dumps (
    recipient INTEGER NOT NULL REFERENCES pending_recipients(id),
    swarm INTEGER NOT NULL,
    next_id INTEGER NOT NULL,
    end_id INTEGER NOT NULL,
    next_attempt DOUBLE PRECISION NOT NULL DEFAULT 0,
    PRIMARY KEY(recipient, swarm)
);

CREATE TABLE IF NOT EXISTS pending_deliveries (
    recipient INTEGER NOT NULL REFERENCES pending_recipients(id),
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    PRIMARY KEY(recipient, message)
) WITHOUT ROWID;

-- Deleting a message has to find its pending deliveries, if any
CREATE INDEX IF NOT EXISTS pending_deliveries_message ON pending_deliveries(message);
        )");

        // (The `WHERE true`s are needed for an upsert on INSERT ... SELECT: without one sqlite would
        // parse the ON of ON CONFLICT as a join constraint.)
        if (old_dumps)
            db.exec(R"(
INSERT INTO pending_recipients (pubkey) SELECT pubkey FROM pending_dumps_old WHERE true
    ON CONFLICT DO NOTHING;
INSERT INTO pending_dumps (recipient, swarm, next_id, end_id, next_attempt)
    SELECT pending_recipients.id, swarm, next_id, end_id, next_attempt
    FROM pending_dumps_old JOIN pending_recipients USING (pubkey);
DROP TABLE pending_dumps_old;
            )");
        if (old_deliveries)
            db.exec(R"(
INSERT INTO pending_recipients (pubkey) SELECT pubkey FROM pending_deliveries_old WHERE true
    ON CONFLICT DO NOTHING;
INSERT INTO pending_deliveries (recipient, message)
    SELECT pending_recipients.id, message
    FROM pending_deliveries_old JOIN pending_recipients USING (pubkey);
DROP TABLE pending_deliveries_old;
            )");

        transaction.commit();

        views_triggers_indices();
        log::info(logcat, "Database setup complete");
    }

    void create_schema() {
        SQLite::Transaction transaction{db, SQLite::TransactionBehavior::IMMEDIATE};

        db.exec(R"(
CREATE TABLE owners (
    id INTEGER PRIMARY KEY,
    type INTEGER NOT NULL,
    pubkey BLOB NOT NULL,

    UNIQUE(pubkey, type)
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    hash TEXT NOT NULL,
    owner INTEGER NOT NULL REFERENCES owners(id),
    namespace INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    expiry INTEGER NOT NULL,
    data BLOB NOT NULL,

    UNIQUE(hash)
);
        )");

        if (db.tableExists("Data")) {
            log::warning(logcat, "Old database schema detected; performing migration...");

            // Migratation from old table structure:
            //
            // CREATE TABLE Data(
            //    Hash VARCHAR(128) NOT NULL,
            //    Owner VARCHAR(256) NOT NULL,
            //    TTL INTEGER NOT NULL,
            //    Timestamp INTEGER NOT NULL,
            //    TimeExpires INTEGER NOT NULL,
            //    Nonce VARCHAR(128) NOT NULL,
            //    Data BLOB
            // );

            SQLite::Statement ins_owner{
                    db, "INSERT INTO owners (type, pubkey) VALUES (?, ?) RETURNING id"};

            std::unordered_map<std::string, int> owner_ids;
            SQLite::Statement old_owners{db, "SELECT DISTINCT Owner FROM Data"};
            while (old_owners.executeStep()) {
                int type;
                std::array<char, 32> pubkey;
                std::string old_owner = old_owners.getColumn(0);
                if (old_owner.size() == 66 && old_owner.starts_with("05") &&
                    oxenc::is_hex(old_owner)) {
                    type = 5;
                    oxenc::from_hex(old_owner.begin() + 2, old_owner.end(), pubkey.begin());
                } else if (old_owner.size() == 64 && oxenc::is_hex(old_owner)) {
                    type = 0;
                    oxenc::from_hex(old_owner.begin(), old_owner.end(), pubkey.begin());
                } else {
                    log::warning(
                            logcat,
                            "Found invalid owner pubkey '{}' during migration; ignoring",
                            old_owner);
                    continue;
                }

                int id = exec_and_get<int>(ins_owner, type, old_owner);
                ins_owner.reset();
                owner_ids.emplace(std::move(old_owner), id);
            }

            log::warning(
                    logcat, "Migrated {} owner pubkeys.  Migrating messages...", owner_ids.size());

            SQLite::Statement ins_msg{
                    db,
                    "INSERT INTO messages (hash, owner, timestamp, expiry, "
                    "data) VALUES (?, ?, ?, ?, ?)"};

            SQLite::Statement sel_msgs{
                    db,
                    "SELECT Hash, Owner, Timestamp, TimeExpires, Data FROM Data ORDER BY rowid"};
            int msgs = 0, bad_owners = 0;
            while (sel_msgs.executeStep()) {
                auto [hash, owner, ts, exp, data] =
                        get<const char*, const char*, int64_t, int64_t, std::string>(sel_msgs);
                auto it = owner_ids.find(owner);
                if (it == owner_ids.end()) {
                    bad_owners++;
                    continue;
                }
                exec_query(ins_msg, hash, it->second, ts, exp, data);
                ins_msg.reset();
                msgs++;
            }

            log::warning(
                    logcat,
                    "Migrated {} messages ({} invalid owner ids); dropping old Data table",
                    msgs,
                    bad_owners);

            db.exec("DROP TABLE Data");

            log::warning(logcat, "Data migration complete!");
        }

        transaction.commit();
    }

    void views_triggers_indices() {
        // We create these separate from the table because it makes upgrading easier (we can just
        // drop the indices/views that we want to recreate).

        SQLite::Transaction transaction{db, SQLite::TransactionBehavior::IMMEDIATE};

        // Earlier releases defined messages_owner with a trailing timestamp column; see the CREATE
        // INDEX below for why it is gone.  (The lookup is finished before the DROP: a statement
        // still open on sqlite_master locks the schema against it.)
        bool old_messages_owner = false;
        {
            SQLite::Statement st{
                    db,
                    "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = "
                    "'messages_owner'"};
            old_messages_owner = st.executeStep() &&
                                 st.getColumn(0).getString().find("timestamp") != std::string::npos;
        }
        if (old_messages_owner) {
            log::info(logcat, "Upgrading database schema: rebuilding messages_owner index");
            db.exec("DROP INDEX messages_owner");
        }

        db.exec(R"(
CREATE TRIGGER IF NOT EXISTS owner_autoclean
    AFTER DELETE ON messages FOR EACH ROW WHEN NOT EXISTS (SELECT * FROM messages WHERE owner = old.owner)
    BEGIN
        DELETE FROM owners WHERE id = old.owner;
    END;

CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expiry);

-- Every index entry ends in the rowid, so within one (owner, namespace) this index is in id order,
-- which lets retrieve() page by id from its last-hash cursor straight off the index.  A trailing
-- timestamp column here would order ties by that instead and force a sort on every retrieve.
CREATE INDEX IF NOT EXISTS messages_owner ON messages(owner, namespace);

-- UNIQUE(hash) on the table already provides this index; earlier releases created a duplicate.
DROP INDEX IF EXISTS messages_hash;

DROP INDEX IF EXISTS owners_swarm_hi;
DROP INDEX IF EXISTS owners_swarm_lo;
CREATE INDEX IF NOT EXISTS owners_swarm ON owners(swarm_space_hi, swarm_space_lo);

-- Expired retry requests are looked for every few seconds.  Without this that is a table scan, and
-- as `created` comes after the payload each row's scan walks the payload's overflow pages.
CREATE INDEX IF NOT EXISTS retry_requests_created ON retry_requests(created);

DROP VIEW IF EXISTS owned_messages;
DROP TRIGGER IF EXISTS owned_messages_insert;
DROP TRIGGER IF EXISTS owned_messages_upsert;
)");

        transaction.commit();
    }

    /** Wrapper around a SQLite::Statement that calls `tryReset()` on destruction of the
     * wrapper. */
};

// Applied to every connection the pool opens.  WAL mode, busy_timeout and foreign key enforcement
// are handled by session::sqlite::Database itself, so only what it does not cover is here.
void Database::setup_connection(session::sqlite::Connection& conn) {
    auto& db = conn.sql;

    // sqlite application-defined functions are per-connection.  Registered through the C API rather
    // than SQLiteCpp's createFunction because that offers no way to pass SQLITE_INNOCUOUS: these
    // are called from triggers, and under the PRAGMA trusted_schema = OFF that session-sqlite sets,
    // sqlite rejects any function used in a trigger that is not marked innocuous ("unsafe use of
    // func_swarm_space_hi()").
    for (auto [name, fn] :
         {std::pair{"func_swarm_space_hi", &sqlite_swarm_space_hi},
          std::pair{"func_swarm_space_lo", &sqlite_swarm_space_lo}}) {
        if (int rc = sqlite3_create_function_v2(
                    db.getHandle(),
                    name,
                    1,
                    SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS,
                    nullptr,
                    fn,
                    nullptr,
                    nullptr,
                    nullptr);
            rc != SQLITE_OK) {
            auto m = fmt::format("Failed to register {}: {}", name, sqlite3_errstr(rc));
            log::critical(logcat, "{}", m);
            throw std::runtime_error{m};
        }
    }

    // Not fatal: we can still work without it.
    if (int rc = db.tryExec("PRAGMA synchronous = NORMAL"); rc != SQLITE_OK)
        log::error(logcat, "Failed to set synchronous mode to NORMAL: {}", sqlite3_errstr(rc));

    // The same for every connection, but only obtainable from one.
    int page_size = db.execAndGet("PRAGMA page_size").getInt();
    page_size_.store(page_size, std::memory_order_relaxed);

    // Would use a placeholder here, but sqlite3 apparently doesn't support them for PRAGMAs.
    if (int rc = db.tryExec("PRAGMA max_page_count = {}"_format(SIZE_LIMIT / page_size));
        rc != SQLITE_OK) {
        auto m = fmt::format("Failed to set max page count: {}", sqlite3_errstr(rc));
        log::critical(logcat, "{}", m);
        throw std::runtime_error{m};
    }
}

Database::Database(std::filesystem::path db_path) : db_path_{std::move(db_path)} {
    namespace ss = session::sqlite;
    db_ = std::make_unique<ss::Database>(
            db_path_ / u8"storage.db",
            ss::Encryption::None,
            ss::busy_timeout{SQLite_busy_timeout},
            ss::post_open{[this](ss::Connection& conn) { setup_connection(conn); }});

    {
        auto conn = db_->conn();
        DatabaseImpl{*this, conn.sql}.initialize_database();
    }

    clean_expired();
}

Database::~Database() = default;

/// Database methods obtain a connection from the pool for the duration of their work:
///
///     {
///       auto conn = db_->conn();
///       conn.prepared_exec(...);
///     }
///
/// Connections are independent: WAL mode lets one writer run concurrently with any number of
/// readers, each reader seeing a consistent snapshot, and busy_timeout covers writer contention.
/// Multi-statement sequences that must be atomic use an explicit IMMEDIATE transaction rather than
/// relying on holding a connection; see store() for why DEFERRED is not good enough.

void Database::clean_expired() {
    db_->conn().prepared_exec(
            "DELETE FROM messages WHERE expiry <= ?",
            to_epoch_ms(std::chrono::system_clock::now()));
}

int64_t Database::get_message_count() {
    return db_->conn().prepared_get<int64_t>("SELECT COUNT(*) FROM messages");
}

int64_t Database::get_owner_count() {
    return db_->conn().prepared_get<int64_t>("SELECT COUNT(*) FROM owners");
}

std::vector<int> Database::get_message_counts() {
    auto conn = db_->conn();
    auto st = conn.prepared_st("SELECT COUNT(*) FROM messages GROUP BY owner");
    return get_all<int>(st);
}

std::vector<std::pair<namespace_id, int64_t>> Database::get_namespace_counts() {
    auto conn = db_->conn();
    auto st = conn.prepared_st("SELECT namespace, COUNT(*) FROM messages GROUP BY namespace");
    return get_all_pairs<namespace_id, int64_t>(st);
}

int64_t Database::get_total_bytes() {
    auto conn = db_->conn();
    return conn.prepared_get<int64_t>("PRAGMA page_count") * page_size_;
}

int64_t Database::get_used_bytes() {
    auto conn = db_->conn();
    return get_total_bytes() - conn.prepared_get<int64_t>("PRAGMA freelist_count") * page_size_;
}

std::optional<message> Database::retrieve_by_hash(const std::string& msg_hash) {
    auto conn = db_->conn();
    auto st = conn.prepared_st(
            "SELECT hash, owners.type, owners.pubkey, namespace, timestamp, expiry, data"
            " FROM messages JOIN owners ON messages.owner = owners.id WHERE hash = ?");
    st->bindNoCopy(1, msg_hash);
    std::optional<message> msg;
    while (st->executeStep()) {
        assert(!msg);
        auto [hash, otype, opubkey, ns, ts, exp, data] =
                get<std::string, uint8_t, std::string, namespace_id, int64_t, int64_t, std::string>(
                        st);
        msg.emplace(
                load_pubkey(otype, std::move(opubkey)),
                std::move(hash),
                ns,
                from_epoch_ms(ts),
                from_epoch_ms(exp),
                std::move(data));
    }
    return msg;
}

StoreResult Database::store(const message& msg, std::chrono::system_clock::time_point* expiry) {

    auto conn = db_->conn();

    StoreResult ret;
    try {

        // IMMEDIATE, not the default DEFERRED: this transaction reads (the owner/message lookups
        // below) before it writes, and a deferred transaction that upgrades to a write lock fails
        // with SQLITE_BUSY_SNAPSHOT if anything else committed since the read snapshot was taken.
        // That error does not invoke the busy handler, so busy_timeout cannot retry it.
        SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};

        int64_t owner_id;
        if (auto maybe = exec_and_maybe_get<int64_t>(
                    conn.prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?"),
                    msg.pubkey.raw_bytes(),
                    msg.pubkey.type()))
            owner_id = *maybe;
        else
            owner_id = conn.prepared_get<int64_t>(
                    "INSERT INTO owners (pubkey, type) VALUES (?, ?) RETURNING id",
                    msg.pubkey.raw_bytes(),
                    msg.pubkey.type());

        auto new_exp = to_epoch_ms(msg.expiry);

        if (auto existing = exec_and_maybe_get<int64_t, int64_t>(
                    conn.prepared_st("SELECT id, expiry FROM messages WHERE hash = ?"), msg.hash)) {
            auto& [id, exp] = *existing;
            if (exp < new_exp) {
                conn.prepared_exec("UPDATE messages SET expiry = ? WHERE id = ?", new_exp, id);
                ret = StoreResult::Extended;
                exp = new_exp;
            } else {
                ret = StoreResult::Exists;
            }
            if (expiry)
                *expiry = from_epoch_ms(exp);
        } else {
            auto rows = conn.prepared_exec(
                    "INSERT INTO messages (owner, hash, namespace, timestamp, expiry, data)"
                    " VALUES (?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT (owner, namespace) WHERE namespace < 0 AND namespace % 20 = -1"
                    " DO UPDATE SET"
                    " hash = EXCLUDED.hash, timestamp = EXCLUDED.timestamp,"
                    " expiry = EXCLUDED.expiry, data = EXCLUDED.data"
                    " WHERE EXCLUDED.timestamp > messages.timestamp",
                    owner_id,
                    msg.hash,
                    msg.msg_namespace,
                    to_epoch_ms(msg.timestamp),
                    to_epoch_ms(msg.expiry),
                    to_span(msg.data));

            // did not insert, which means public namespace and not newer
            if (rows == 0)
                return StoreResult::Obsolete;

            ret = StoreResult::New;

            if (expiry)
                *expiry = msg.expiry;
        }

        transaction.commit();

    } catch (const SQLite::Exception& e) {
        if (e.getErrorCode() == SQLITE_FULL) {
            if (db_full_counter++ % DB_FULL_FREQUENCY == 0)
                log::error(logcat, "Failed to store message: database is full");
            return StoreResult::Full;
        } else {
            log::critical(logcat, "Failed to store message: {}", e.getErrorStr());
            throw;
        }
    }
    return ret;
}

void Database::bulk_store(std::span<const message> items) {
    auto conn = db_->conn();
    SQLite::Transaction t{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};
    auto get_owner = conn.prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?");
    auto insert_owner = conn.prepared_st(
            "INSERT INTO owners (pubkey, type) VALUES (?, ?) ON CONFLICT DO NOTHING RETURNING id");
    std::unordered_map<user_pubkey, int64_t> seen;
    for (auto& m : items) {
        if (!m.pubkey)
            continue;
        if (auto [it, ins] = seen.emplace(m.pubkey, 0); ins) {
            auto ownerid =
                    exec_and_maybe_get<int64_t>(get_owner, m.pubkey.raw_bytes(), m.pubkey.type());
            get_owner->reset();
            if (!ownerid) {
                ownerid = exec_and_maybe_get<int64_t>(
                        insert_owner, m.pubkey.raw_bytes(), m.pubkey.type());
                insert_owner->reset();
            }
            if (ownerid)
                it->second = *ownerid;
            else {
                log::error(
                        logcat,
                        "Failed to insert owner {} for bulk store",
                        m.pubkey.prefixed_hex());
                seen.erase(it);
            }
        }
    }

    auto insert_message = conn.prepared_st(
            "INSERT INTO messages (owner, hash, namespace, timestamp, expiry, data)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (hash)"
            " DO UPDATE SET"
            " expiry = MAX(EXCLUDED.expiry, messages.expiry)"
            " ON CONFLICT (owner, namespace) WHERE namespace < 0 AND namespace % 20 = -1"
            " DO UPDATE SET"
            " hash = EXCLUDED.hash, timestamp = EXCLUDED.timestamp,"
            " expiry = EXCLUDED.expiry, data = EXCLUDED.data"
            " WHERE EXCLUDED.timestamp > messages.timestamp");

    for (auto& m : items) {
        if (!m.pubkey)
            continue;
        auto owner_it = seen.find(m.pubkey);
        if (owner_it == seen.end())
            continue;

        exec_query(
                insert_message,
                owner_it->second,
                m.hash,
                m.msg_namespace,
                to_epoch_ms(m.timestamp),
                to_epoch_ms(m.expiry),
                to_span(m.data));
        insert_message->reset();
    }

    t.commit();
}

std::pair<std::vector<message>, bool> Database::retrieve(
        const user_pubkey& pubkey,
        namespace_id ns,
        const std::string& last_hash,
        std::optional<size_t> max_results,
        std::optional<size_t> max_size,
        const bool size_b64,
        const size_t per_message_overhead) {

    auto conn = db_->conn();
    auto owner_st = conn.prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?");
    auto ownerid = exec_and_maybe_get<int64_t>(owner_st, pubkey.raw_bytes(), pubkey.type());
    if (!ownerid)
        return {};

    if (max_results && *max_results < 1)
        max_results = 1;

    std::optional<int64_t> last_id;
    if (!last_hash.empty()) {
        auto st = conn.prepared_st(
                "SELECT id FROM messages WHERE owner = ? AND namespace = ? AND hash = ?");
        last_id = exec_and_maybe_get<int64_t>(st, *ownerid, to_int(ns), last_hash);
    }

    auto st = conn.prepared_st(
            last_id ? "SELECT hash, namespace, timestamp, expiry, data FROM messages "
                      "WHERE owner = ? AND namespace = ? AND id > ? ORDER BY id LIMIT ?"
                    : "SELECT hash, namespace, timestamp, expiry, data FROM messages "
                      "WHERE owner = ? AND namespace = ? ORDER BY id LIMIT ?");
    int pos = 1;
    st->bind(pos++, *ownerid);
    st->bind(pos++, to_int(ns));
    if (last_id)
        st->bind(pos++, *last_id);
    st->bind(pos++, max_results ? static_cast<int>(*max_results) + 1 : -1);

    std::pair<std::vector<message>, bool> result{};
    auto& [results, more] = result;

    size_t agg_size = 0;
    while (st->executeStep()) {
        auto [hash, ns, ts, exp, data] =
                get<std::string, namespace_id, int64_t, int64_t, std::string>(st);
        if (max_results && results.size() >= *max_results) {
            more = true;
            break;
        }
        if (max_size) {
            agg_size += per_message_overhead;
            agg_size += hash.size();
            agg_size += size_b64 ? data.size() * 4 / 3 : data.size();
            if (!results.empty() && agg_size > *max_size) {
                more = true;
                break;
            }
        }

        results.emplace_back(
                std::move(hash), ns, from_epoch_ms(ts), from_epoch_ms(exp), std::move(data));
    }

    return result;
}

std::vector<message> Database::retrieve_all() {
    auto conn = db_->conn();

    std::vector<message> results;
    auto st = conn.prepared_st(
            "SELECT owners.type, owners.pubkey, hash, namespace, timestamp, expiry, data"
            " FROM messages JOIN owners ON messages.owner = owners.id ORDER BY messages.id");

    while (st->executeStep()) {
        auto [type, pubkey, hash, ns, ts, exp, data] =
                get<uint8_t, std::string, std::string, namespace_id, int64_t, int64_t, std::string>(
                        st);
        results.emplace_back(
                load_pubkey(type, pubkey),
                std::move(hash),
                ns,
                from_epoch_ms(ts),
                from_epoch_ms(exp),
                std::move(data));
    }

    return results;
}

std::vector<std::pair<namespace_id, std::string>> Database::delete_all(const user_pubkey& pubkey) {
    auto conn = db_->conn();

    auto st = conn.prepared_st(
            "DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " RETURNING namespace, hash");
    return get_all_pairs<namespace_id, std::string>(st, pubkey.raw_bytes(), pubkey.type());
}

std::vector<std::string> Database::delete_all(const user_pubkey& pubkey, namespace_id ns) {
    auto conn = db_->conn();

    auto st = conn.prepared_st(
            "DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND namespace = ?"
            " RETURNING hash");
    return get_all<std::string>(st, pubkey.raw_bytes(), pubkey.type(), ns);
}

namespace {
    std::string multi_in_query(std::string_view prefix, size_t count, std::string_view suffix) {
        std::string query;
        query.reserve(prefix.size() + (count == 0 ? 0 : 2 * count - 1) + suffix.size());
        query += prefix;
        for (size_t i = 0; i < count; i++) {
            if (i > 0)
                query += ',';
            query += '?';
        }
        query += suffix;
        return query;
    }
}  // namespace

std::vector<std::string> Database::delete_by_hash(
        const user_pubkey& pubkey, std::span<const std::string> msg_hashes) {

    auto conn = db_->conn();

    // One statement per hash, never `owner = ? AND hash IN (...)`: without ANALYZE statistics the
    // planner serves that from messages_owner, scanning every message the owner has (some owners
    // have 100k+), rather than looking each hash up in the unique hash index.  update_expiry and
    // get_expiries do the same.
    std::vector<std::string> deleted;

    SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};

    auto owner = exec_and_maybe_get<int64_t>(
            conn.prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?"),
            pubkey.raw_bytes(),
            pubkey.type());
    if (!owner)
        return deleted;

    auto st = conn.prepared_st("DELETE FROM messages WHERE hash = ? AND owner = ?");
    for (const auto& hash : msg_hashes) {
        if (exec_query(st, hash, *owner) > 0)
            deleted.push_back(hash);
        st->reset();
    }

    transaction.commit();
    return deleted;
}

std::vector<std::pair<namespace_id, std::string>> Database::delete_by_timestamp(
        const user_pubkey& pubkey, std::chrono::system_clock::time_point timestamp) {
    auto conn = db_->conn();

    auto st = conn.prepared_st(
            "DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND timestamp <= ?"
            " RETURNING hash");
    return get_all_pairs<namespace_id, std::string>(
            st, pubkey.raw_bytes(), pubkey.type(), to_epoch_ms(timestamp));
}

std::vector<std::string> Database::delete_by_timestamp(
        const user_pubkey& pubkey,
        namespace_id ns,
        std::chrono::system_clock::time_point timestamp) {
    auto conn = db_->conn();

    auto st = conn.prepared_st(
            "DELETE FROM messages"
            " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND timestamp <= ? AND namespace = ?"
            " RETURNING hash");
    return get_all<std::string>(st, pubkey.raw_bytes(), pubkey.type(), to_epoch_ms(timestamp), ns);
}

static constexpr auto ins_revoke_prefix = "INSERT INTO revoked_subaccounts (owner, token) "sv;
static constexpr auto ins_revoke_suffix =
        " ON CONFLICT(owner, token) DO UPDATE SET timestamp = excluded.timestamp "
        "WHERE revoked_subaccounts.timestamp < excluded.timestamp"sv;

void Database::revoke_subaccounts(
        const user_pubkey& pubkey, std::span<const subaccount_token> subaccounts) {
    if (subaccounts.empty())
        return;

    auto conn = db_->conn();

    if (subaccounts.size() == 1) {
        auto insert_token = conn.prepared_st(fmt::format(
                "{} VALUES ((SELECT id FROM owners WHERE pubkey = ? AND type = ?), ?) {}",
                ins_revoke_prefix,
                ins_revoke_suffix));
        exec_query(insert_token, pubkey.raw_bytes(), pubkey.type(), subaccounts[0].view());
        return;
    }

    SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};

    auto get_owner = conn.prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?");
    auto ownerid = exec_and_maybe_get<int64_t>(get_owner, pubkey.raw_bytes(), pubkey.type());
    if (!ownerid)
        return;

    auto insert_token = conn.prepared_st(
            fmt::format("{} VALUES (?, ?) {}", ins_revoke_prefix, ins_revoke_suffix));

    for (const auto& sa : subaccounts) {
        exec_query(insert_token, *ownerid, sa.view());
        insert_token->reset();
    }

    transaction.commit();
}

int Database::unrevoke_subaccounts(
        const user_pubkey& pubkey, std::span<const subaccount_token> subaccounts) {
    if (subaccounts.empty())
        return 0;

    auto conn = db_->conn();

    if (subaccounts.size() == 1) {
        auto remove_token = conn.prepared_st(
                "DELETE FROM revoked_subaccounts"
                " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                " AND token = ?");
        return exec_query(remove_token, pubkey.raw_bytes(), pubkey.type(), subaccounts[0].view());
    }

    SQLite::Statement st{
            conn.sql,
            multi_in_query(
                    "DELETE FROM revoked_subaccounts"
                    " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                    " AND token IN ("sv,  // ?,?,?,...,?
                    subaccounts.size(),
                    ")"sv)};

    std::vector<std::span<const std::byte>> tokens;
    tokens.reserve(subaccounts.size());
    for (const auto& sa : subaccounts)
        tokens.push_back(sa.view());

    return exec_query(st, pubkey.raw_bytes(), pubkey.type(), bind_each{tokens});
}

bool Database::subaccount_revoked(const user_pubkey& pubkey, const subaccount_token& subaccount) {
    auto conn = db_->conn();

    auto count = exec_and_get<int64_t>(
            conn.prepared_st("SELECT COUNT(*) FROM revoked_subaccounts WHERE token = ? AND "
                             "owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"),
            subaccount.view(),
            pubkey.raw_bytes(),
            pubkey.type());
    return count > 0;
}

std::vector<std::string> Database::revoked_subaccounts(const user_pubkey& pubkey) {
    auto conn = db_->conn();
    auto st = conn.prepared_st(
            "SELECT token FROM revoked_subaccounts WHERE"
            " owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)");
    return get_all<std::string>(st, pubkey.raw_bytes(), pubkey.type());
}

namespace {
    // Message hashes are base64-encoded digests, so decoding just enough of the text to fill a
    // size_t gives uniformly random hash bits without hashing the whole string.  (The text itself
    // is not uniform: each byte is one of only 64 characters.)  Characters that aren't base64
    // decode as 0, which only makes collisions for such (invalid) hashes more likely.
    //
    // Deliberately not noexcept: libstdc++ stores each node's hash code only for a hash that may
    // throw, and otherwise recomputes neighbouring nodes' hashes while walking a bucket, which would
    // repeat this decode.
    struct b64_prefix_hash {
        static constexpr size_t chars = (std::numeric_limits<size_t>::digits + 5) / 6;

        size_t operator()(std::string_view s) const {
            if (s.size() < chars)
                return std::hash<std::string_view>{}(s);
            size_t h = 0;
            for (size_t i = 0; i < chars; i++)
                h = (h << 6) | static_cast<unsigned char>(oxenc::detail::b64_lut.from_b64(
                                       static_cast<unsigned char>(s[i])));
            return h;
        }
    };
}  // namespace

static constexpr auto update_expiry_any =
        "UPDATE messages SET expiry = ?1 WHERE hash = ?2 AND owner = ?3"sv;
static constexpr auto update_expiry_extend =
        "UPDATE messages SET expiry = ?1 WHERE hash = ?2 AND owner = ?3 AND expiry < ?1"sv;
static constexpr auto update_expiry_shorten =
        "UPDATE messages SET expiry = ?1 WHERE hash = ?2 AND owner = ?3 AND expiry > ?1"sv;

std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> Database::update_expiry(
        const user_pubkey& pubkey,
        std::span<const std::string> msg_hashes,
        std::span<const std::chrono::system_clock::time_point> new_exp,
        bool extend_only,
        bool shorten_only) {

    if (new_exp.size() != 1 && new_exp.size() != msg_hashes.size())
        throw std::logic_error{"update_expiry: new_exp must be 1 or N"};

    std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> result;

    if (msg_hashes.empty())
        return result;

    auto conn = db_->conn();

    // One statement per hash; see delete_by_hash.
    SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};

    auto owner = exec_and_maybe_get<int64_t>(
            conn.prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?"),
            pubkey.raw_bytes(),
            pubkey.type());
    if (!owner)
        return result;

    auto st = conn.prepared_st(
            extend_only    ? update_expiry_extend
            : shorten_only ? update_expiry_shorten
                           : update_expiry_any);

    // A repeated hash has to be reported updated only once.  With a single expiry and an
    // extend/shorten constraint a repeat can't match again (the row's expiry now equals the one
    // being set), but with neither constraint it would.
    const bool dedupe = new_exp.size() == 1 && !extend_only && !shorten_only;
    std::unordered_set<std::string_view, b64_prefix_hash> seen;
    if (dedupe)
        seen.reserve(msg_hashes.size());
    for (size_t i = 0; i < msg_hashes.size(); i++) {
        if (dedupe && !seen.insert(msg_hashes[i]).second)
            continue;
        auto exp = new_exp.size() == 1 ? new_exp[0] : new_exp[i];
        if (exec_query(st, to_epoch_ms(exp), msg_hashes[i], *owner) > 0)
            result.emplace_back(msg_hashes[i], exp);
        st->reset();
    }

    transaction.commit();
    return result;
}

std::map<std::string, int64_t> Database::get_expiries(
        const user_pubkey& pubkey, std::span<const std::string> msg_hashes) {
    auto conn = db_->conn();

    // One statement per hash; see delete_by_hash.  The transaction only gives the lookups a single
    // consistent snapshot.
    std::map<std::string, int64_t> result;

    SQLite::Transaction transaction{conn.sql};

    auto owner = exec_and_maybe_get<int64_t>(
            conn.prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?"),
            pubkey.raw_bytes(),
            pubkey.type());
    if (!owner)
        return result;

    auto st = conn.prepared_st("SELECT expiry FROM messages WHERE hash = ? AND owner = ?");
    for (const auto& hash : msg_hashes) {
        if (auto exp = exec_and_maybe_get<int64_t>(st, hash, *owner))
            result.emplace(hash, *exp);
        st->reset();
    }

    transaction.commit();
    return result;
}

std::vector<std::pair<namespace_id, std::string>> Database::update_all_expiries(
        const user_pubkey& pubkey, std::chrono::system_clock::time_point new_exp) {
    auto conn = db_->conn();

    auto new_exp_ms = to_epoch_ms(new_exp);
    auto st = conn.prepared_st(
            "UPDATE messages SET expiry = ?"
            " WHERE expiry > ? AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " RETURNING namespace, hash");
    return get_all_pairs<namespace_id, std::string>(
            st, new_exp_ms, new_exp_ms, pubkey.raw_bytes(), pubkey.type());
}

std::vector<std::string> Database::update_all_expiries(
        const user_pubkey& pubkey, namespace_id ns, std::chrono::system_clock::time_point new_exp) {
    auto conn = db_->conn();

    auto new_exp_ms = to_epoch_ms(new_exp);
    auto st = conn.prepared_st(
            "UPDATE messages SET expiry = ?"
            " WHERE expiry > ? AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
            " AND namespace = ?"
            " RETURNING hash");
    return get_all<std::string>(st, new_exp_ms, new_exp_ms, pubkey.raw_bytes(), pubkey.type(), ns);
}

void oxenss::Database::test_suite_backdate_retries(std::chrono::seconds age) {
    auto conn = db_->conn();
    conn.prepared_exec(
            "UPDATE retry_node_requests SET next_retry = next_retry - ?",
            std::chrono::duration<double>{age}.count());
}

int64_t Database::add_retry_request(
        const crypto::legacy_pubkey& key,
        const std::string& cmd,
        const std::string& payload,
        int64_t req_id) {
    auto conn = db_->conn();

    // The two inserts have to land together: the second one is what makes the first one reachable,
    // so a failure between them would leave an orphaned retry_requests row that nothing retries.
    SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};

    // insert into request table if not present
    if (req_id == 0) {
        req_id = conn.prepared_get<int64_t>(
                "INSERT INTO retry_requests (command, payload) values (?,?) RETURNING id",
                cmd,
                payload);
    }

    conn.prepared_exec(
            "INSERT INTO retry_node_reqs (rr_id, pubkey, next_retry) VALUES(?, ?, ?)",
            req_id,
            key.str(),
            to_epoch_double(std::chrono::system_clock::now() + RETRY_INITIAL_DELAY));

    transaction.commit();

    return req_id;
}

void Database::foreach_ready_retry_request(std::function<
                                           bool(const crypto::legacy_pubkey& key,
                                                const std::string& cmd,
                                                const std::string& payload,
                                                int64_t req_id)> callback) {
    auto conn = db_->conn();

    // Collect everything first: SQLite does not guarantee a SELECT cursor sees consistent results
    // if the table it is reading is updated on the same connection mid-iteration.
    //
    // See the retry_requests.created default for why this isn't `unixepoch('now', 'subsec')`.
    auto ready = get_all<int64_t, std::string, std::string, std::string>(
            conn.prepared_st("SELECT rr_id, pubkey, command, payload FROM retry_node_reqs"
                             " WHERE next_retry < (julianday('now') - 2440587.5) * 86400.0"));

    // The next retry time is set here, before the outcome of the request is known, rather than
    // when the request times out: a successful or definitively failed request deletes the row
    // (making this update moot), and doing it here avoids a second write on every timeout.
    auto now = std::chrono::system_clock::now();
    auto sent_retry = to_epoch_double(now + RETRY_INTERVAL);
    auto unsent_retry = to_epoch_double(now + RETRY_NO_CONTACT_INTERVAL);

    // The callback dispatches network requests, so the updates are accumulated here and applied
    // together afterwards rather than one per iteration: a transaction around this loop would hold
    // the write lock open across every dispatch.  If we die partway through then the rows already
    // dispatched keep their old next_retry and simply come up for retry again sooner, which is
    // harmless.
    std::vector<std::pair<int64_t, double>> updates;
    updates.reserve(ready.size());
    for (auto& [req_id, key_str, cmd, payload] : ready) {
        bool sent = callback(crypto::legacy_pubkey::from_bytes(key_str), cmd, payload, req_id);
        updates.emplace_back(req_id, sent ? sent_retry : unsent_retry);
    }

    SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};
    for (const auto& [req_id, next_retry] : updates)
        conn.prepared_exec(
                "UPDATE retry_node_requests SET next_retry = ? WHERE id = ?", next_retry, req_id);
    transaction.commit();
}

int64_t Database::retry_request_count() {
    auto conn = db_->conn();
    return conn.prepared_get<int64_t>("SELECT COUNT(*) from retry_node_reqs");
}

namespace {

    // A query over the owners in a (lower, upper] swarm space range, in the three forms such a
    // range needs: the whole space (lower == upper), a plain range, and one that wraps around the
    // top of the space (lower > upper).  Parameters ?1-?4 are the high and low 32-bit halves of
    // lower and upper: swarm space is unsigned 64-bit and sqlite integers are signed, so the halves
    // are stored separately and compared as a row value.
    struct swarm_range_query {
        std::string all, between, wrapped;

        // `query` has a single `{}` where the range condition goes.
        explicit swarm_range_query(fmt::format_string<std::string> query) :
                all{fmt::format(query, "1"s)},
                between{fmt::format(query, "({} AND {})"_format(above_lower, at_most_upper))},
                wrapped{fmt::format(query, "({} OR {})"_format(above_lower, at_most_upper))} {}

        const std::string& get(uint64_t lower, uint64_t upper) const {
            return lower == upper ? all : lower < upper ? between : wrapped;
        }

      private:
        static constexpr auto above_lower =
                "(owners.swarm_space_hi, owners.swarm_space_lo) > (?1, ?2)"sv;
        static constexpr auto at_most_upper =
                "(owners.swarm_space_hi, owners.swarm_space_lo) <= (?3, ?4)"sv;
    };

    void bind_swarm_range(SQLite::Statement& st, uint64_t lower, uint64_t upper) {
        if (lower == upper)
            return;
        st.bind(1, static_cast<int64_t>(lower >> 32));
        st.bind(2, static_cast<int64_t>(lower & 0xffffffff));
        st.bind(3, static_cast<int64_t>(upper >> 32));
        st.bind(4, static_cast<int64_t>(upper & 0xffffffff));
    }

}  // namespace

static const swarm_range_query has_owners_in_range_sql{
        "SELECT EXISTS(SELECT 1 FROM owners WHERE {})"};

bool Database::has_owners_in_range(uint64_t lower, uint64_t upper) {
    auto conn = db_->conn();
    auto st = conn.prepared_st(has_owners_in_range_sql.get(lower, upper));
    bind_swarm_range(*st, lower, upper);
    st->executeStep();
    return get<int64_t>(*st) != 0;
}

int64_t Database::max_message_id() {
    return db_->conn().prepared_get<int64_t>("SELECT COALESCE(MAX(id), 0) FROM messages");
}

static constexpr auto insert_pending_recipient =
        "INSERT INTO pending_recipients (pubkey) VALUES (?) ON CONFLICT DO NOTHING"sv;

void Database::queue_dump(const crypto::legacy_pubkey& pubkey, uint64_t swarm, int64_t end_id) {
    auto conn = db_->conn();

    // One transaction so that clean_pending_recipients can't remove a new recipient before the
    // dump refers to it.
    SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};
    conn.prepared_exec(insert_pending_recipient, pubkey.str());
    conn.prepared_exec(
            "INSERT INTO pending_dumps (recipient, swarm, next_id, end_id)"
            " SELECT id, ?, 1, ? FROM pending_recipients WHERE pubkey = ?"
            " ON CONFLICT (recipient, swarm) DO UPDATE SET"
            " next_id = 1, end_id = MAX(pending_dumps.end_id, excluded.end_id), next_attempt = 0",
            static_cast<int64_t>(swarm),
            end_id,
            pubkey.str());
    transaction.commit();
}

std::vector<Database::pending_dump> Database::pending_dumps() {
    auto conn = db_->conn();
    std::vector<pending_dump> result;
    for (auto& [pk, swarm, next_id, end_id, next_attempt] :
         get_all<std::string, int64_t, int64_t, int64_t, double>(conn.prepared_st(
                 "SELECT pubkey, swarm, next_id, end_id, next_attempt"
                 " FROM pending_dumps JOIN pending_recipients ON pending_recipients.id = recipient")))
        result.push_back(
                {crypto::legacy_pubkey::from_bytes(pk),
                 static_cast<uint64_t>(swarm),
                 next_id,
                 end_id,
                 from_epoch_double(next_attempt)});
    return result;
}

void Database::update_dump(
        const crypto::legacy_pubkey& pubkey,
        uint64_t swarm,
        int64_t next_id,
        std::chrono::system_clock::time_point next_attempt) {
    auto conn = db_->conn();
    conn.prepared_exec(
            "UPDATE pending_dumps SET next_id = ?, next_attempt = ?"
            " WHERE recipient = (SELECT id FROM pending_recipients WHERE pubkey = ?) AND swarm = ?",
            next_id,
            to_epoch_double(next_attempt),
            pubkey.str(),
            static_cast<int64_t>(swarm));
}

void Database::remove_dump(const crypto::legacy_pubkey& pubkey, uint64_t swarm) {
    auto conn = db_->conn();
    conn.prepared_exec(
            "DELETE FROM pending_dumps"
            " WHERE recipient = (SELECT id FROM pending_recipients WHERE pubkey = ?) AND swarm = ?",
            pubkey.str(),
            static_cast<int64_t>(swarm));
}

static const swarm_range_query next_dump_batch_sql{R"(
SELECT messages.id, owners.type, owners.pubkey, messages.hash, messages.namespace,
       messages.timestamp, messages.expiry, messages.data
FROM messages JOIN owners ON messages.owner = owners.id
WHERE messages.id >= ?5 AND messages.id <= ?6 AND {}
ORDER BY messages.id)"};

std::pair<std::vector<message>, int64_t> Database::next_dump_batch(
        int64_t from_id, int64_t end_id, uint64_t lower, uint64_t upper, size_t byte_budget) {
    auto conn = db_->conn();
    auto st = conn.prepared_st(next_dump_batch_sql.get(lower, upper));
    bind_swarm_range(*st, lower, upper);
    st->bind(5, from_id);
    st->bind(6, end_id);

    std::pair<std::vector<message>, int64_t> result{{}, 0};
    auto& [messages, last_id] = result;
    size_t size = 0;
    while (size < byte_budget && st->executeStep()) {
        auto [id, type, pubkey, hash, ns, ts, exp, data] =
                get<int64_t,
                    uint8_t,
                    std::string,
                    std::string,
                    namespace_id,
                    int64_t,
                    int64_t,
                    std::string>(*st);
        // Approximately the serialized size; the constant covers the pubkey, timestamps, namespace
        // and bt framing.
        size += data.size() + hash.size() + 80;
        last_id = id;
        messages.emplace_back(
                load_pubkey(type, pubkey),
                std::move(hash),
                ns,
                from_epoch_ms(ts),
                from_epoch_ms(exp),
                std::move(data));
    }
    return result;
}

static constexpr auto queue_delivery_sql =
        "INSERT INTO pending_deliveries (recipient, message)"
        " SELECT pending_recipients.id, messages.id FROM pending_recipients, messages"
        " WHERE pending_recipients.pubkey = ?1 AND messages.hash = ?2"
        " ON CONFLICT DO NOTHING"sv;

void Database::queue_delivery(const crypto::legacy_pubkey& pubkey, const std::string& hash) {
    auto conn = db_->conn();

    // Almost always the recipient already exists and this one statement queues the delivery.
    if (conn.prepared_exec(queue_delivery_sql, pubkey.str(), hash) > 0)
        return;

    // Nothing inserted: this is the recipient's first pending delivery (so no pending_recipients
    // row yet), or it is already queued, or the message is gone.  Add the recipient and retry, in
    // one transaction so that clean_pending_recipients can't remove the recipient in between, and
    // rolled back if the retry inserts nothing either so that the recipient isn't left unused.
    SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};
    conn.prepared_exec(insert_pending_recipient, pubkey.str());
    if (conn.prepared_exec(queue_delivery_sql, pubkey.str(), hash) > 0)
        transaction.commit();
}

std::vector<crypto::legacy_pubkey> Database::delivery_peers() {
    auto conn = db_->conn();
    std::vector<crypto::legacy_pubkey> peers;
    // A recipient may have only dumps pending, or nothing at all until clean_pending_recipients
    // next runs.
    auto st = conn.prepared_st(
            "SELECT pubkey FROM pending_recipients WHERE EXISTS"
            " (SELECT 1 FROM pending_deliveries WHERE recipient = pending_recipients.id)");
    while (st->executeStep())
        peers.push_back(crypto::legacy_pubkey::from_bytes(get<std::string>(st)));
    return peers;
}

void Database::clean_pending_recipients() {
    db_->conn().prepared_exec(
            "DELETE FROM pending_recipients WHERE"
            " NOT EXISTS (SELECT 1 FROM pending_dumps WHERE recipient = pending_recipients.id) AND"
            " NOT EXISTS (SELECT 1 FROM pending_deliveries WHERE recipient = pending_recipients.id)");
}

std::pair<std::vector<message>, std::vector<int64_t>> Database::next_delivery_batch(
        const crypto::legacy_pubkey& pubkey, size_t byte_budget) {
    auto conn = db_->conn();
    // Ordered by pending_deliveries.message rather than the equal messages.id: the primary key
    // (recipient, message) already yields the peer's rows in that order, but the planner does not
    // carry the join equality into ORDER BY and would sort the whole backlog before the byte
    // budget could stop the scan.
    auto st = conn.prepared_st(
            "SELECT messages.id, owners.type, owners.pubkey, hash, namespace, timestamp, expiry,"
            " data"
            " FROM pending_deliveries"
            " JOIN messages ON messages.id = pending_deliveries.message"
            " JOIN owners ON owners.id = messages.owner"
            " WHERE pending_deliveries.recipient ="
            " (SELECT id FROM pending_recipients WHERE pubkey = ?)"
            " ORDER BY pending_deliveries.message");
    st->bind(1, pubkey.str());

    std::pair<std::vector<message>, std::vector<int64_t>> result;
    auto& [messages, ids] = result;
    size_t size = 0;
    while (size < byte_budget && st->executeStep()) {
        auto [id, type, pubkey, hash, ns, ts, exp, data] =
                get<int64_t,
                    uint8_t,
                    std::string,
                    std::string,
                    namespace_id,
                    int64_t,
                    int64_t,
                    std::string>(st);
        size += data.size() + hash.size() + 80;
        ids.push_back(id);
        messages.emplace_back(
                load_pubkey(type, pubkey),
                std::move(hash),
                ns,
                from_epoch_ms(ts),
                from_epoch_ms(exp),
                std::move(data));
    }
    return result;
}

void Database::remove_deliveries(
        const crypto::legacy_pubkey& pubkey, std::span<const int64_t> ids) {
    auto conn = db_->conn();
    SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};
    auto recipient = exec_and_maybe_get<int64_t>(
            conn.prepared_st("SELECT id FROM pending_recipients WHERE pubkey = ?"), pubkey.str());
    if (!recipient)
        return;
    auto st = conn.prepared_st(
            "DELETE FROM pending_deliveries WHERE recipient = ? AND message = ?");
    for (auto id : ids) {
        exec_query(st, *recipient, id);
        st->reset();
    }
    transaction.commit();
}

void Database::remove_deliveries(const crypto::legacy_pubkey& pubkey) {
    db_->conn().prepared_exec(
            "DELETE FROM pending_deliveries"
            " WHERE recipient = (SELECT id FROM pending_recipients WHERE pubkey = ?)",
            pubkey.str());
}

void Database::remove_node_retry_request(int64_t req_id) {
    auto conn = db_->conn();
    conn.prepared_exec("DELETE FROM retry_node_requests WHERE id = ?", req_id);
}

void Database::remove_expired_retry_requests(std::chrono::system_clock::time_point now) {
    auto conn = db_->conn();

    conn.prepared_exec(
            "DELETE FROM retry_requests WHERE created < ?", to_epoch_double(now - RETRY_EXPIRY));
}

void Database::update_current_swarm(uint64_t swarm_id) {
    db_->conn().prepared_exec(
            "INSERT OR REPLACE INTO state_kv (key, value) VALUES ('swarm_id', ?)",
            static_cast<int64_t>(swarm_id));
}

std::optional<uint64_t> Database::get_current_swarm() {
    auto conn = db_->conn();
    if (auto id = exec_and_maybe_get<int64_t>(
                conn.prepared_st("SELECT value FROM state_kv WHERE key = 'swarm_id'")))
        return static_cast<uint64_t>(*id);
    return std::nullopt;
}

}  // namespace oxenss
