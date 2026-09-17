#include "database.hpp"
#include <SQLiteCpp/Database.h>
#include <SQLiteCpp/Exception.h>
#include <SQLiteCpp/Statement.h>
#include <SQLiteCpp/Transaction.h>
#include <session/sqlite.hpp>
#include <oxenss/logging/oxen_logger.h>
#include <limits>
#include <oxenss/utils/string_utils.hpp>
#include <oxenss/utils/time.hpp>
#include <oxenss/common/format.h>
#include <oxenc/hex.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include "oxenc/bt_serialize.h"
#include "oxenc/bt_value.h"
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

    // session-sqlite has no map-producing counterpart to get_all.
    template <typename K, typename V, typename... Bind>
    std::map<K, V> get_map(SQLite::Statement& st, const Bind&... bind) {
        bind_oneshot(st, bind...);
        std::map<K, V> results;
        while (st.executeStep()) {
            auto [k, v] = get<K, V>(st);
            results.emplace(std::move(k), std::move(v));
        }
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
        parent._had_swarm_state_on_open = db.tableExists("state_kv");

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

        if (!parent._had_swarm_state_on_open) {
            log::info(
                    logcat,
                    "Upgrading database schema: adding swarm space cache, runtime state, "
                    "retryable requests, and public namespace unique constraint");

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

-- Generic key->value store for the database
-- in future, we may explicitly require TEXT for keys, but arbitrary type for values.
-- store arbitrary persistent state, e.g. which swarm were we in before restart
CREATE TABLE state_kv (
    key TEXT NOT NULL,
    value TEXT,
    UNIQUE(key)
);

-- public namespaces are at most used for testing before this migration, so clear them before
-- adding the unique owner/namespace index
DELETE FROM messages WHERE namespace < 0 AND namespace % 20 = -1;

CREATE UNIQUE INDEX message_outbox_singleton
ON messages(owner, namespace)
WHERE namespace < 0 AND namespace % 20 = -1;

            )");
        }

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
                if (old_owner.size() == 66 && util::starts_with(old_owner, "05") &&
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

        db.exec(R"(
CREATE TRIGGER IF NOT EXISTS owner_autoclean
    AFTER DELETE ON messages FOR EACH ROW WHEN NOT EXISTS (SELECT * FROM messages WHERE owner = old.owner)
    BEGIN
        DELETE FROM owners WHERE id = old.owner;
    END;

CREATE INDEX IF NOT EXISTS messages_expiry ON messages(expiry);
CREATE INDEX IF NOT EXISTS messages_owner ON messages(owner, namespace, timestamp);
CREATE INDEX IF NOT EXISTS messages_hash ON messages(hash);

CREATE INDEX IF NOT EXISTS owners_swarm_hi ON owners(swarm_space_hi);
CREATE INDEX IF NOT EXISTS owners_swarm_lo ON owners(swarm_space_lo);

CREATE VIEW IF NOT EXISTS owned_messages AS
    SELECT owners.id AS oid, type, pubkey, messages.id AS mid, hash, namespace, timestamp, expiry, data
    FROM messages JOIN owners ON messages.owner = owners.id;

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
            "SELECT hash, type, pubkey, namespace, timestamp, expiry, data"
            " FROM owned_messages WHERE hash = ?");
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

void Database::bulk_store(const std::vector<message>& items) {
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
            "SELECT type, pubkey, hash, namespace, timestamp, expiry, data"
            " FROM owned_messages ORDER BY mid");

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
        const user_pubkey& pubkey, const std::vector<std::string>& msg_hashes) {

    auto conn = db_->conn();

    if (msg_hashes.size() == 1) {
        // Use an optimized prepared statement for very common single-hash deletions
        auto st = conn.prepared_st(
                "DELETE FROM messages"
                " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                " AND hash = ?"
                " RETURNING hash");
        return get_all<std::string>(st, pubkey.raw_bytes(), pubkey.type(), msg_hashes[0]);
    }

    SQLite::Statement st{
            conn.sql,
            multi_in_query(
                    "DELETE FROM messages"
                    " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                    " AND hash IN ("sv,  // ?,?,?,...,?
                    msg_hashes.size(),
                    ") RETURNING hash"sv)};

    return get_all<std::string>(st, pubkey.raw_bytes(), pubkey.type(), bind_each{msg_hashes});
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
        const user_pubkey& pubkey, const std::vector<subaccount_token>& subaccounts) {
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
        const user_pubkey& pubkey, const std::vector<subaccount_token>& subaccounts) {
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

std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> Database::update_expiry(
        const user_pubkey& pubkey,
        const std::vector<std::string>& msg_hashes,
        const std::vector<std::chrono::system_clock::time_point> new_exp,
        bool extend_only,
        bool shorten_only) {

    if (new_exp.size() != 1 && new_exp.size() != msg_hashes.size())
        throw std::logic_error{"update_expiry: new_exp must be 1 or N"};

    std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> result;

    if (msg_hashes.empty())
        return result;

    auto expiry_constraint = extend_only  ? " AND expiry < ?1"s
                           : shorten_only ? " AND expiry > ?1"s
                                          : ""s;

    auto conn = db_->conn();

    if (msg_hashes.size() == 1) {
        // Pre-prepared version for the common single hash case
        if (conn.prepared_exec(
                    "UPDATE messages SET expiry = ? WHERE hash = ?"s + expiry_constraint +
                            " AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)",
                    to_epoch_ms(new_exp[0]),
                    msg_hashes[0],
                    pubkey.raw_bytes(),
                    pubkey.type()) > 0)
            result.emplace_back(msg_hashes[0], new_exp[0]);

    } else if (new_exp.size() == 1) {
        SQLite::Statement st{
                conn.sql,
                multi_in_query(
                        "UPDATE messages SET expiry = ?"
                        " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"s +
                                expiry_constraint + " AND hash IN (",  // ?,?,?,...,?
                        msg_hashes.size(),
                        ") RETURNING hash"sv)};
        for (auto& hash : get_all<std::string>(
                     st,
                     to_epoch_ms(new_exp[0]),
                     pubkey.raw_bytes(),
                     pubkey.type(),
                     bind_each{msg_hashes}))
            result.emplace_back(hash, new_exp[0]);
    } else {
        SQLite::Transaction transaction{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};

        int64_t owner;
        if (auto maybe = exec_and_maybe_get<int64_t>(
                    conn.prepared_st("SELECT id FROM owners WHERE pubkey = ? AND type = ?"),
                    pubkey.raw_bytes(),
                    pubkey.type()))
            owner = *maybe;
        else
            return result;

        auto st = conn.prepared_st(
                "UPDATE messages SET expiry = ? WHERE hash = ?"s + expiry_constraint +
                " AND owner = ?");
        for (size_t i = 0; i < msg_hashes.size(); i++) {
            if (i > 0)
                st->tryReset();
            if (exec_query(st, to_epoch_ms(new_exp[i]), msg_hashes[i], owner) > 0)
                result.emplace_back(msg_hashes[i], new_exp[i]);
        }

        transaction.commit();
    }
    return result;
}

std::map<std::string, int64_t> Database::get_expiries(
        const user_pubkey& pubkey, const std::vector<std::string>& msg_hashes) {
    auto conn = db_->conn();

    if (msg_hashes.size() == 1) {
        // Pre-prepared version for the common single hash case
        auto st = conn.prepared_st(
                "SELECT hash, expiry FROM messages WHERE hash = ?"
                " AND owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)");
        return get_map<std::string, int64_t>(st, msg_hashes[0], pubkey.raw_bytes(), pubkey.type());
    }

    SQLite::Statement st{
            conn.sql,
            multi_in_query(
                    "SELECT hash, expiry FROM messages"
                    " WHERE owner = (SELECT id FROM owners WHERE pubkey = ? AND type = ?)"
                    " AND hash IN ("sv,  // ?,?,?,...,?
                    msg_hashes.size(),
                    ")"sv)};
    return get_map<std::string, int64_t>(
            st, pubkey.raw_bytes(), pubkey.type(), bind_each{msg_hashes});
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

void Database::foreach_swarm_message(
        std::function<void(const std::vector<message>&)> callback,
        uint64_t lower_bound,
        uint64_t upper_bound,
        bool zero_inclusive) {

    if (lower_bound > upper_bound) {
        foreach_swarm_message(callback, lower_bound, std::numeric_limits<uint64_t>::max());
        foreach_swarm_message(callback, 0, upper_bound, /*zero_inclusive=*/true);
        return;
    }

    auto conn = db_->conn();

    constexpr size_t batch_size = 100;

    std::optional<SQLite::Statement> statement;

    // weird case of their exists exactly one swarm, which should be impossible
    if (lower_bound == upper_bound) {
        statement = SQLite::Statement{
                conn.sql,
                "SELECT type, pubkey, hash, namespace, timestamp, expiry, data"
                " FROM owned_messages ORDER BY mid"};
    } else {
        // there's probably a better way to do this, but it should be fine
        std::string query = R"(
SELECT type, pubkey, hash, namespace, timestamp, expiry, data
FROM owned_messages
JOIN owners ON oid = id
WHERE
        )";
        query += R"(
    (owners.swarm_space_hi >{0} ?1 OR (owners.swarm_space_hi == ?1 AND owners.swarm_space_lo >{0} ?2))
    AND
    (owners.swarm_space_hi <= ?3 OR (owners.swarm_space_hi == ?3 AND owners.swarm_space_lo <= ?4))
ORDER BY mid;
        )"_format(zero_inclusive ? "=" : "");

        statement = SQLite::Statement{conn.sql, query};

        int pos = 1;
        statement->bind(pos++, (int64_t)(lower_bound >> 32));
        statement->bind(pos++, (int64_t)(lower_bound & 0xffffffff));
        statement->bind(pos++, (int64_t)(upper_bound >> 32));
        statement->bind(pos++, (int64_t)(upper_bound & 0xffffffff));
    }

    auto& st = *statement;
    std::vector<message> messages;
    while (st.executeStep()) {
        auto [type, pubkey, hash, ns, ts, exp, data] =
                get<uint8_t, std::string, std::string, namespace_id, int64_t, int64_t, std::string>(
                        st);
        messages.emplace_back(
                load_pubkey(type, pubkey),
                std::move(hash),
                ns,
                from_epoch_ms(ts),
                from_epoch_ms(exp),
                std::move(data));
        if (messages.size() >= batch_size) {
            callback(messages);
            messages.clear();
        }
    }
    if (messages.size())
        callback(messages);
}

void Database::remove_node_retry_request(int64_t req_id) {
    auto conn = db_->conn();
    conn.prepared_exec("DELETE FROM retry_node_reqs WHERE id = ?", req_id);
}

void Database::remove_expired_retry_requests(std::chrono::system_clock::time_point now) {
    auto conn = db_->conn();

    // FIXME: retry requests don't have an expiry, so we need to pick a good expiration time
    //        for these retries.  For now, using 4 hours ago.  Tests will pass 4 hours from
    //        now.
    conn.prepared_exec("DELETE FROM retry_requests WHERE created < ?", to_epoch_double(now - 4h));
}

void Database::update_current_swarm(uint64_t swarm_id) {
    auto as_hex = oxenc::bt_serialize<uint64_t>(swarm_id);
    auto conn = db_->conn();
    conn.prepared_exec(
            "INSERT OR REPLACE INTO state_kv (key, value) VALUES ('swarm_id', ?)", as_hex);
}

std::optional<uint64_t> Database::get_current_swarm() {
    auto conn = db_->conn();
    try {
        auto as_hex =
                conn.prepared_get<std::string>("SELECT value FROM state_kv WHERE key = 'swarm_id'");
        return oxenc::bt_deserialize<uint64_t>(as_hex);
    } catch (const std::exception& e) {
        return std::nullopt;
    }
    return std::nullopt;
}

}  // namespace oxenss
