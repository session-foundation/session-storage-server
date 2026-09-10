#!/usr/bin/env python3
"""
Creates a historical test database for exercising schema migrations.
Run this first, then run migrate_test against the output path.

Usage: python3 create_old_db.py [schema] [output_dir]
  schema     : which historical schema to create (default: pre-swarm-space)
  output_dir : where to write storage.db (default: /tmp/test_migration_<schema>)

Available schemas:

  pre-swarm-space  (as of v2.11.3)
    owners(id INTEGER PK, type INTEGER, pubkey BLOB, UNIQUE(pubkey, type))
    messages(id INTEGER PK, hash TEXT UNIQUE, owner→owners, namespace INTEGER,
             timestamp INTEGER, expiry INTEGER, data BLOB)
    revoked_subaccounts(owner→owners, token BLOB, timestamp INTEGER)

  post-swarm-space  (current)
    owners: added swarm_space_hi INTEGER, swarm_space_lo INTEGER
            (upper/lower 32-bit halves of pubkey_to_swarm_space(); populated on migration
             via custom SQLite functions func_swarm_space_hi/lo registered by C++ at open time)
            new trigger: swarm_space_trigger auto-populates these on INSERT
            new indices: owners_swarm_hi, owners_swarm_lo
    messages: public outbox namespaces (namespace < 0 AND namespace % 20 = -1, i.e. -1,-21,-41,…)
              cleared entirely, then UNIQUE INDEX message_outbox_singleton added on
              (owner, namespace) — enforces singleton behaviour going forward
    new tables: retry_requests(id, command, payload, created)
                retry_pubkeys(id, pubkey UNIQUE)
                retry_node_requests(id, rr_id→retry_requests, pk_id→retry_pubkeys,
                                    next_retry, UNIQUE(rr_id,pk_id))
    new view+triggers: retry_node_reqs (insert view), retry_node_add, rr_cleanup
    new table: state_kv(key TEXT UNIQUE, value TEXT)  — generic persistent key/value store
"""

import sqlite3, os, sys, time


def create_pre_swarm_space(c):
    c.executescript("""
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

CREATE TABLE revoked_subaccounts (
    owner INTEGER REFERENCES owners(id) ON DELETE CASCADE,
    token BLOB NOT NULL,
    timestamp INTEGER NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5)*86400000 AS INTEGER))
);
""")

    # Pubkeys: 32-byte blobs (type prefix stored separately in the type column).
    # swarm_space = XOR of four big-endian uint64 chunks of the pubkey bytes.
    pk_100    = bytes(31) + bytes([0x64])   # swarm_space=100   (hi=0, lo=100)
    pk_1      = bytes(31) + bytes([0x01])   # swarm_space=1     (hi=0, lo=1)
    pk_0      = bytes(32)                   # swarm_space=0     (hi=0, lo=0)
    pk_maxu64 = bytes(24) + bytes([0xff]*8) # swarm_space=UINT64_MAX

    now_ms    = int(time.time() * 1000)
    future_ms = now_ms + 86400_000

    def ins_owner(pk, t=5):
        c.execute("INSERT INTO owners (type, pubkey) VALUES (?, ?)", (t, pk))
        return c.lastrowid

    def ins_msg(owner_id, ns, h, d=b"data"):
        c.execute("INSERT INTO messages (hash, owner, namespace, timestamp, expiry, data)"
                  " VALUES (?, ?, ?, ?, ?, ?)", (h, owner_id, ns, now_ms, future_ms, d))

    o1 = ins_owner(pk_100)     # swarm_space=100
    o2 = ins_owner(pk_1)       # swarm_space=1
    o3 = ins_owner(pk_0)       # swarm_space=0
    o4 = ins_owner(pk_maxu64)  # swarm_space=UINT64_MAX

    # o1: regular namespaces only — all messages survive migration
    ins_msg(o1, 0,   "o1_ns0")
    ins_msg(o1, 5,   "o1_ns5")

    # o2: one public outbox message (ns=-1) — deleted by migration
    ins_msg(o2, -1,  "o2_ns-1")

    # o3: multiple public outbox messages + non-outbox negative ns
    ins_msg(o3, -1,  "o3_ns-1_a")   # deleted (public outbox)
    ins_msg(o3, -1,  "o3_ns-1_b")   # deleted (public outbox, same ns)
    ins_msg(o3, -21, "o3_ns-21")    # deleted (also public outbox: -21 % 20 = -1)
    ins_msg(o3, -2,  "o3_ns-2")     # survives (-2 % 20 = -2, not public outbox)

    # o4: mix of outbox and non-outbox
    ins_msg(o4, -1,  "o4_ns-1_a")   # deleted
    ins_msg(o4, -1,  "o4_ns-1_b")   # deleted
    ins_msg(o4, 10,  "o4_ns10")     # survives


SCHEMAS = {
    'pre-swarm-space': create_pre_swarm_space,
}

schema  = sys.argv[1] if len(sys.argv) > 1 else 'pre-swarm-space'
db_dir  = sys.argv[2] if len(sys.argv) > 2 else f'/tmp/test_migration_{schema}'
db_path = os.path.join(db_dir, 'storage.db')

if schema not in SCHEMAS:
    print(f"Unknown schema '{schema}'. Available: {', '.join(SCHEMAS)}")
    sys.exit(1)

os.makedirs(db_dir, exist_ok=True)
if os.path.exists(db_path):
    os.remove(db_path)

conn = sqlite3.connect(db_path)
c = conn.cursor()

SCHEMAS[schema](c)

conn.commit()

print(f"=== PRE-MIGRATION STATE ({schema}) ===")
print(f"owners columns : {[r[1] for r in c.execute('PRAGMA table_info(owners)')]}")
print(f"owners         : {c.execute('SELECT id, type FROM owners').fetchall()}")
print(f"messages       : {[(r[0], r[1]) for r in c.execute('SELECT namespace, hash FROM messages ORDER BY hash')]}")
print(f"\nDatabase written to: {db_path}")
print(f"Now run:  ./migrate_test {db_dir}")

conn.close()
