#include <limits>
#include <oxenss/storage/database.hpp>

#include <oxenss/logging/oxen_logger.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <future>

#include <catch2/catch.hpp>
#include "oxenss/common/format.h"
#include "oxenss/utils/time.hpp"

using namespace oxenss;

using namespace std::literals;

struct StorageDeleter {
    bool delete_it = true;
    StorageDeleter() { std::filesystem::remove("storage.db"); }
    ~StorageDeleter() {
        if (delete_it)
            std::filesystem::remove("storage.db");
    }
};

TEST_CASE("storage - database file creation", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};
    CHECK(std::filesystem::exists("storage.db"));
}

TEST_CASE("storage - data persistence", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto hash = "myhash";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto ns = namespace_id::Default;
    const auto now = std::chrono::system_clock::now();
    {
        Database storage{"."};
        CHECK(storage.store({pubkey, hash, ns, now, now + ttl, bytes}) == StoreResult::New);

        CHECK(storage.get_owner_count() == 1);
        CHECK(storage.get_message_count() == 1);

        // the database is closed when storage goes out of scope
    }
    {
        // re-open the database
        Database storage{"."};

        CHECK(storage.get_owner_count() == 1);
        CHECK(storage.get_message_count() == 1);

        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, "");

        REQUIRE(items.size() == 1);
        CHECK_FALSE(items[0].pubkey);  // pubkey is left unset when we retrieve for pubkey
        CHECK(items[0].hash == hash);
        CHECK(items[0].msg_namespace == namespace_id::Default);
        CHECK(items[0].expiry - items[0].timestamp == ttl);
        CHECK(items[0].data == bytes);
    }
}

TEST_CASE("storage - data persistence, namespace", "[storage][namespace]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto hash = "myhash";
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const namespace_id ns{42};
    const auto now = std::chrono::system_clock::now();
    {
        Database storage{"."};
        CHECK(storage.store({pubkey, hash, ns, now, now + ttl, bytes}) == StoreResult::New);

        CHECK(storage.get_owner_count() == 1);
        CHECK(storage.get_message_count() == 1);

        // the database is closed when storage goes out of scope
    }
    {
        // re-open the database
        Database storage{"."};

        CHECK(storage.get_owner_count() == 1);
        CHECK(storage.get_message_count() == 1);

        auto [items, more] = storage.retrieve(pubkey, ns, "");

        REQUIRE(items.size() == 1);
        CHECK_FALSE(items[0].pubkey);  // pubkey is left unset when we retrieve for pubkey
        CHECK(items[0].hash == hash);
        CHECK(items[0].msg_namespace == namespace_id{42});
        CHECK(items[0].expiry - items[0].timestamp == ttl);
        CHECK(items[0].data == bytes);
    }
}

TEST_CASE("storage - re-storing existing hash", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto hash = "myhash";
    const auto bytes = "bytesasstring";
    const auto ttl1 = 200s;
    const auto timestamp = std::chrono::system_clock::now();

    Database storage{"."};

    auto ins = storage.store(
            {pubkey, hash, namespace_id::Default, timestamp, timestamp + ttl1, bytes});
    CHECK(ins == StoreResult::New);

    std::chrono::seconds ttl2 = ttl1 - 100s;
    SECTION("later expiry") {
        ttl2 = ttl1 + 100s;
    }
    SECTION("earlier expiry") {
        ttl2 = ttl1 - 100s;
    }
    ins = storage.store({pubkey, hash, namespace_id::Default, timestamp, timestamp + ttl2, bytes});
    if (ttl2 > ttl1)
        CHECK(ins == StoreResult::Extended);
    else
        CHECK(ins == StoreResult::Exists);

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == 1);
}

TEST_CASE("storage - only return entries for specified pubkey", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};

    user_pubkey pubkey1, pubkey2;
    REQUIRE(pubkey1.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    REQUIRE(pubkey2.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee"));

    auto now = std::chrono::system_clock::now();
    CHECK(storage.store(
                  {pubkey1, "hash0", namespace_id::Default, now, now + 100s, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store(
                  {pubkey2, "hash1", namespace_id::Default, now, now + 100s, "bytesasstring1"}) ==
          StoreResult::New);

    CHECK(storage.get_owner_count() == 2);
    CHECK(storage.get_message_count() == 2);

    const auto lastHash = "";
    {
        auto [items, more] = storage.retrieve(pubkey1, namespace_id::Default, lastHash);
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash0");
    }

    {
        auto [items, more] = storage.retrieve(pubkey2, namespace_id::Default, lastHash);
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash1");
    }
}

TEST_CASE("storage - return entries older than lasthash", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    auto now = std::chrono::system_clock::now();
    const size_t num_entries = 100;
    for (size_t i = 0; i < num_entries; i++) {
        const auto hash = "hash" + std::to_string(i);
        storage.store({pubkey, hash, namespace_id::Default, now, now + 100s, "bytesasstring"});
    }

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == 100);

    {
        const auto lastHash = "hash0";
        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, lastHash);
        REQUIRE(items.size() == num_entries - 1);
        CHECK(items[0].hash == "hash1");
    }

    {
        const auto lastHash = std::string("hash") + std::to_string(num_entries / 2 - 1);
        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, lastHash);
        REQUIRE(items.size() == num_entries / 2);
        CHECK(items[0].hash == "hash" + std::to_string(num_entries / 2));
    }
}

TEST_CASE("storage - remove expired entries", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey1, pubkey2, pubkey3;
    REQUIRE(pubkey1.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    REQUIRE(pubkey2.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee"));
    REQUIRE(pubkey3.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcded"));

    Database storage{"."};

    auto now = std::chrono::system_clock::now();
    CHECK(storage.store(
                  {pubkey1, "hash0", namespace_id::Default, now, now + 1s, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey1, "hash1", namespace_id::Default, now, now, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store(
                  {pubkey2, "hash2", namespace_id::Default, now, now + 1s, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey3, "hash3", namespace_id::Default, now, now, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey3, "hash4", namespace_id::Default, now, now, "bytesasstring0"}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey3, "hash5", namespace_id::Default, now, now, "bytesasstring0"}) ==
          StoreResult::New);

    CHECK(storage.get_owner_count() == 3);
    CHECK(storage.get_message_count() == 6);

    {
        const auto lastHash = "";
        auto [items, more] = storage.retrieve(pubkey1, namespace_id::Default, lastHash);
        REQUIRE(items.size() == 2);
    }
    std::this_thread::sleep_for(5ms);
    storage.clean_expired();
    {
        const auto lastHash = "";
        auto [items, more] = storage.retrieve(pubkey1, namespace_id::Default, lastHash);
        REQUIRE(items.size() == 1);
        CHECK(items[0].hash == "hash0");
    }

    CHECK(storage.get_owner_count() == 2);
    CHECK(storage.get_message_count() == 2);
}

TEST_CASE("storage - bulk data storage", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto timestamp = std::chrono::system_clock::now();

    const size_t num_items = 100;

    Database storage{"."};

    // bulk store
    {
        std::vector<message> items;
        for (size_t i = 0; i < num_items; ++i) {
            items.emplace_back(
                    pubkey,
                    std::to_string(i),
                    namespace_id::Default,
                    timestamp,
                    timestamp + ttl,
                    bytes);
        }

        CHECK_NOTHROW(storage.bulk_store(items));
    }

    // retrieve
    {
        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, "");
        CHECK(items.size() == num_items);
    }

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == num_items);
}

TEST_CASE("storage - bulk storage with overlap", "[storage]") {
    StorageDeleter fixture;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    const auto bytes = "bytesasstring";
    const auto ttl = 123456ms;
    const auto timestamp = std::chrono::system_clock::now();

    const size_t num_items = 100;

    Database storage{"."};

    // insert existing; the bulk store shouldn't fail when these conflicts already exist
    CHECK(storage.store({pubkey, "0", namespace_id::Default, timestamp, timestamp + ttl, bytes}) ==
          StoreResult::New);
    CHECK(storage.store({pubkey, "5", namespace_id::Default, timestamp, timestamp + ttl, bytes}) ==
          StoreResult::New);

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == 2);

    // bulk store
    {
        std::vector<message> items;
        for (size_t i = 0; i < num_items; ++i) {
            items.emplace_back(
                    pubkey,
                    std::to_string(i),
                    namespace_id::Default,
                    timestamp,
                    timestamp + ttl,
                    bytes);
        }

        CHECK_NOTHROW(storage.bulk_store(items));
    }

    CHECK(storage.get_owner_count() == 1);
    CHECK(storage.get_message_count() == num_items);

    // retrieve
    {
        auto [items, more] = storage.retrieve(pubkey, namespace_id::Default, "");
        CHECK(items.size() == num_items);
    }
}

TEST_CASE("storage - retrieve limit", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    auto now = std::chrono::system_clock::now();
    const size_t num_entries = 100;
    for (size_t i = 0; i < num_entries; i++) {
        const auto hash = "hash" + std::to_string(i);
        storage.store({pubkey, hash, namespace_id::Default, now, now + 100s, "bytesasstring"});
    }

    user_pubkey pubkey2;
    REQUIRE(pubkey2.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee"));

    for (size_t i = 0; i < 5; i++) {
        const auto hash = "anotherhash" + std::to_string(i);
        storage.store({pubkey2, hash, namespace_id::Default, now, now + 100s, "bytesasstring"});
    }

    CHECK(storage.get_owner_count() == 2);
    CHECK(storage.get_message_count() == num_entries + 5);

    CHECK(storage.retrieve(pubkey, namespace_id::Default, "").first.size() == num_entries);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 10).first.size() == 10);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 88).first.size() == 88);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 99).first.size() == 99);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 100).first.size() == 100);
    CHECK(storage.retrieve(pubkey, namespace_id::Default, "", 101).first.size() == 100);
    CHECK(storage.retrieve(pubkey2, namespace_id::Default, "", 10).first.size() == 5);
}

namespace oxenss {
class TestSuiteHacks {
  public:
    static void db_backdate_retries(Database& db, std::chrono::seconds age) {
        db.test_suite_backdate_retries(age);
    }
};
}  // namespace oxenss

// The connection pool belongs to session-sqlite now, so rather than asserting on its internals this
// checks what we actually depend on: that concurrent readers and writers all get through without
// "database is locked" and without losing writes.
TEST_CASE("storage - concurrent access", "[storage][pool]") {
    StorageDeleter fixture;

    Database storage{"."};

    auto n_threads = GENERATE(2, 5, 10);
    constexpr int per_thread = 20;

    user_pubkey pubkey;
    REQUIRE(pubkey.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    auto now = std::chrono::system_clock::now();
    std::atomic<int> failures = 0;

    std::vector<std::thread> workers;
    for (int t = 0; t < n_threads; t++)
        workers.emplace_back([&, t] {
            try {
                for (int i = 0; i < per_thread; i++) {
                    auto hash = "hash{}_{}"_format(t, i);
                    storage.store(
                            {pubkey,
                             hash,
                             namespace_id::Default,
                             now,
                             now + 1h,
                             "data{}_{}"_format(t, i)});
                    // Interleave reads with the writes so both are in flight at once.
                    storage.retrieve_by_hash(hash);
                    storage.get_message_count();
                }
            } catch (const std::exception& e) {
                if (failures++ == 0)
                    UNSCOPED_INFO("first failure: " << e.what());
            }
        });
    for (auto& w : workers)
        w.join();

    CHECK(failures == 0);
    CHECK(storage.get_message_count() == n_threads * per_thread);

    // Everything each thread wrote is retrievable and intact.
    for (int t = 0; t < n_threads; t++)
        for (int i = 0; i < per_thread; i++) {
            auto msg = storage.retrieve_by_hash("hash{}_{}"_format(t, i));
            REQUIRE(msg);
            CHECK(msg->data == "data{}_{}"_format(t, i));
        }
}

TEST_CASE("storage - current swarm", "[storage]") {
    StorageDeleter fixture;

    Database storage{"."};

    // new db has no current swarm
    CHECK(storage.get_current_swarm() == std::nullopt);

    storage.update_current_swarm(12345);

    CHECK(*(storage.get_current_swarm()) == 12345);
}

TEST_CASE("storage - retry requests", "[storage]") {
    StorageDeleter fixture;
    fixture.delete_it = false;
    oxenss::crypto::legacy_pubkey pubkey, pubkey2;
    pubkey.load_from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    pubkey2.load_from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0");

    Database storage{"."};

    // first row id = 1
    CHECK(storage.add_retry_request(pubkey, "foo", "bar") == 1);

    // unique on retry id and pubkey
    CHECK_THROWS(storage.add_retry_request(pubkey, "foo", "bar", 1));
    // this will silently fail, but also should never be done.
    CHECK_THROWS(storage.add_retry_request(pubkey, "foo", "bar", 2));

    auto req_count = storage.retry_request_count();
    CHECK(req_count == 1);

    storage.add_retry_request(pubkey2, "foo", "bar");
    req_count = storage.retry_request_count();
    CHECK(req_count == 2);

    storage.add_retry_request(pubkey, "bits", "bits");
    req_count = storage.retry_request_count();
    CHECK(req_count == 3);

    std::this_thread::sleep_for(500ms);
    // FIXME: "expiry" is currently 4h, this is incredibly arbitrary and should be considered
    // further.
    auto the_future = std::chrono::system_clock::now() + 4h;

    std::this_thread::sleep_for(
            500ms);  // the following insert should *not* be considered "expired"
    CHECK_NOTHROW(storage.add_retry_request(pubkey, "fools", "barred") == 4);
    req_count = storage.retry_request_count();
    CHECK(req_count == 4);
    // remove expired, pretending it's 4h (minus the sleep) from now
    CHECK_NOTHROW(storage.remove_expired_retry_requests(the_future));
    req_count = storage.retry_request_count();
    CHECK(req_count == 1);
}

TEST_CASE("storage - ready retry requests", "[storage]") {
    StorageDeleter fixture;
    crypto::legacy_pubkey pk1, pk2, pk3;
    pk1.load_from_hex("1111111111111111111111111111111111111111111111111111111111111111");
    pk2.load_from_hex("2222222222222222222222222222222222222222222222222222222222222222");
    pk3.load_from_hex("3333333333333333333333333333333333333333333333333333333333333333");

    Database storage{"."};

    storage.add_retry_request(pk1, "cmd1", "payload1");
    storage.add_retry_request(pk2, "cmd2", "payload2");
    storage.add_retry_request(pk3, "cmd3", "payload3");
    REQUIRE(storage.retry_request_count() == 3);

    std::vector<std::pair<std::string, std::string>> seen;
    auto collect = [&seen](bool sent) {
        return [&seen, sent](
                       const crypto::legacy_pubkey&,
                       const std::string& cmd,
                       const std::string& payload,
                       int64_t) {
            seen.emplace_back(cmd, payload);
            return sent;
        };
    };
    auto saw = [&seen](std::string_view cmd) {
        for (const auto& [c, p] : seen)
            if (c == cmd)
                return true;
        return false;
    };

    // add_retry_request schedules the first attempt RETRY_INITIAL_DELAY out, so nothing is due yet
    storage.foreach_ready_retry_request(collect(true));
    CHECK(seen.empty());

    // Backdating past RETRY_INITIAL_DELAY makes all three due; report only cmd1 as sent.
    TestSuiteHacks::db_backdate_retries(storage, 30s);
    seen.clear();
    storage.foreach_ready_retry_request([&seen](const crypto::legacy_pubkey&,
                                                const std::string& cmd,
                                                const std::string& payload,
                                                int64_t) {
        seen.emplace_back(cmd, payload);
        return cmd == "cmd1";
    });
    REQUIRE(seen.size() == 3);
    CHECK(saw("cmd1"));
    CHECK(saw("cmd2"));
    CHECK(saw("cmd3"));
    for (const auto& [c, p] : seen)
        CHECK(p == "payload" + c.substr(3));

    // Every row's next_retry was moved forward, so a second pass finds nothing.
    seen.clear();
    storage.foreach_ready_retry_request(collect(true));
    CHECK(seen.empty());

    // cmd1 was reported sent, so it waits RETRY_INTERVAL (60s); the other two were not, so they
    // wait only RETRY_NO_CONTACT_INTERVAL (15s).  Backdating 30s brings back just those two.
    TestSuiteHacks::db_backdate_retries(storage, 30s);
    seen.clear();
    storage.foreach_ready_retry_request(collect(true));
    REQUIRE(seen.size() == 2);
    CHECK_FALSE(saw("cmd1"));
    CHECK(saw("cmd2"));
    CHECK(saw("cmd3"));
}

TEST_CASE("storage - removing retry requests", "[storage]") {
    StorageDeleter fixture;
    Database storage{"."};

    const auto pk1 = crypto::legacy_pubkey::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111");
    const auto pk2 = crypto::legacy_pubkey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222");

    // One request, retried to two nodes
    auto req = storage.add_retry_request(pk1, "cmd", "payload");
    storage.add_retry_request(pk2, "cmd", "payload", req);
    REQUIRE(storage.retry_request_count() == 2);

    TestSuiteHacks::db_backdate_retries(storage, 1h);
    std::vector<int64_t> node_reqs;
    storage.foreach_ready_retry_request(
            [&node_reqs](const auto&, const auto&, const auto&, int64_t id) {
                node_reqs.push_back(id);
                return true;
            });
    REQUIRE(node_reqs.size() == 2);

    storage.remove_node_retry_request(node_reqs[0]);
    CHECK(storage.retry_request_count() == 1);
    storage.remove_node_retry_request(node_reqs[1]);
    CHECK(storage.retry_request_count() == 0);

    // The request itself goes with its last node entry, so it can no longer be added to:
    CHECK_THROWS(storage.add_retry_request(pk1, "cmd", "payload", req));
}

TEST_CASE("storage - pending deliveries", "[storage][swarm]") {
    StorageDeleter fixture;
    Database storage{"."};

    user_pubkey pk;
    REQUIRE(pk.load("0500112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210"));
    const auto now = std::chrono::system_clock::now();
    const std::string data(100, 'x');
    for (int i = 1; i <= 3; i++)
        REQUIRE(storage.store({pk, "h{}"_format(i), namespace_id::Default, now, now + 1h, data}) ==
                StoreResult::New);

    const auto peer1 = crypto::legacy_pubkey::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111");
    const auto peer2 = crypto::legacy_pubkey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222");
    using pks = std::vector<crypto::legacy_pubkey>;

    CHECK(storage.delivery_peers().empty());

    storage.queue_delivery(peer1, "h1");
    storage.queue_delivery(peer1, "h3");
    storage.queue_delivery(peer1, "h3");            // already queued: no-op
    storage.queue_delivery(peer1, "no such hash");  // nothing to deliver: no-op
    CHECK(storage.delivery_peers() == pks{peer1});

    auto [msgs, ids] = storage.next_delivery_batch(peer1, 1 << 20);
    REQUIRE(msgs.size() == 2);
    CHECK(msgs[0].hash == "h1");
    CHECK(msgs[1].hash == "h3");
    CHECK(ids == std::vector<int64_t>{1, 3});

    // The byte budget splits batches as for dumps
    CHECK(storage.next_delivery_batch(peer1, 1).first.size() == 1);

    storage.remove_deliveries(peer1, {1});
    std::tie(msgs, ids) = storage.next_delivery_batch(peer1, 1 << 20);
    REQUIRE(msgs.size() == 1);
    CHECK(msgs[0].hash == "h3");

    // Deleting the message takes its pending delivery with it
    CHECK(storage.delete_by_hash(pk, {"h3"}) == std::vector<std::string>{"h3"});
    CHECK(storage.next_delivery_batch(peer1, 1 << 20).first.empty());
    CHECK(storage.delivery_peers().empty());

    // ... as does expiry
    REQUIRE(storage.store({pk, "h4", namespace_id::Default, now, now - 1s, data}) ==
            StoreResult::New);
    storage.queue_delivery(peer1, "h4");
    storage.queue_delivery(peer2, "h2");
    CHECK(storage.delivery_peers().size() == 2);
    storage.clean_expired();
    CHECK(storage.delivery_peers() == pks{peer2});

    storage.remove_deliveries(peer2);
    CHECK(storage.delivery_peers().empty());
}

TEST_CASE("storage - swarm space range queries", "[storage][swarm]") {
    StorageDeleter fixture;
    Database storage{"."};

    // Two owners; the trigger on owners fills in their swarm space from the pubkey.  Swarm space
    // is the XOR of the pubkey's four 8-byte words, so the keys must not be a repeated pattern
    // (that XORs to 0).
    user_pubkey pk1, pk2;
    REQUIRE(pk1.load("0500112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210"));
    REQUIRE(pk2.load("05a1b2c3d4e5f60718293a4b5c6d7e8f900f1e2d3c4b5a69781122334455667788"));
    const auto s1 = pubkey_to_swarm_space(pk1), s2 = pubkey_to_swarm_space(pk2);
    REQUIRE(s1 != 0);
    REQUIRE(s2 != 0);
    REQUIRE(s1 < s2);

    const auto now = std::chrono::system_clock::now();
    REQUIRE(storage.store({pk1, "hash1", namespace_id::Default, now, now + 1h, "one"}) ==
            StoreResult::New);
    REQUIRE(storage.store({pk2, "hash2", namespace_id::Default, now, now + 1h, "two"}) ==
            StoreResult::New);

    using set = std::set<std::string>;
    auto hashes = [&](uint64_t lower, uint64_t upper) {
        set seen;
        for (const auto& m :
             storage.next_dump_batch(1, storage.max_message_id(), lower, upper, 1 << 20).first)
            seen.insert(m.hash);
        return seen;
    };
    constexpr auto max = std::numeric_limits<uint64_t>::max();

    // lower < upper: the single range query.  (0, max] covers everything but swarm space 0.
    CHECK(hashes(0, max) == set{"hash1", "hash2"});
    CHECK(storage.has_owners_in_range(0, max));

    // The lower bound is exclusive and the upper inclusive.
    CHECK(hashes(s1 - 1, s1) == set{"hash1"});
    CHECK(hashes(s1, s2 - 1).empty());
    CHECK_FALSE(storage.has_owners_in_range(s1, s2 - 1));
    CHECK(hashes(s1, s2) == set{"hash2"});
    CHECK(storage.has_owners_in_range(s1, s2));

    // lower > upper wraps around: (s2, max] plus [0, s1], which takes in hash1 but not hash2.
    CHECK(hashes(s2, s1) == set{"hash1"});
    CHECK(storage.has_owners_in_range(s2, s1));

    // Equal bounds mean the whole space (the single-swarm case).
    CHECK(hashes(s1, s1) == set{"hash1", "hash2"});
    CHECK(storage.has_owners_in_range(7, 7));
}

TEST_CASE("storage - dump batches and cursors", "[storage][swarm]") {
    StorageDeleter fixture;
    Database storage{"."};

    user_pubkey pk;
    REQUIRE(pk.load("0500112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210"));
    const auto now = std::chrono::system_clock::now();
    const std::string data(100, 'x');
    for (int i = 1; i <= 5; i++)
        REQUIRE(storage.store({pk, "h{}"_format(i), namespace_id::Default, now, now + 1h, data}) ==
                StoreResult::New);
    CHECK(storage.max_message_id() == 5);

    // Each message counts for a bit over 180 bytes, so a 300 byte budget stops after the message
    // that takes the batch past it: two per batch.
    auto [b1, last1] = storage.next_dump_batch(1, 5, 0, 0, 300);
    REQUIRE(b1.size() == 2);
    CHECK(b1[0].hash == "h1");
    CHECK(b1[1].hash == "h2");
    CHECK(last1 == 2);

    auto [b2, last2] = storage.next_dump_batch(last1 + 1, 5, 0, 0, 300);
    REQUIRE(b2.size() == 2);
    CHECK(b2[0].hash == "h3");
    CHECK(last2 == 4);

    auto [b3, last3] = storage.next_dump_batch(last2 + 1, 5, 0, 0, 300);
    REQUIRE(b3.size() == 1);
    CHECK(b3[0].hash == "h5");
    CHECK(last3 == 5);

    auto [b4, last4] = storage.next_dump_batch(last3 + 1, 5, 0, 0, 300);
    CHECK(b4.empty());
    CHECK(last4 == 0);

    // end_id is a snapshot: a message stored after it is not part of the dump.
    REQUIRE(storage.store({pk, "h6", namespace_id::Default, now, now + 1h, data}) ==
            StoreResult::New);
    CHECK(storage.max_message_id() == 6);
    CHECK(storage.next_dump_batch(6, 5, 0, 0, 300).first.empty());
    CHECK(storage.next_dump_batch(6, 6, 0, 0, 300).first.size() == 1);

    // Cursor rows
    const auto peer = crypto::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(storage.pending_dumps().empty());

    storage.queue_dump(peer, 123, 5);
    auto dumps = storage.pending_dumps();
    REQUIRE(dumps.size() == 1);
    CHECK(dumps[0].pubkey == peer);
    CHECK(dumps[0].swarm == 123);
    CHECK(dumps[0].next_id == 1);
    CHECK(dumps[0].end_id == 5);
    CHECK(dumps[0].next_attempt == std::chrono::system_clock::time_point{});

    storage.update_dump(peer, 123, 3, now + 1h);
    dumps = storage.pending_dumps();
    REQUIRE(dumps.size() == 1);
    CHECK(dumps[0].next_id == 3);
    CHECK(dumps[0].end_id == 5);
    auto delta = dumps[0].next_attempt - (now + 1h);
    CHECK(delta > -1s);
    CHECK(delta < 1s);

    // Queueing again for the same node and swarm restarts from the beginning, keeps the later end,
    // and makes it due immediately.
    storage.queue_dump(peer, 123, 4);
    dumps = storage.pending_dumps();
    REQUIRE(dumps.size() == 1);
    CHECK(dumps[0].next_id == 1);
    CHECK(dumps[0].end_id == 5);
    CHECK(dumps[0].next_attempt == std::chrono::system_clock::time_point{});

    // A different swarm for the same node is a separate dump.
    storage.queue_dump(peer, 124, 9);
    CHECK(storage.pending_dumps().size() == 2);

    storage.remove_dump(peer, 123);
    dumps = storage.pending_dumps();
    REQUIRE(dumps.size() == 1);
    CHECK(dumps[0].swarm == 124);
    CHECK(dumps[0].end_id == 9);
}
