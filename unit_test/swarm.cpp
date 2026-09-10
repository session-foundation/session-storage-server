#include <catch2/catch.hpp>
#include <iostream>

#include <oxenmq/oxenmq.h>
#include <oxenss/crypto/keys.h>
#include <oxenss/rpc/request_handler.h>
#include <oxenss/snode/swarm.h>
#include <oxenss/utils/time.hpp>

#include <oxenc/base64.h>

using namespace std::literals;

using ip_ports = std::tuple<const char*, uint16_t, uint16_t>;

using oxenss::snode::INVALID_SWARM_ID;
using oxenss::snode::Network;
using oxenss::snode::Swarm;

TEST_CASE("swarm - pubkey to swarm space", "[swarm]") {
    oxenss::user_pubkey pk;
    REQUIRE(pk.load("053506f4a71324b7dd114eddbf4e311f39dde243e1f2cb97c40db1961f70ebaae8"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 17589930838143112648ULL);
    REQUIRE(pk.load("05cf27da303a50ac8c4b2d43d27259505c9bcd73fc21cf2a57902c3d050730b604"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 10370619079776428163ULL);
    REQUIRE(pk.load("03d3511706b8b34f6e8411bf07bd22ba6b2435ca56846fbccf6eb1e166a6cd15cc"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 2144983569669512198ULL);
    REQUIRE(pk.load("ff0f06693428fca9102a451e3f28d9cc743d8ea60a89ab6aa69eb119470c11cbd3"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 9690840703409570833ULL);
    REQUIRE(pk.load("05ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 4532060000165252872ULL);
    REQUIRE(pk.load("05eeeeeeeeeeeeeeee777777777777777711111111111111118888888888888888"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 0);
    REQUIRE(pk.load("050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 0);
    REQUIRE(pk.load("05fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 1);
    REQUIRE(pk.load("05ffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffff"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 1ULL << 63);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000ffffffffffffffff"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == INVALID_SWARM_ID);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000123456789abcdef"));
    CHECK(oxenss::pubkey_to_swarm_space(pk) == 0x0123456789abcdefULL);
}

struct StorageDeleter {
    StorageDeleter() { std::filesystem::remove("storage.db"); }
    ~StorageDeleter() { std::filesystem::remove("storage.db"); }
};

TEST_CASE("service nodes - pubkey to swarm id") {
    const auto fake_pk = oxenss::crypto::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    oxenmq::OxenMQ omq;
    Network network{omq};
    oxenss::Database db{"."};  // unused here, but required by Swarm
    Swarm swarm{network, fake_pk, db};

    using oxenss::snode::swarms_t;
    swarms_t swarms;
    for (oxenss::snode::swarm_id_t s : {100, 200, 300, 399, 498, 596, 694})
        swarms[s];
    swarm.update_swarms(0, swarms_t{swarms}, {});

    oxenss::user_pubkey pk;

    // Exact matches:
    // 0x64 = 100, 0xc8 = 200, 0x1f2 = 498
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000064"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000000c8"));
    CHECK(network.get_swarm_id_for(pk).value() == 200);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000001f2"));
    CHECK(network.get_swarm_id_for(pk).value() == 498);

    // Nearest
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000000"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);

    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000001"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);

    // Nearest, with wraparound
    // 0x8000... is closest to the top value
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000008000000000000000"));
    CHECK(network.get_swarm_id_for(pk).value() == 694);

    // 0xa000... is closest (via wraparound) to the smallest
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000a000000000000000"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);

    // A pubkey whose swarm space == INVALID_SWARM_ID is not a valid swarm id, but *is* a valid
    // swarm space value
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000ffffffffffffffff"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);

    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000fffffffffffffffe"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);

    // Midpoint tests; we prefer the lower value when exactly in the middle between two swarms.
    // 0x96 = 150
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000095"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000096"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000097"));
    CHECK(network.get_swarm_id_for(pk).value() == 200);

    // 0xfa = 250
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000000f9"));
    CHECK(network.get_swarm_id_for(pk).value() == 200);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000000fa"));
    CHECK(network.get_swarm_id_for(pk).value() == 200);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000000fb"));
    CHECK(network.get_swarm_id_for(pk).value() == 300);

    // 0x15d = 349
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000000000000000015d"));
    CHECK(network.get_swarm_id_for(pk).value() == 300);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000000000000000015e"));
    CHECK(network.get_swarm_id_for(pk).value() == 399);

    // 0x1c0 = 448
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000001c0"));
    CHECK(network.get_swarm_id_for(pk).value() == 399);
    REQUIRE(pk.load("0500000000000000000000000000000000000000000000000000000000000001c1"));
    CHECK(network.get_swarm_id_for(pk).value() == 498);

    // 0x223 = 547
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000222"));
    CHECK(network.get_swarm_id_for(pk).value() == 498);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000223"));
    CHECK(network.get_swarm_id_for(pk).value() == 498);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000224"));
    CHECK(network.get_swarm_id_for(pk).value() == 596);

    // 0x285 = 645
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000285"));
    CHECK(network.get_swarm_id_for(pk).value() == 596);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000286"));
    CHECK(network.get_swarm_id_for(pk).value() == 694);

    // 0x800....d is the midpoint between 694 and 100 (the long way).  We always round "down" (which
    // in this case, means wrapping to the largest swarm).
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000800000000000018c"));
    CHECK(network.get_swarm_id_for(pk).value() == 694);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000800000000000018d"));
    CHECK(network.get_swarm_id_for(pk).value() == 694);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000800000000000018e"));
    CHECK(network.get_swarm_id_for(pk).value() == 100);

    // With a swarm at -20 the midpoint is now 40 (=0x28).  When our value is the *low* value we
    // prefer the *last* swarm in the case of a tie (while consistent with the general case of
    // preferring the left edge, it means we're inconsistent with the other wraparound case, above.
    // *sigh*).
    oxenss::snode::swarm_id_t wrapped_swarm = (uint64_t)-20;
    swarms[wrapped_swarm];
    swarm.update_swarms(0, swarms_t{swarms}, {});
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000027"));
    CHECK(network.get_swarm_id_for(pk).value() == swarms.rbegin()->first);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000028"));
    CHECK(network.get_swarm_id_for(pk).value() == swarms.rbegin()->first);
    REQUIRE(pk.load("050000000000000000000000000000000000000000000000000000000000000029"));
    CHECK(network.get_swarm_id_for(pk).value() == swarms.begin()->first);

    // The code used to have a broken edge case if we have a swarm at zero and a client at
    // INVALID_SWARM_ID (UINT64_MAX) because of an overflow in how the distance is calculated (the
    // first swarm will be calculated as UINT64_MAX away (i.e. -1), rather than 1 away), and so the
    // id always maps to the highest swarm (even though 0xfff...fe maps to the lowest swarm); the
    // first check here, then, would fail.
    swarms[0];
    swarm.update_swarms(0, swarms_t{swarms}, {});
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000ffffffffffffffff"));
    CHECK(network.get_swarm_id_for(pk).value() == 0);
    REQUIRE(pk.load("05000000000000000000000000000000000000000000000000fffffffffffffffe"));
    CHECK(network.get_swarm_id_for(pk).value() == 0);
}

TEST_CASE(
        "service nodes - swarm id to swarm space, boundaries near 0 and INVALID_SWARM_ID",
        "[swarm]") {
    const auto fake_pk = oxenss::crypto::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    oxenmq::OxenMQ omq;
    Network network{omq};
    oxenss::Database db{"."};
    Swarm swarm{network, fake_pk, db};

    using oxenss::snode::swarm_id_t;
    using oxenss::snode::swarms_t;

    // INVALID_SWARM_ID (UINT64_MAX) cannot be a swarm id; INVALID_SWARM_ID - 1 can.
    const swarm_id_t near_max = INVALID_SWARM_ID - 1;
    swarms_t swarms;
    for (swarm_id_t s : {swarm_id_t{1}, swarm_id_t{100}, swarm_id_t{694}, near_max})
        swarms[s];
    swarm.update_swarms(0, swarms_t{swarms}, {});

    // swarm 1 (prev=near_max, next=100):
    //   left_diff = 3 (odd, rounded up to 4); lo = 1 - 2 = INVALID_SWARM_ID (UINT64_MAX)
    //   right_diff = 99; hi = 50
    //   lo == INVALID_SWARM_ID (UINT64_MAX), which is a valid swarm space position.
    //   Range wraps: (INVALID_SWARM_ID, 50] = [0, 50] since nothing exceeds INVALID_SWARM_ID.
    auto b_1 = network.get_swarm_boundaries(1);
    REQUIRE(b_1.first == INVALID_SWARM_ID);
    REQUIRE(b_1.second == 50);

    // swarm 100 (prev=1, next=694):
    //   left_diff = 99 (odd, rounded up to 100); lo = 50; right_diff = 594; hi = 397
    auto b_100 = network.get_swarm_boundaries(100);
    REQUIRE(b_100.first == 50);
    REQUIRE(b_100.second == 397);

    // swarm 694 (prev=100, next=near_max):
    //   left_diff = 594 (even); lo = 397
    //   right_diff = near_max - 694 (large, even); hi = 0x800000000000015A
    auto b_694 = network.get_swarm_boundaries(694);
    REQUIRE(b_694.first == 397);
    REQUIRE(b_694.second == 0x800000000000015AULL);

    // swarm near_max (prev=694, next=1):
    //   left_diff = near_max - 694 (large, even); lo = 0x800000000000015A
    //   right_diff = 3; hi = near_max + 1 = INVALID_SWARM_ID (UINT64_MAX)
    //   hi lands exactly on INVALID_SWARM_ID (UINT64_MAX): a valid swarm space position even
    //   though it cannot be a swarm id.  near_max owns INVALID_SWARM_ID as a swarm space position.
    auto b_near_max = network.get_swarm_boundaries(near_max);
    REQUIRE(b_near_max.first == 0x800000000000015AULL);
    REQUIRE(b_near_max.second == INVALID_SWARM_ID);

    // Shared boundaries
    REQUIRE(b_694.second == b_near_max.first);  // 0x800000000000015A
    REQUIRE(b_near_max.second ==
            b_1.first);  // INVALID_SWARM_ID (UINT64_MAX): near_max's hi == swarm 1's lo
}

TEST_CASE(
        "service nodes - swarm id to swarm space, minimal 0 and INVALID_SWARM_ID - 1", "[swarm]") {
    const auto fake_pk = oxenss::crypto::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    oxenmq::OxenMQ omq;
    Network network{omq};
    oxenss::Database db{"."};
    Swarm swarm{network, fake_pk, db};

    using oxenss::snode::swarm_id_t;
    using oxenss::snode::swarms_t;

    swarms_t swarms;
    for (swarm_id_t s : {swarm_id_t{0}, INVALID_SWARM_ID - 1})
        swarms[s];
    swarm.update_swarms(0, swarms_t{swarms}, {});

    // Two swarms split the space exactly in half.
    // swarm 0: left_diff=2 (even); lo = 0 - 1 = INVALID_SWARM_ID (UINT64_MAX); hi =
    // 0x7FFFFFFFFFFFFFFF swarm INVALID_SWARM_ID-1: lo = 0x7FFFFFFFFFFFFFFF; hi = INVALID_SWARM_ID -
    // 1 + 1 = INVALID_SWARM_ID INVALID_SWARM_ID is a valid swarm space position, owned here by
    // swarm INVALID_SWARM_ID - 1.
    auto b_0 = network.get_swarm_boundaries(0);
    REQUIRE(b_0.first == INVALID_SWARM_ID);
    REQUIRE(b_0.second == 0x7FFFFFFFFFFFFFFFULL);

    auto b_max = network.get_swarm_boundaries(INVALID_SWARM_ID - 1);
    REQUIRE(b_max.first == 0x7FFFFFFFFFFFFFFFULL);
    REQUIRE(b_max.second == INVALID_SWARM_ID);

    REQUIRE(b_0.second == b_max.first);  // shared midpoint
    REQUIRE(b_max.second == b_0.first);  // shared boundary at INVALID_SWARM_ID (UINT64_MAX)
}

// A round-trip test against "service nodes - pubkey to swarm id" is not needed here.
// Both get_swarm_boundaries and _find_swarm_for_swarm_space use consistent uint64_t modular
// arithmetic, and the wrapping range case (lo > hi, crossing INVALID_SWARM_ID (UINT64_MAX)) is
// already exercised by swarm 100's boundaries below.  INVALID_SWARM_ID is a valid swarm space
// position but is assumed (and enforced elsewhere) to never be a swarm id, so no additional edge
// cases exist.
TEST_CASE("service nodes - swarm id to swarm space (pubkey range)") {
    const auto fake_pk = oxenss::crypto::legacy_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    oxenmq::OxenMQ omq;
    Network network{omq};
    oxenss::Database db{"."};  // unused here, but required by Swarm
    Swarm swarm{network, fake_pk, db};

    using oxenss::snode::swarms_t;
    swarms_t swarms;
    for (oxenss::snode::swarm_id_t s : {100, 200, 300, 399, 498, 596, 694})
        swarms[s];
    swarm.update_swarms(0, swarms_t{swarms}, {});

    oxenss::user_pubkey pk;

    auto boundaries = network.get_swarm_boundaries(200);
    REQUIRE(boundaries.first == 150);
    REQUIRE(boundaries.second == 250);  // swarm 300 loses this tie; 250 is inclusive for swarm 200

    boundaries = network.get_swarm_boundaries(300);
    REQUIRE(boundaries.first == 250);
    REQUIRE(boundaries.second == 349);

    boundaries = network.get_swarm_boundaries(399);
    REQUIRE(boundaries.first == 349);
    REQUIRE(boundaries.second == 448);

    boundaries = network.get_swarm_boundaries(498);
    REQUIRE(boundaries.first == 448);   // left_diff=99 (odd, rounded up to 100), so lo = 498 - 50
    REQUIRE(boundaries.second == 547);  // right_diff=98, so hi = 498 + 49

    boundaries = network.get_swarm_boundaries(596);
    REQUIRE(boundaries.first == 547);
    REQUIRE(boundaries.second == 645);

    auto boundaries_100 = network.get_swarm_boundaries(100);
    REQUIRE(boundaries_100.first == (0x18d + 0x8000000000000000));
    REQUIRE(boundaries_100.second == 150);

    // 694 is the last element; its successor wraps around to 100.
    // right_diff = 100 - 694 (uint64 wraparound) = 0xFFFFFFFFFFFFFDAE
    // hi = 694 + 0x7FFFFFFFFFFFFED7 = 0x800000000000018D
    // 694's upper bound and 100's lower bound must be the same value (shared boundary).
    auto boundaries_694 = network.get_swarm_boundaries(694);
    REQUIRE(boundaries_694.first == 645);
    REQUIRE(boundaries_694.second == (0x18d + 0x8000000000000000));
    REQUIRE(boundaries_694.second == boundaries_100.first);
}
