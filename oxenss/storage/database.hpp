#pragma once

#include <oxenss/common/subaccount_token.h>
#include <oxenss/common/message.h>
#include <oxenss/common/pubkey.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "oxenss/crypto/keys.h"

namespace session::sqlite {
class Connection;
class Database;
}  // namespace session::sqlite

namespace oxenss {

using namespace std::literals;

/// Possible return values of a `store()`:
enum class StoreResult {
    New,       // Message did not exist and was inserted.
    Extended,  // Message existed, but the expiry was extended to match the stored timestamp.
    Exists,    // Message exists and already has an expiry >= the stored one.
    Obsolete,  // Newer message exists and message type is singleton (e.g. public outbox)
    Full,      // Can't insert right now because the database is full.
};

inline std::atomic<int> tmp_init_db_version = 0;

enum class BlobType {
    Swarms,
    RetryableRequests,
};

// Storage database class.
class Database {
    // Held by pointer so that this header does not have to pull in SQLiteCpp.
    std::unique_ptr<session::sqlite::Database> db_;
    friend class DatabaseImpl;

    // Applied to every connection the pool opens, not just the first.
    void setup_connection(session::sqlite::Connection& conn);

    const std::filesystem::path db_path_;

    // Constant for the database, but written from whichever thread opens a connection, so atomic
    // even though every write stores the same value.
    std::atomic<int> page_size_ = 0;

    friend class TestSuiteHacks;
    // Shifts every pending retry's next_retry earlier, so that a test can reach the ready state
    // without waiting out RETRY_INITIAL_DELAY.
    void test_suite_backdate_retries(std::chrono::seconds age);

    // keep track of db full errors so we don't print them on every store
    std::atomic<int> db_full_counter = 0;

    // True if swarm state was already persisted in the database when it was opened.
    // On the first swarm update after startup, this prevents spurious DB dump requests
    // to peers who only appear as new members because swarm state was not persisted
    // in pre-migration databases.
    bool _had_swarm_state_on_open = false;

  public:
    // Recommended period for calling clean_expired()
    static constexpr auto CLEANUP_PERIOD = 10s;

    static constexpr int64_t SIZE_LIMIT = 10LL * 1024 * 1024 * 1024;  // 10 GiB

    // How long after a swarm request to a peer times out before we first retry it.
    static constexpr auto RETRY_INITIAL_DELAY = 15s;
    // How long to wait between retry attempts once a retry has been sent.
    static constexpr auto RETRY_INTERVAL = 60s;
    // How long to wait before re-checking a retry that could not be sent because we had no contact
    // details for the peer.
    static constexpr auto RETRY_NO_CONTACT_INTERVAL = 15s;

    // Constructor.  Note that you *must* also set up a timer that runs periodically (every
    // CLEANUP_PERIOD is recommended) and calls clean_expired().
    explicit Database(std::filesystem::path db_path);

    ~Database();

    bool had_swarm_state_on_open() const { return _had_swarm_state_on_open; }

    // if the database is full then print an error only once ever N errors
    static constexpr int DB_FULL_FREQUENCY = 100;

    // Stores a message in the database.  Returns an enum value indicating the result -- see
    // StoreResult for a description.  `expiry` can be set to a pointer into which the message's
    // expiry (existing, if longer; otherwise the one from `msg`) will be copied.
    StoreResult store(const message& msg, std::chrono::system_clock::time_point* expiry = nullptr);

    void bulk_store(const std::vector<message>& items);

    // Default value for message overhead calculations in `retrieve`.  In practice, overhead for the
    // message itself (i.e. the json keys, etc.) seems to be in the 75-80 character range (depending
    // on whether json or bt-encoded), not including the hash + the data.
    constexpr static size_t DEFAULT_MSG_OVERHEAD = 100;

    // Retrieves messages owned by pubkey received since `last_hash` stored in namespace `ns`.  If
    // last_hash is empty or not found then returns all messages (up to the limit). Optionally takes
    // a maximum number of messages to return or a maximum aggregate size of messages to return.
    //
    // Note that the `pubkey` value of the returned message's will be left default constructed,
    // i.e. *not* filled with the given pubkey.
    //
    // Returns a vector of messages, and a bool indicating whether there are more results to
    // retrieve.
    std::pair<std::vector<message>, bool> retrieve(
            const user_pubkey& pubkey,
            namespace_id ns,
            const std::string& last_hash,
            std::optional<size_t> num_results = std::nullopt,
            std::optional<size_t> max_size = std::nullopt,
            bool size_b64 =
                    true,  // True if the data will get b64-encoded (and thus is 4/3 as large)
            size_t per_message_overhead =
                    DEFAULT_MSG_OVERHEAD  // how much overhead per message to allow for
    );

    // Retrieves all messages.
    std::vector<message> retrieve_all();

    enum class GetMessageCount {
        All,
        Owned,  // Only messages that belong to this node's swarm
    };

    // Return the total number of messages stored
    int64_t get_message_count();

    // Returns the per-owner counts of stored messages, for storage statistics purposes.
    std::vector<int> get_message_counts();

    // Returns the number of distinct owner pubkeys with stored messages
    int64_t get_owner_count();

    // Returns the number of messages grouped by namespace id
    std::vector<std::pair<namespace_id, int64_t>> get_namespace_counts();

    // Returns the number of allocated bytes used on disk (i.e. used pages * page size).  This
    // includes both used and unused storage (i.e. allocated on disk, currently currently unused
    // that will likely be reused by sqlite when needed).
    int64_t get_total_bytes();

    // Returns the number of used bytes on disk; that is, total pages (as returned by
    // `get_total_bytes`) minus unused pages in the database file.  Note that this is still an upper
    // bound on actual stored size as there may be partially filled pages.
    int64_t get_used_bytes();

    // Get message by `msg_hash`, return true if found.  Note that this does *not* filter by
    // pubkey or namespace!
    std::optional<message> retrieve_by_hash(const std::string& msg_hash);

    // Removes expired messages from the database; the `Database` instance owner should call
    // this periodically.
    void clean_expired();

    // Deletes all messages owned by the given pubkey.  Returns the [namespace, hash] pairs of any
    // deleted messages.
    std::vector<std::pair<namespace_id, std::string>> delete_all(const user_pubkey& pubkey);

    // Deletes all messages owned by the given pubkey with the given namespace.  Returns the hashes
    // of any deleted messages.
    std::vector<std::string> delete_all(const user_pubkey& pubkey, namespace_id ns);

    // Delete messages owned by the given pubkey having the given hashes.  Returns the hashes of any
    // deleted messages.
    std::vector<std::string> delete_by_hash(
            const user_pubkey& pubkey, const std::vector<std::string>& msg_hashes);

    // Deletes all messages owned by the given pubkey with a timestamp <= timestamp.  Returns the
    // [namespace, hash] pairs of any deleted messages.
    std::vector<std::pair<namespace_id, std::string>> delete_by_timestamp(
            const user_pubkey& pubkey, std::chrono::system_clock::time_point timestamp);

    // Deletes all messages owned by the given pubkey with a timestamp <= timestamp in the given
    // namespace.  Returns the hashes of any deleted messages.
    std::vector<std::string> delete_by_timestamp(
            const user_pubkey& pubkey,
            namespace_id ns,
            std::chrono::system_clock::time_point timestamp);

    // Adds access tokens to the revoked token database so that users may not longer use those
    // tokens to authenticate.
    void revoke_subaccounts(
            const user_pubkey& pubkey, const std::vector<subaccount_token>& subaccount);

    // Removes access tokens from the revoked token database so that users may use those tokens to
    // authenticate (if currently revoked).  Returns the number of tokens that were found and
    // removed.
    int unrevoke_subaccounts(
            const user_pubkey& pubkey, const std::vector<subaccount_token>& subaccount);

    // Checks if a subaccount token exists in the revoked subaccount database. Returns true if the
    // subaccount has been revoked, false otherwise.
    bool subaccount_revoked(const user_pubkey& pubkey, const subaccount_token& subaccount);

    // Return the list of currently revoked subaccounts
    std::vector<std::string> revoked_subaccounts(const user_pubkey& pubkey);

    // Updates the expiry time of the given messages owned by the given pubkey.  Returns a vector of
    // pairs of hashes of updated messages to the new expiry of the messages.  Hashes that don't
    // exist, or were not updated, are not returned.
    //
    // extend_only and shorten_only allow message expiries to only be adjusted in one way or the
    // other.  They are mutually exclusive.
    //
    // new_exp can be length one to apply the same timestamp to all messages, or the same length as
    // msg_hashes to apply a different timestamp to each.
    std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> update_expiry(
            const user_pubkey& pubkey,
            const std::vector<std::string>& msg_hashes,
            const std::vector<std::chrono::system_clock::time_point> new_exp,
            bool extend_only = false,
            bool shorten_only = false);

    // Shortens the expiry time of all messages owned by the given pubkey.  Expiries can only be
    // shortened (i.e. brought closer to now), not extended into the future.  Returns a vector of
    // [namespace, hash] pairs of messages that had their expiries shortened.
    std::vector<std::pair<namespace_id, std::string>> update_all_expiries(
            const user_pubkey& pubkey, std::chrono::system_clock::time_point new_exp);

    // Shortens the expiry time of all messages owned by the given pubkey in the given namespace.
    // Expiries can only be shortened (i.e. brought closer to now), not extended into the future.
    // Returns a vector of hashes of messages that had their expiries shortened.
    std::vector<std::string> update_all_expiries(
            const user_pubkey& pubkey,
            namespace_id ns,
            std::chrono::system_clock::time_point new_exp);

    // Retrieves the expiries of messages by hash.  Returns a map of hash -> expiry (hashes not
    // found are not included).
    std::map<std::string, int64_t> get_expiries(
            const user_pubkey& pubkey, const std::vector<std::string>& msg_hashes);

    // Adds a request retry to the database, to be retried later.  If req_id is specified, this
    // is a subsequent failure on the same request.  It's not great to leak database table indices
    // into the rest of the code if avoidable, but deduplication would be otherwise tedious.
    int64_t add_retry_request(
            const crypto::legacy_pubkey& key,
            const std::string& cmd,
            const std::string& payload,
            int64_t req_id = 0);

    // executes the provided callback for each request retry in the database which ready to retry.
    // The table id is provided so the callback can call remove_retry_request on success.  The
    // callback returns true if it sent the request, in which case the next retry is scheduled
    // RETRY_INTERVAL out, or false if it could not send it (e.g. no contact details yet), in which
    // case the next retry is scheduled RETRY_NO_CONTACT_INTERVAL out.
    void foreach_ready_retry_request(std::function<
                                     bool(const crypto::legacy_pubkey& key,
                                          const std::string& cmd,
                                          const std::string& payload,
                                          int64_t req_id)>);

    // This is just for the test suite, as using "ready retry requests" as above would require it
    // to take several seconds longer to execute, per call.
    int64_t retry_request_count();

    // Swarm space ranges below are (lower, upper] on the circular uint64 swarm space, as returned
    // by Network::get_swarm_boundaries(): lower < upper is an ordinary interval, lower > upper
    // wraps around past UINT64_MAX, and lower == upper (only when there is a single swarm) is the
    // whole space.

    // True if any message owner falls in the given swarm space range.
    bool has_owners_in_range(uint64_t lower, uint64_t upper);

    // The highest message id in the database, or 0 if there are no messages.
    int64_t max_message_id();

    // A queued or in-progress dump of our messages to another service node: every message with id
    // in [next_id, end_id] whose owner is in `swarm`'s swarm space range still has to be sent.
    struct pending_dump {
        crypto::legacy_pubkey pubkey;
        uint64_t swarm;
        int64_t next_id;
        int64_t end_id;
        std::chrono::system_clock::time_point next_attempt;
    };

    // Queues a dump to `pubkey` of all current messages (up to and including `end_id`) for the
    // given swarm.  If a dump to that node for that swarm is already queued it is restarted from
    // the beginning with the later end id, so that nothing the new request covers is skipped.
    void queue_dump(const crypto::legacy_pubkey& pubkey, uint64_t swarm, int64_t end_id);

    std::vector<pending_dump> pending_dumps();

    // Records progress on a dump: `next_id` is the first id not yet confirmed received, and
    // `next_attempt` the earliest time to send more.
    void update_dump(
            const crypto::legacy_pubkey& pubkey,
            uint64_t swarm,
            int64_t next_id,
            std::chrono::system_clock::time_point next_attempt);

    void remove_dump(const crypto::legacy_pubkey& pubkey, uint64_t swarm);

    // Returns the next batch of a dump: messages with id in [from_id, end_id] whose owner is in the
    // swarm space range, in id order, stopping after the message that takes the batch past
    // `byte_budget`.  The second element is the id of the last message returned (0 if none).
    std::pair<std::vector<message>, int64_t> next_dump_batch(
            int64_t from_id, int64_t end_id, uint64_t lower, uint64_t upper, size_t byte_budget);

    // Remove the specified request retry.  This is one node's retry request, not the request
    // itself -- if no more nodes need the request retried it will be removed as well.
    void remove_node_retry_request(int64_t req_id);

    // the `now` argument here only exists for the test suite; do not use it.
    void remove_expired_retry_requests(
            std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

    void update_current_swarm(uint64_t swarm_id);

    std::optional<uint64_t> get_current_swarm();
};

}  // namespace oxenss
