#pragma once

#include <cstdint>
#include <map>

namespace oxenss::server {

/// Which missed-notification replay paces each connection.  Notifications go out on a connection's
/// one stream, and a replay paces itself by the callback it sets on that stream's unsent-buffer
/// watermark, so only one replay can be pacing there at a time: the newest.  A connection can have
/// two replays in flight when it switches sessions mid-replay; the older one is then superseded,
/// and must neither replace the newer one's callback nor switch its pacing off when it ends.
///
/// Replays are identified by ids that increase with each one started.  Not thread-safe: the QUIC
/// server uses it only on its loop thread.
template <typename Key>
class replay_owners {
    struct owner {
        uint64_t latest = 0;  // the newest replay seen on the key
        bool pacing = false;  // whether that one has pacing in place
    };
    std::map<Key, owner> owners_;

  public:
    // Called for each chunk replay `id` sends on `key`: false if a newer replay has started there
    // since, in which case this one is superseded and is to stop; otherwise it now paces the key.
    bool claim(const Key& key, uint64_t id) {
        auto& o = owners_[key];
        if (id < o.latest)
            return false;
        o.latest = id;
        o.pacing = true;
        return true;
    }

    // Called when replay `id` is done on `key`, finished or given up: true if it is the one pacing
    // there, whose pacing is then to be switched off.
    bool release(const Key& key, uint64_t id) {
        auto it = owners_.find(key);
        if (it == owners_.end() || it->second.latest != id || !it->second.pacing)
            return false;
        it->second.pacing = false;
        return true;
    }

    // Drops what is known of `key`, e.g. when its connection has closed.
    void forget(const Key& key) { owners_.erase(key); }

    void clear() { owners_.clear(); }
};

}  // namespace oxenss::server
