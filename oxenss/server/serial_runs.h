#pragma once

#include <cstddef>
#include <deque>
#include <map>
#include <utility>

namespace oxenss::server {

/// Runs some of each connection's requests one after another, in the order they arrive, while
/// leaving the work itself to happen elsewhere (on worker threads).  A connection is "running" from
/// the first such request until its run finishes with nothing left waiting; requests added while it
/// runs wait their turn.  Not thread-safe: the QUIC server uses it only on its loop thread.
template <typename Key, typename T>
class serial_runs {
    // Present for each running key: the items waiting to run after the current ones.
    std::map<Key, std::deque<T>> waiting_;

  public:
    // The most items that can wait behind a run; any more are refused.
    static constexpr size_t MAX_WAITING = 64;

    enum class added {
        run,     // nothing was running for the key: run the item now, and call `next` when done
        queued,  // the item waits behind the current run, to be returned by a later `next`
        full,    // too many are already waiting: the item was not added
    };

    bool running(const Key& key) const { return waiting_.contains(key); }

    added add(const Key& key, T& item) {
        auto [it, inserted] = waiting_.try_emplace(key);
        if (inserted)
            return added::run;
        if (it->second.size() >= MAX_WAITING)
            return added::full;
        it->second.push_back(std::move(item));
        return added::queued;
    }

    // Called when the items last returned to run for `key` are done: returns those that have been
    // waiting since, in order, to run next.  An empty result means the run is over (and nothing is
    // running for the key any more), as is the case for a key that has been forgotten.
    std::deque<T> next(const Key& key) {
        auto it = waiting_.find(key);
        if (it == waiting_.end())
            return {};
        if (it->second.empty()) {
            waiting_.erase(it);
            return {};
        }
        return std::exchange(it->second, {});
    }

    // Drops everything for `key`, e.g. when its connection has closed.
    void forget(const Key& key) { waiting_.erase(key); }

    void clear() { waiting_.clear(); }
};

}  // namespace oxenss::server
