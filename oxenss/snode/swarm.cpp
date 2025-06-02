#include "swarm.h"
#include "oxenss/crypto/keys.h"
#include "service_node.h"
#include <oxenss/logging/oxen_logger.h>
#include <chrono>
#include <oxenss/utils/string_utils.hpp>

#include <algorithm>
#include <cstdlib>
#include <ranges>

namespace oxenss::snode {

static auto logcat = log::Cat("snode");
static auto logswarm = log::Cat("swarm");

Swarm::~Swarm() = default;

SwarmEvents Swarm::derive_swarm_events(uint64_t height, const swarms_t& swarms) const {
    SwarmEvents events{};

    events.our_swarm_id = INVALID_SWARM_ID;
    for (auto& [id, members] : swarms) {
        if (members.count(our_pk)) {
            events.our_swarm_id = id;
            events.our_swarm_members = members;
            break;
        }
    }

    const auto& new_swarm = events.our_swarm_id;
    const auto& old_swarm = cur_swarm_id_;

    if (new_swarm == INVALID_SWARM_ID) {
        if (cur_swarm_id_ != INVALID_SWARM_ID)
            log::warning(
                    logswarm,
                    "Leaving swarm {:#018x}: we are no longer an active Service Node",
                    cur_swarm_id_);
        else
            log::debug(logswarm, "Still not an active Service Node");

        // We are not in any swarm (or have been kicked out); nothing to do
        return events;
    }

    if (old_swarm == INVALID_SWARM_ID) {
        log::info(logcat, "Joined swarm {:#18x} (blk {:#018x})", new_swarm, height);
        // We were previously not in a swarm, which means we just got assigned to one and so we have
        // nothing to do (other snodes will also see this and push messages to us).
        events.new_swarm_members = events.our_swarm_members;
        events.new_swarm_members.erase(our_pk);
        return events;
    }

    if (old_swarm != new_swarm) {
        // Moved to a new swarm

        if (!network.swarms_.count(old_swarm)) {
            // The old swarm dissolved, which means we have a responsibility to push messages we are
            // still holding to whichever swarm(s) should now own them.  E.g. if swarms were
            // previously distributed:
            //
            //          A                B                 C
            // |.................|###############|!!!!!!!!!!!!!!!!!|
            //
            // and B gets dissolved then all the messages in swarm space ### need to get sent to
            // either A or C (depending on which swarm they land post-dissolution), like this:
            //
            //          A                                  C
            // |.................########|########!!!!!!!!!!!!!!!!!|
            events.dissolved = true;
        }
        log::info(
                logcat,
                "Changed from {:018x} {}to {:018x} (blk {})",
                old_swarm,
                new_swarm,
                height,
                events.dissolved ? "(dissolved) " : "");

        // If our old swarm is still alive then that means we got moved out of it, and so there's
        // nothing for us to do because the remaining swarm members will continue to administer the
        // old swarm, and whatever swarm we just moved into (possibly a new one) will have messages
        // pushed to it by other network nodes.
        return events;
    }

    /// --- WE are still in the same swarm if we reach here ---

    /// See if anyone joined our swarm: if so, we need to push messages to them:
    for (auto it : events.our_swarm_members)
        if (members_.count(it) == 0)
            events.new_swarm_members.insert(it);
    events.new_swarm_members.erase(our_pk);

    // See if there are any new swarms, because if there are, we might need to push messages to them
    // if they happened to get set up adjascent to us.  E.g. if we are A (or C) here:
    //
    //          A                                  C
    // |.................########|########!!!!!!!!!!!!!!!!!|
    //
    // and B gets created in between us, then we need to push the `#` messages that we currently
    // hold to the new B swarm, so that the local swarm space ends up looking like this:
    //
    //          A                B                 C
    // |.................|###############|!!!!!!!!!!!!!!!!!|
    //
    // FIXME: currently we do this on any new swarm creation, but that seems excessive: we really
    // only need to worry about this if our boundary on either side changes.  (Most of the time it
    // won't because, with hundreds of swarms, most new swarms don't affect our swarm space).
    auto new_swarm_ids = std::views::keys(swarms);
    auto old_swarm_ids = std::views::keys(network.swarms_);
    std::set_difference(
            new_swarm_ids.begin(),
            new_swarm_ids.end(),
            old_swarm_ids.begin(),
            old_swarm_ids.end(),
            std::inserter(events.new_swarms, events.new_swarms.end()));

    return events;
}

SwarmEvents Swarm::update_swarms(
        uint64_t height,
        swarms_t&& swarms,
        const std::map<crypto::legacy_pubkey, contact>& new_contacts) {

    std::lock_guard lock{network.mut_};

    auto events = derive_swarm_events(height, swarms);

    if (events.our_swarm_id != INVALID_SWARM_ID) {
        for (const auto& pk : events.new_swarm_members)
            log::info(logswarm, "New SN joining our swarm: {}", pk);

        for (auto swarm : events.new_swarms)
            log::info(logswarm, "New network swarm: {}", swarm);

        // Remove members that are no longer in the swarm from our runtime state
        for (auto it = members_.begin(); it != members_.end(); ) {
            if (events.our_swarm_members.find(it->first) == events.our_swarm_members.end())
                it = members_.erase(it);
            else
                it++;
        }

        // Add members from the swarm that are missing from our runtime state
        for (auto it : events.our_swarm_members)
            members_.try_emplace(it);
    }

    cur_swarm_id_ = events.our_swarm_id;

    network.update_swarms(std::move(swarms), new_contacts);

    return events;
}

bool Swarm::is_pubkey_for_us(const user_pubkey& pk) const {
    auto maybe_swarm = network.get_swarm_id_for(pk);
    return maybe_swarm && cur_swarm_id_ == *maybe_swarm;
}

std::map<crypto::legacy_pubkey, Swarm::MemberState> Swarm::members() const {
    std::shared_lock lock{network.mut_};
    return members_;
}

// Returns a copy of all the other members of this swarm, not including this node.
std::map<crypto::legacy_pubkey, Swarm::MemberState> Swarm::peers() const {
    auto peers = members();
    peers.erase(our_pk);
    return peers;
}

bool Swarm::is_member(const crypto::legacy_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    return members_.count(pk);
}

bool Swarm::is_member(const crypto::x25519_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    if (auto lpk = network.contacts.lookup(pk))
        return members_.count(*lpk);
    return false;
}

bool Swarm::is_member(const crypto::ed25519_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    if (auto lpk = network.contacts.lookup(pk))
        return members_.count(*lpk);
    return false;
}

size_t Swarm::size() const {
    std::shared_lock lock{network.mut_};
    return members_.size();
}

std::set<crypto::legacy_pubkey> Swarm::extract_contact_details_pending_members() {
    std::lock_guard lock{network.mut_};

    std::set<crypto::legacy_pubkey> result;
    auto now = std::chrono::steady_clock::now();
    for (auto it = members_.begin(); it != members_.end(); it++) {
        MemberState& state = it->second;
        if (state.status != MemberStatus::ContactDetailsPending)
            continue;
        std::chrono::steady_clock::time_point& next_retry =
                it->second.check_contact_info_next_retry;
        if (now >= next_retry) {
            next_retry = now + NEW_SWARM_MEMBER_RETRY;
            const crypto::legacy_pubkey& pk = it->first;
            result.insert(pk);
        }
    }

    return result;
}

std::set<crypto::legacy_pubkey> Swarm::extract_contact_details_ready_members() {
    std::lock_guard lock{network.mut_};

    std::set<crypto::legacy_pubkey> result;
    for (auto& it : members_) {
        if (it.second.status != MemberStatus::ContactDetailsReady)
            continue;
        const crypto::legacy_pubkey& pk = it.first;
        it.second.status = MemberStatus::Ready;
        result.insert(pk);
    }

    return result;
}

void Swarm::set_member_contact_details_ready(
        const crypto::legacy_pubkey& pk, std::optional<std::chrono::milliseconds> last_synced_ts) {
    std::lock_guard lock{network.mut_};

    auto it = members_.find(pk);
    assert(it != members_.end());

    if (it != members_.end()) {
        it->second.status = MemberStatus::ContactDetailsReady;
        if (last_synced_ts)
            it->second.newest_msg_timestamp = *last_synced_ts;
    }
}
}  // namespace oxenss::snode
