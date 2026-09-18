#include "swarm.h"
#include "oxenss/crypto/keys.h"
#include "service_node.h"
#include <oxenss/common/format.h>
#include <oxenss/logging/oxen_logger.h>
#include <chrono>
#include <oxenss/utils/string_utils.hpp>

#include <nlohmann/json.hpp>
#include <oxenc/base32z.h>

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
        log::info(logcat, "Joined swarm {:#18x} (blk {})", new_swarm, height);
        // Every member of the swarm is new to us
        events.new_swarm_members = events.our_swarm_members;
        events.new_swarm_members.erase(our_pk);
        return events;
    }

    if (old_swarm != new_swarm) {
        // Moved to a new swarm; every member of it is new to us
        events.new_swarm_members = events.our_swarm_members;
        events.new_swarm_members.erase(our_pk);

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
                events.dissolved ? "(dissolved) " : "",
                new_swarm,
                height);

        // If our old swarm is still alive then the remaining members continue to administer it and
        // we have nothing to push; if it dissolved we have to push what we hold to the swarms that
        // now own it.  Either way we ask our new swarm's members for its messages.
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
    //
    // On the first update after startup we have no previous swarm list to compare against (only
    // our own swarm id is persisted), so every swarm would look new; none of them are.
    if (!network.swarms_.empty()) {
        auto new_swarm_ids = std::views::keys(swarms);
        auto old_swarm_ids = std::views::keys(network.swarms_);
        std::set_difference(
                new_swarm_ids.begin(),
                new_swarm_ids.end(),
                old_swarm_ids.begin(),
                old_swarm_ids.end(),
                std::inserter(events.new_swarms, events.new_swarms.end()));
    }

    return events;
}

SwarmEvents Swarm::update_swarms(
        uint64_t height,
        swarms_t&& swarms,
        const std::map<crypto::legacy_pubkey, contact>& new_contacts) {

    std::lock_guard lock{network.mut_};

    // The first update after startup has no previous swarm list; only our own swarm id survives a
    // restart, so "still in the same swarm" says nothing about what we hold.
    const bool first_update = network.swarms_.empty();

    auto events = derive_swarm_events(height, swarms);
    const bool entered_swarm =
            events.our_swarm_id != INVALID_SWARM_ID && events.our_swarm_id != cur_swarm_id_;

    if (events.our_swarm_id != INVALID_SWARM_ID) {
        for (const auto& pk : events.new_swarm_members)
            log::info(logswarm, "New SN joining our swarm: {}", pk);

        for (auto swarm : events.new_swarms)
            log::info(logswarm, "New network swarm: {}", swarm);

        for (auto it = members_.begin(); it != members_.end();) {
            if (events.our_swarm_members.find(it->first) == events.our_swarm_members.end())
                it = members_.erase(it);
            else
                it++;
        }
        for (const auto& pk : events.new_swarm_members)
            members_[pk];

        // We ask our peers for the swarm's messages when we have just entered the swarm, and on
        // the first update after startup if we hold none of them: a fresh, wiped or copied
        // database looks the same as a wiped one from here.  A restart that finds us in the same
        // swarm with its messages present asks for nothing, and neither does a peer joining a
        // swarm we are already in (it asks us).
        bool request_dump = entered_swarm;
        if (first_update) {
            auto [lower, upper] = Network::swarm_boundaries(swarms, events.our_swarm_id);
            request_dump = !_db.has_owners_in_range(lower, upper);
        }
        if (request_dump) {
            log::info(
                    logswarm,
                    "Requesting swarm {:x} messages from {} peers",
                    events.our_swarm_id,
                    members_.size() - members_.count(our_pk));
            for (auto& [pk, state] : members_) {
                if (pk == our_pk)
                    continue;
                state.our_ss_requested_db_dump = SwarmRequestedDBDump::NeedsToRequest;
                // The request goes out with the handshake, so redo that even for a member we had
                // already handshaken with.
                state.status = SwarmMemberStatus::ContactDetailsPending;
                state.check_contact_info_next_retry = {};
            }
        }
    }

    cur_swarm_id_ = events.our_swarm_id;
    _db.update_current_swarm(cur_swarm_id_);

    network.update_swarms(std::move(swarms), new_contacts);

    return events;
}

bool Swarm::is_pubkey_for_us(const user_pubkey& pk) const {
    auto maybe_swarm = network.get_swarm_id_for(pk);
    return maybe_swarm && cur_swarm_id_ == *maybe_swarm;
}

std::map<crypto::legacy_pubkey, SwarmMemberState> Swarm::members() const {
    std::shared_lock lock{network.mut_};
    return members_;
}

// Returns a copy of all the other members of this swarm, not including this node.
std::map<crypto::legacy_pubkey, SwarmMemberState> Swarm::peers() const {
    auto peers = members();
    peers.erase(our_pk);
    return peers;
}

std::optional<SwarmMemberState> Swarm::is_member(const crypto::legacy_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    std::optional<SwarmMemberState> result;
    if (const auto& it = members_.find(pk); it != members_.end())
        result = it->second;
    return result;
}

std::optional<SwarmMemberState> Swarm::is_member(const crypto::x25519_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    std::optional<SwarmMemberState> result;
    if (auto lpk = network.contacts.lookup(pk))
        result = is_member(*lpk);
    return result;
}

std::optional<SwarmMemberState> Swarm::is_member(const crypto::ed25519_pubkey& pk) const {
    std::shared_lock lock{network.mut_};
    std::optional<SwarmMemberState> result;
    if (auto lpk = network.contacts.lookup(pk))
        result = is_member(*lpk);
    return result;
}

SwarmMemberState* Swarm::is_member_locked(const crypto::legacy_pubkey& pk) {
    SwarmMemberState* result = nullptr;
    if (auto it = members_.find(pk); it != members_.end())
        result = &it->second;
    return result;
}

size_t Swarm::size() const {
    std::shared_lock lock{network.mut_};
    return members_.size();
}

std::set<crypto::legacy_pubkey> Swarm::extract_contact_pending_members() {
    std::lock_guard lock{network.mut_};

    std::set<crypto::legacy_pubkey> result;
    auto now = std::chrono::steady_clock::now();
    for (auto it = members_.begin(); it != members_.end(); it++) {
        SwarmMemberState& state = it->second;
        if (state.status != SwarmMemberStatus::ContactDetailsPending)
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

namespace {

    // The fields we publish about a swarm member, listed once so that the json and bt encodings
    // cannot drift apart.  `add(key, value)` is called for each in ascending key order, which bt
    // dicts require; json objects are key-sorted regardless, so the order does not affect the json
    // output.
    template <typename Add>
    void snode_fields(const crypto::legacy_pubkey& snpk, const contact& ct, Add&& add) {
        // Deprecated; use pubkey_legacy instead:
        add("address", "{}.snode"_format(oxenc::to_base32z(snpk.view())));
        add("ip", ct.ip.to_string());
        // Deprecated string port for backwards compat; prefer port_https:
        add("port", "{}"_format(ct.https_port));
        add("port_https", ct.https_port);
        add("port_omq", ct.omq_quic_port);
        add("port_quic", ct.omq_quic_port);
        add("pubkey_ed25519", ct.pubkey_ed25519.hex());
        add("pubkey_legacy", snpk.hex());
        add("pubkey_x25519", ct.pubkey_x25519.hex());
    }

    template <typename F>
    void each_contactable_member(const swarm_membership& swarm, const Contacts& contacts, F&& f) {
        if (!swarm)
            return;
        for (const auto& snpk : swarm->second) {
            auto ct = contacts.find(snpk);
            // Older versions did not even have (and so could not return) any info for
            // non-contactable nodes, so do the same to avoid potentially breaking session clients
            // that aren't expecting 0 values for pubkey/IP/ports.
            if (!ct || !*ct)
                continue;
            f(snpk, *ct);
        }
    }

    std::string swarm_id_hex(const swarm_membership& swarm) {
        return "{:x}"_format(swarm ? swarm->first : INVALID_SWARM_ID);
    }

}  // namespace

nlohmann::json swarm_to_json(const swarm_membership& swarm, const Contacts& contacts) {
    auto snodes = nlohmann::json::array();
    each_contactable_member(swarm, contacts, [&snodes](const auto& snpk, const contact& ct) {
        auto& sn = snodes.emplace_back(nlohmann::json::object());
        snode_fields(snpk, ct, [&sn](std::string_view key, auto&& val) {
            sn[std::string{key}] = std::forward<decltype(val)>(val);
        });
    });

    return nlohmann::json{{"snodes", std::move(snodes)}, {"swarm", swarm_id_hex(swarm)}};
}

void swarm_to_bt(
        oxenc::bt_dict_producer& out, const swarm_membership& swarm, const Contacts& contacts) {
    {
        auto snodes = out.append_list("snodes");
        each_contactable_member(swarm, contacts, [&snodes](const auto& snpk, const contact& ct) {
            auto sn = snodes.append_dict();
            snode_fields(snpk, ct, [&sn](std::string_view key, auto&& val) {
                sn.append(key, std::forward<decltype(val)>(val));
            });
        });
    }
    out.append("swarm", swarm_id_hex(swarm));
}

}  // namespace oxenss::snode
