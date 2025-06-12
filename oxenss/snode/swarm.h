#pragma once

#include <chrono>
#include <set>

#include "network.h"
#include "oxenss/crypto/keys.h"

namespace oxenss::snode {

using namespace std::literals;

class ServiceNode;

enum class SnodeStatus { UNKNOWN, UNSTAKED, DECOMMISSIONED, ACTIVE };

struct SwarmEvents {
    /// our (potentially new) swarm id
    swarm_id_t our_swarm_id;
    /// whether our swarm got dissolved and we need to salvage our stale data
    bool dissolved = false;
    /// detected new swarms that need to be bootstrapped
    std::set<swarm_id_t> new_swarms;
    /// detected new snodes in our swarm
    std::set<crypto::legacy_pubkey> new_swarm_members;
    /// our swarm members 
    std::set<crypto::legacy_pubkey> our_swarm_members;
};

enum struct SwarmMemberStatus {
    // Pubkeys of new members into our swarm who we haven't yet established communications with;
    // once we do, we push all our swarm's messages to them.
    ContactDetailsPending,
    ContactDetailsReady,
    Ready,
};

struct SwarmMemberState {
    SwarmMemberStatus status;

    std::chrono::milliseconds newest_msg_timestamp;

    // Set if this member joined the swarm. They are assumed to not have any of the messages for
    // the swarm yet so a full DB will be initiated
    bool new_swarm_member;

    // The earliest timestamp at which the swarm will check if they have received contact
    // information for this member yet and can send them data. Only utilised when status is
    // 'ContactDetailsPending' before transitioning to 'ContactDetailsReady' when the contact
    // detail has been confirmed.
    std::chrono::steady_clock::time_point check_contact_info_next_retry;
};


// How often we wait, after returning a pending new member, before we return the member again from
// `extract_new_members()`.
constexpr auto NEW_SWARM_MEMBER_RETRY = 30s;

class Swarm {
    // Extract relevant information from incoming swarm composition.
    SwarmEvents derive_swarm_events(uint64_t height, const swarms_t& swarms) const;

    friend class ServiceNode;

    std::map<crypto::legacy_pubkey, SwarmMemberState>
            members_;  // includes `our_pk`, when we are in a swarm.

    swarm_id_t cur_swarm_id_ = INVALID_SWARM_ID;

  public:
    Swarm(Network& network, const crypto::legacy_pubkey& our_pk) :
            network{network}, our_pk{our_pk} {}

    ~Swarm();

    Network& network;

    const crypto::legacy_pubkey our_pk;

    /// Update swarm state; this takes care of updating both this swarm itself, and propagates the
    /// general network swarm changes to the Network object (including contacts) as well.
    SwarmEvents update_swarms(
            uint64_t height,
            swarms_t&& swarms,
            const std::map<crypto::legacy_pubkey, contact>& new_contacts);

    bool is_pubkey_for_us(const user_pubkey& pk) const;

    // Returns a copy of all the members of this swarm, including this node.
    std::map<crypto::legacy_pubkey, SwarmMemberState> members() const;

    // Returns a copy of all the other members of this swarm, not including this node.
    std::map<crypto::legacy_pubkey, SwarmMemberState> peers() const;

    // Returns the swarm member's state if the given pubkey is recognized as a member of this swarm.
    std::optional<SwarmMemberState> is_member(const crypto::legacy_pubkey& pk) const;
    std::optional<SwarmMemberState> is_member(const crypto::x25519_pubkey& pk) const;
    std::optional<SwarmMemberState> is_member(const crypto::ed25519_pubkey& pk) const;

    // Returns the size of this swarm (including this node).
    size_t size() const;

    // Resets the timer and returns the pubkeys of any new swarm members that are due to be
    // contacted to establish liveness in prep for transitioning to a contact that we can push swarm
    // messages to.
    std::set<crypto::legacy_pubkey> extract_contact_pending_members();

    // Returns the pubkeys of any new swarm members that have joined that we now have contact
    // details for, mark them as ready and need a dump of the DB.
    std::set<crypto::legacy_pubkey> extract_contacts_needing_db_dump();

    // Marks a pending member as ready, so that it is returned by the next call to
    // `extract_contact_details_ready_members()`, and is no longer returned by
    // `extract_contract_details_pending_member()`.
    void set_member_contact_details_ready(
            const crypto::legacy_pubkey& pk,
            std::optional<std::chrono::milliseconds> last_synced_ts);

    swarm_id_t our_swarm_id() const {
        std::shared_lock lock{network.mut_};
        return cur_swarm_id_;
    }

    bool is_valid() const { return our_swarm_id() != INVALID_SWARM_ID; }
};

}  // namespace oxenss::snode
