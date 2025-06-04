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

// How often we wait, after returning a pending new member, before we return the member again from
// `extract_new_members()`.
constexpr auto NEW_SWARM_MEMBER_RETRY = 30s;

class Swarm {
    // Extract relevant information from incoming swarm composition.
    SwarmEvents derive_swarm_events(uint64_t height, const swarms_t& swarms) const;

  public:
    Swarm(Network& network, const crypto::legacy_pubkey& our_pk) :
            network{network}, our_pk{our_pk} {}

    ~Swarm();

    enum struct MemberStatus {
        // Pubkeys of new members into our swarm who we haven't yet established communications with;
        // once we do, we push all our swarm's messages to them.
        ContactDetailsPending,
        ContactDetailsReady,
        Ready,
    };

    struct MemberState {
        MemberStatus status;
        std::chrono::milliseconds newest_msg_timestamp;

        // The earliest timestamp at which the swarm will check if they have received contact
        // information for this member yet and can send them data. Only utilised when status is
        // 'ContactDetailsPending' before transitioning to 'ContactDetailsReady' when the contact
        // detail has been confirmed.
        std::chrono::steady_clock::time_point check_contact_info_next_retry;
    };

    swarm_id_t cur_swarm_id_ = INVALID_SWARM_ID;

    std::map<crypto::legacy_pubkey, MemberState> members_;  // includes `our_pk`, when we are in a swarm.

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
    std::map<crypto::legacy_pubkey, MemberState> members() const;

    // Returns a copy of all the other members of this swarm, not including this node.
    std::map<crypto::legacy_pubkey, MemberState> peers() const;

    // Returns true if the given pubkey is recognized as a member of this swarm.
    bool is_member(const crypto::legacy_pubkey& pk) const;
    bool is_member(const crypto::x25519_pubkey& pk) const;
    bool is_member(const crypto::ed25519_pubkey& pk) const;

    // Returns the size of this swarm (including this node).
    size_t size() const;

    // Resets the timer and returns the pubkeys of any new swarm members that are due to be
    // contacted to push swarm messages to.
    std::set<crypto::legacy_pubkey> extract_contact_details_pending_members();

    // Marks a pending member as ready, so that it is returned by the next call to
    // `extract_contact_details_ready_members()`, and is no longer returned by
    // `extract_contract_details_pending_member()`.
    void set_member_contact_details_ready(
            const crypto::legacy_pubkey& pk,
            std::optional<std::chrono::milliseconds> last_synced_ts);

    // Extracts any "ready" members (that is, those that were pending and then marked ready with
    // `set_member_contact_details_ready`), returning them and transitioning them from the pending
    // state.
    std::set<crypto::legacy_pubkey> extract_contact_details_ready_members();

    swarm_id_t our_swarm_id() const {
        std::shared_lock lock{network.mut_};
        return cur_swarm_id_;
    }

    bool is_valid() const { return our_swarm_id() != INVALID_SWARM_ID; }
};

}  // namespace oxenss::snode
