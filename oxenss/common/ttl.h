#pragma once

#include <chrono>

namespace oxenss {

using namespace std::literals;

// Minimum and maximum TTL permitted for storing a new, public message
inline constexpr auto TTL_MINIMUM = 10s;
inline constexpr auto TTL_MAXIMUM = 14 * 24h;

// For messages in a user's control (i.e. new messages in private namespaces, or updating TTLs of
// existing public or private namespace messages) we allow a longer TTL.
inline constexpr auto TTL_MAXIMUM_PRIVATE = 30 * 24h;

}  // namespace oxenss
