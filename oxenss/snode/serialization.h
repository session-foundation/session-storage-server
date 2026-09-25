#pragma once

#include <span>
#include <string>
#include <vector>
#include <oxenss/common/message.h>

namespace oxenss::snode {

// As soon as we exceed this we stop the current serialization message and begin a new one.  (And so
// our messages end up a little larger than this, but still well under the 10MiB limit).
inline constexpr size_t SERIALIZATION_BATCH_SIZE = 9'000'000;

// Newer serialization version based on bt-encoding.
inline constexpr uint8_t SERIALIZATION_VERSION_BT = 1;

// Serialises the messages into one or more blobs of at most about SERIALIZATION_BATCH_SIZE each.
std::vector<std::string> serialize_messages(std::span<const message> msgs, uint8_t version);

std::vector<message> deserialize_messages(std::string_view blob);

}  // namespace oxenss::snode
