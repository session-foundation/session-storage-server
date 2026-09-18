#pragma once

#include <filesystem>
#include <string_view>

#include <oxen/log.hpp>

namespace oxenss {
namespace log = oxen::log;
}

namespace oxenss::logging {

// Everything at info except libquic and oxenmq, which are chatty at that level.
inline constexpr std::string_view DEFAULT_LOG_LEVELS = "info,quic=warning,oxenmq=warning";

// Sets up logging to stdout and to a rotating file in `data_dir`, and applies `log_levels`: a bare
// level ("debug"), which applies to every category, and/or comma-separated CAT=LEVEL entries
// ("*=warning,snode=debug"); see oxen::log::extract_categories for the full syntax.  An empty
// string means DEFAULT_LOG_LEVELS.  Entries that do not parse are logged and skipped; returns
// false if nothing in the string was usable.
bool init(const std::filesystem::path& data_dir, std::string_view log_levels);

}  // namespace oxenss::logging
