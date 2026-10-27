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

// Applies DEFAULT_LOG_LEVELS and then, on top of them, `log_levels`: a bare level ("debug"), which
// resets every category, and/or comma-separated CAT=LEVEL entries ("*=warning,snode=debug"),
// applied in order; see oxen::log::extract_categories for the full syntax.  So "db=debug" adds to
// the defaults while "debug" replaces them.  Entries that do not parse are logged and skipped;
// returns false if `log_levels` is not blank but nothing in it was usable.
bool apply_levels(std::string_view log_levels);

// Sets up logging to stdout and to a rotating file in `data_dir`, then calls apply_levels() and
// returns its result.
bool init(const std::filesystem::path& data_dir, std::string_view log_levels);

}  // namespace oxenss::logging
