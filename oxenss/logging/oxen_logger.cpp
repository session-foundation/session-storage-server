#include "oxen_logger.h"
#include <oxen/log.hpp>

#include <spdlog/sinks/rotating_file_sink.h>
#include <filesystem>
#include <oxenss/utils/string_utils.hpp>

namespace oxenss::logging {

static auto logcat = oxen::log::Cat("logging");

bool init(const std::filesystem::path& data_dir, std::string_view log_levels) {
    // Sinks first: the level parser reports bad entries through the logger.
    log::add_sink(log::Type::Print, "stdout");

    auto log_location = data_dir / "storage.logs";

    constexpr size_t LOG_FILE_SIZE_LIMIT = 1024 * 1024 * 50;  // 50MiB
    constexpr size_t EXTRA_FILES = 1;

    // setting this to `true` can be useful for debugging on testnet
    bool rotate_on_open = false;

    bool file_logging = true;
    try {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_location, LOG_FILE_SIZE_LIMIT, EXTRA_FILES, rotate_on_open);

        log::add_sink(std::move(file_sink));
    } catch (const spdlog::spdlog_ex& ex) {
        log::error(
                logcat,
                "Failed to open {} for logging: {}.  File logging disabled.",
                util::to_sv(log_location.u8string()),
                ex.what());
        file_logging = false;
    }

    if (log_levels.find_first_not_of(" \t,;") == std::string_view::npos)
        log_levels = DEFAULT_LOG_LEVELS;
    auto levels = log::extract_categories(log_levels);
    if (levels.empty())
        return false;
    levels.apply();

    if (file_logging)
        log::info(logcat, "Writing logs to {}", util::to_sv(log_location.u8string()));
    return true;
}

}  // namespace oxenss::logging
