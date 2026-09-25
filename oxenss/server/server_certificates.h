#pragma once

#include <filesystem>

namespace oxenss {
void generate_cert(const std::filesystem::path& cert_path, const std::filesystem::path& key_path);

}  // namespace oxenss
