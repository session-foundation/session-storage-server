#pragma once

#include <filesystem>

namespace oxenss::test {

struct StorageDeleter {
    bool delete_it = true;
    StorageDeleter() { std::filesystem::remove("storage.db"); }
    ~StorageDeleter() {
        if (delete_it)
            std::filesystem::remove("storage.db");
    }
};

}  // namespace oxenss::test
