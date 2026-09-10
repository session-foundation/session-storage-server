// Standalone migration test: open a pre-existing database, trigger migration, print results.
#include <oxenss/storage/database.hpp>
#include <iostream>
#include <filesystem>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: migrate_test <db_path>\n";
        return 1;
    }
    std::string path = argv[1];
    std::cout << "Opening: " << path << "\n";
    try {
        oxenss::Database db{path};
        std::cout << "had_swarm_state_on_open: " << db.had_swarm_state_on_open() << "\n";
        std::cout << "Migration complete.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
