#include <catch2/catch.hpp>

#include <oxenss/logging/oxen_logger.h>

using namespace oxenss;
using oxen::log::Level;

TEST_CASE("logging - configured levels adjust the defaults", "[logging]") {
    struct restore_levels {
        ~restore_levels() { oxen::log::reset_level(Level::info); }
    } restorer;

    SECTION("nothing configured") {
        REQUIRE(logging::apply_levels(""));
        CHECK(oxen::log::get_level("quic") == Level::warn);
        CHECK(oxen::log::get_level("oxenmq") == Level::warn);
        CHECK(oxen::log::get_level("db") == Level::info);
    }

    SECTION("a category entry adds to the defaults") {
        REQUIRE(logging::apply_levels("db=debug"));
        CHECK(oxen::log::get_level("db") == Level::debug);
        CHECK(oxen::log::get_level("quic") == Level::warn);
        CHECK(oxen::log::get_level("oxenmq") == Level::warn);
        CHECK(oxen::log::get_level("snode") == Level::info);
    }

    SECTION("a bare level resets everything, defaults included") {
        REQUIRE(logging::apply_levels("debug,snode=trace"));
        CHECK(oxen::log::get_level("quic") == Level::debug);
        CHECK(oxen::log::get_level("db") == Level::debug);
        CHECK(oxen::log::get_level("snode") == Level::trace);
    }

    SECTION("nothing usable") {
        CHECK_FALSE(logging::apply_levels("verbose"));
        CHECK(oxen::log::get_level("quic") == Level::warn);
    }
}
