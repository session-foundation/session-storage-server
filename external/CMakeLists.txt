
message(STATUS "Checking submodules")
check_submodule(CLI11)
check_submodule(cpr)
check_submodule(nlohmann_json)
check_submodule(oxen-libquic)
check_submodule(oxen-mq)
check_submodule(SQLiteCpp)
check_submodule(uWebSockets)


session_dep(libsodium 1.0.18)
session_dep(libzmq 4.3)
session_dep(libssl 3 WITH libcrypto)
session_dep(libcurl 7.68)

# oxenss/http drives curl from libquic's event loop, so it needs libevent itself rather than just
# inheriting it from libquic (which isn't built at all when a system liboxenquic is used).
session_dep(libevent_core 2.1)

# oxen-mq looks for plain `sodium` and `libzmq` targets set up by the parent project and links to
# those in preference to going looking for system libraries of its own.
add_library(sodium INTERFACE)
target_link_libraries(sodium INTERFACE sessiondep::libsodium)
add_library(libzmq INTERFACE)
target_link_libraries(libzmq INTERFACE sessiondep::libzmq)


# oxenc and oxen-logging come from libquic's submodules: libquic pulls them in anyway, and a second
# copy here would only be a second thing to keep in sync.
if(NOT TARGET oxenc::oxenc)
    sessiondep_or_submodule(liboxenc 1.5.0 oxen-libquic/external/oxen-encoding oxenc::oxenc)
endif()

# oxen::logging, with matching fmt/spdlog targets.  This can't go through sessiondep_or_submodule
# because oxen-logging's public headers expose fmt types, which a system liboxen-logging's .pc file
# doesn't pull in; load.cmake resolves that for us.  It doesn't know about our submodule/static
# options, though, so translate those for it.
option(DEPS_FORCE_liboxen-logging_SUBMODULE "force using liboxen-logging submodule" OFF)
if(BUILD_STATIC_DEPS OR DEPS_FORCE_SUBMODULE OR DEPS_FORCE_liboxen-logging_SUBMODULE)
    set(OXEN_LOGGING_FORCE_SUBMODULES ON)
endif()
include(oxen-libquic/external/oxen-logging/cmake/load.cmake)

set(LIBQUIC_BUILD_TESTS OFF CACHE BOOL "")
sessiondep_or_submodule(liboxenquic 1.8.0 oxen-libquic oxen::quic)

sessiondep_or_submodule(liboxenmq 1.3.0 oxen-mq oxenmq::oxenmq)

set(JSON_MultipleHeaders ON CACHE BOOL "") # Allows multi-header nlohmann use
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(JSON_Diagnostics ON CACHE BOOL "")
endif()
sessiondep_or_submodule(nlohmann_json 3.11.0 nlohmann_json nlohmann_json::nlohmann_json)

sessiondep_or_submodule(CLI11 2.2.0 CLI11 CLI11::CLI11)


# uSockets doesn't really have a proper build system (just a very simple Makefile) so build it
# ourselves.
file(GLOB usockets_src CONFIGURE_DEPENDS
    uWebSockets/uSockets/src/*.c
    uWebSockets/uSockets/src/eventing/*.c
    uWebSockets/uSockets/src/crypto/*.c
    uWebSockets/uSockets/src/crypto/*.cpp)
file(COPY uWebSockets/uSockets/src/libusockets.h DESTINATION uWebSockets)
add_library(uSockets STATIC EXCLUDE_FROM_ALL ${usockets_src})
target_include_directories(uSockets PRIVATE uWebSockets/uSockets/src)
target_compile_definitions(uSockets PRIVATE LIBUS_USE_OPENSSL)
target_compile_features(uSockets PRIVATE c_std_11 cxx_std_17)
target_link_libraries(uSockets sessiondep::libssl sessiondep::libcrypto)

# The uWebSockets C++ layer is header-only but isn't actually prefixed in the repository itself, but
# rather only on install (which, as above, is just a very simple Makefile).  This is unfortunate
# because it means that we can't use `#include <uWebSockets/App.h>` directly with the repo; so
# instead we emulate the installation process into the build directory and include it (with the
# prefix) from there.
file(COPY uWebSockets/src/ DESTINATION uWebSockets/uWebSockets FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
add_library(uWebSockets INTERFACE)
target_include_directories(uWebSockets SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/uWebSockets)
target_link_libraries(uWebSockets INTERFACE uSockets)
target_compile_definitions(uWebSockets INTERFACE UWS_HTTPRESPONSE_NO_WRITEMARK UWS_NO_ZLIB)


# cpr configuration.  Ideally we'd just do this via add_subdirectory, but cpr's cmake drags in a
# pile of options and its own curl handling, and this is fairly simple to build.
file(GLOB cpr_sources CONFIGURE_DEPENDS cpr/cpr/*.cpp)
file(READ cpr/CMakeLists.txt cpr_cmakelists_txt)
if(NOT cpr_cmakelists_txt MATCHES "project\\(cpr VERSION ([0-9]+)\\.([0-9]+)\\.([0-9]+) LANGUAGES CXX\\)")
    message(FATAL_ERROR "Failed to detect cpr version")
endif()
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include/cpr)
set(cpr_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(cpr_VERSION_MINOR "${CMAKE_MATCH_2}")
set(cpr_VERSION_PATCH "${CMAKE_MATCH_3}")
set(cpr_VERSION "${cpr_VERSION_MAJOR}.${cpr_VERSION_MINOR}.${cpr_VERSION_PATCH}")
set(cpr_VERSION_NUM "(${cpr_VERSION_MAJOR} * 0x10000 + ${cpr_VERSION_MINOR} * 0x100 + ${cpr_VERSION_PATCH})")
configure_file("cpr/cmake/cprver.h.in" "${CMAKE_CURRENT_BINARY_DIR}/include/cpr/cprver.h")

add_library(cpr STATIC EXCLUDE_FROM_ALL ${cpr_sources})
target_link_libraries(cpr PUBLIC sessiondep::libcurl)
target_include_directories(cpr PUBLIC cpr/include "${CMAKE_CURRENT_BINARY_DIR}/include")
target_compile_definitions(cpr PUBLIC CPR_CURL_NOSIGNAL)
add_library(cpr::cpr ALIAS cpr)


option(USE_JEMALLOC "Link to jemalloc for memory allocations, if found" ON)
add_library(jemalloc INTERFACE)
add_library(jemalloc::jemalloc ALIAS jemalloc)
if(USE_JEMALLOC AND NOT BUILD_STATIC_DEPS)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(JEMALLOC jemalloc IMPORTED_TARGET)
  if(JEMALLOC_FOUND)
    target_link_libraries(jemalloc INTERFACE PkgConfig::JEMALLOC)
  endif()
endif()


# We require 3.35.x for some queries we use (such as "RETURNING"), and 3.35.5 for bug fixes.  When
# the system sqlite3 is too old we fall back to sqlite3mc, which is a regular sqlite3 build with
# encryption support bolted on: we don't use the encryption, but everything else works as usual.
# Deliberately not named SQLite3_*: the SQLiteCpp workaround below force-sets SQLite3_FOUND in the
# cache, which would then win over this check on every re-configure.
if(NOT BUILD_STATIC_DEPS)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SYS_SQLITE3 sqlite3>=3.35.5 IMPORTED_TARGET GLOBAL)
endif()

if(SYS_SQLITE3_FOUND)
  add_library(SQLite::SQLite3 ALIAS PkgConfig::SYS_SQLITE3)
else()
  session_dep(sqlite3mc 2)
  # IMPORTED so that SQLiteCpp's install(EXPORT) doesn't demand that we export it too.
  add_library(SQLite::SQLite3 INTERFACE IMPORTED GLOBAL)
  set_target_properties(SQLite::SQLite3 PROPERTIES INTERFACE_LINK_LIBRARIES sessiondep::sqlite3mc)
endif()

# Hack around SQLiteCpp's attempts to locate sqlite3 because we *don't* want to link against the
# system one, but don't download and build the embedded one until build time.  Thankfully it
# actually links against the SQLite::SQLite3 cmake target if it already exists, so all we have to do
# is set that up and circumvent some of the non-target bits of its FindSQLite3.cmake.
set(SQLite3_FOUND TRUE CACHE BOOL "" FORCE)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/ignored")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/ignored/sqlite3.h" "#define SQLITE_VERSION \"${SYS_SQLITE3_VERSION}\"")
set(SQLite3_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/ignored" CACHE STRING "" FORCE)
set(SQLite3_LIBRARY "ignored" CACHE STRING "" FORCE)
set(SQLITECPP_INTERNAL_SQLITE OFF CACHE BOOL "don't build SQLiteCpp's internal sqlite3" FORCE)
set(SQLITE_ENABLE_COLUMN_METADATA OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPLINT OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPCHECK OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_DOXYGEN OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)

add_subdirectory(SQLiteCpp EXCLUDE_FROM_ALL)

file(REMOVE "${CMAKE_CURRENT_BINARY_DIR}/ignored/sqlite3.h")
