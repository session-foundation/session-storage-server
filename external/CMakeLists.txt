
message(STATUS "Checking submodules")
check_submodule(CLI11)
check_submodule(cpr)
check_submodule(nlohmann_json)
check_submodule(oxen-libquic)
check_submodule(oxen-mq)
check_submodule(session-sqlite)
if(HTTPS_BACKEND_UWEBSOCKETS)
    check_submodule(uWebSockets)
endif()


session_dep(libsodium 1.0.18)
session_dep(libzmq 4.3)
if(HTTPS_BACKEND_UWEBSOCKETS)
    # Only uSockets wants OpenSSL; everything else TLS-related here is gnutls.  A static build gets
    # session-deps' OpenSSL, whose archives have everything but the public API hidden so that its
    # copy of the CRYPTOGAMS assembly cannot collide with gnutls's (see deps/libssl.cmake there).
    session_dep(libssl 3 WITH libcrypto)
endif()
session_dep(libcurl 7.68)

# Already pulled in by liboxenquic and the gnutls flavour of libcurl; declared here because we use
# it directly for certificate generation.
session_dep(gnutls 3.6)

# Always built from session-deps rather than taken from the system: every release through 1.0.10
# busy-waits for the whole of each TLS handshake in epoll mode, and session-deps carries the patch
# for it (see deps/libmicrohttpd.cmake there).  The version is a security floor, not an API one:
# 1.0.7/1.0.8 fixed crashes and out-of-bounds writes in the request parser that anyone able to
# reach the HTTPS port can trigger.
if(HTTPS_BACKEND_MICROHTTPD)
    set(BUILD_STATIC_libmicrohttpd ON)
    session_dep(libmicrohttpd 1.0.8)
endif()

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
sessiondep_or_submodule(liboxenquic 1.9.0 oxen-libquic oxen::quic)

sessiondep_or_submodule(liboxenmq 1.3.0 oxen-mq oxenmq::oxenmq)

set(JSON_MultipleHeaders ON CACHE BOOL "") # Allows multi-header nlohmann use
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(JSON_Diagnostics ON CACHE BOOL "")
endif()
sessiondep_or_submodule(nlohmann_json 3.11.0 nlohmann_json nlohmann_json::nlohmann_json)

sessiondep_or_submodule(CLI11 2.2.0 CLI11 CLI11::CLI11)


if(HTTPS_BACKEND_UWEBSOCKETS)
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
endif()


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


# 3.37 is required for STRICT tables (state_kv); RETURNING, which we also use, arrived in 3.35.
# Anything older falls back to a static sqlite3mc, which is a regular sqlite3 with encryption bolted
# on that we simply don't use.
session_dep(sqlite3 3.37.0)

# session-sqlite would build its own sqlite3mc given the chance; hand it ours instead so that a
# system sqlite3 gets used where there is a new enough one.  SESSION_EXTERNAL_SQLITE_MC stays off
# deliberately: it only enables session-sqlite's encryption support, which we don't use, and it
# would not be true when the system sqlite3 was picked.
set(SESSION_SQLITE_BUILD_SQLITE3MC OFF CACHE BOOL "" FORCE)
add_library(SQLite::SQLite3 INTERFACE IMPORTED GLOBAL)
set_target_properties(SQLite::SQLite3 PROPERTIES INTERFACE_LINK_LIBRARIES sessiondep::sqlite3)

add_subdirectory(session-sqlite EXCLUDE_FROM_ALL)
