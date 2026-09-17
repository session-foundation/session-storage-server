
add_library(server STATIC
    https.cpp
    mqbase.cpp
    omq.cpp
    quic.cpp
    server_certificates.cpp
    utils.cpp)

find_package(Threads)

target_link_libraries(server
    PUBLIC
    oxen::quic    # public so it gets to /daemon
    PRIVATE
    common
    utils
    rpc
    snode
    logging
    sessiondep::gnutls
    oxenmq::oxenmq
    sessiondep::libsodium
    Threads::Threads)

# The OXENSS_HTTPS_* definitions are public so that anything (e.g. tests) can tell which backends
# were built in.
if(HTTPS_BACKEND_UWEBSOCKETS)
    target_sources(server PRIVATE https_uws.cpp)
    target_link_libraries(server PRIVATE uWebSockets)
    target_compile_definitions(server PUBLIC OXENSS_HTTPS_UWEBSOCKETS)
endif()
