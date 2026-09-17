
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
    uWebSockets
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
