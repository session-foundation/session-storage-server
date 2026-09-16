
add_library(http STATIC
    http_client.cpp)

target_link_libraries(http
    PRIVATE
    version
    oxen::logging
    sessiondep::libevent_core
    PUBLIC
    cpr::cpr
    oxen::quic
    )
