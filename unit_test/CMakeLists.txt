
check_submodule(Catch2)

add_subdirectory(Catch2)

add_executable(Test
    main.cpp

    certificates.cpp
    encrypt.cpp
    https_backends.cpp
    monitor.cpp
    onion_requests.cpp
    rate_limiter.cpp
    serialization.cpp
    service_node.cpp
    storage.cpp
    swarm.cpp
)

target_link_libraries(Test
    PRIVATE
    common storage utils crypto snode rpc server
    cpr::cpr  # https_backends.cpp is an HTTPS client of the server under test
    SQLiteCpp  # storage.cpp recreates old table layouts directly
    Catch2::Catch2)

# certificates.cpp drives each backend's TLS setup directly; https_backends.cpp also speaks raw TLS
# to the libmicrohttpd backend through gnutls.
if(HTTPS_BACKEND_UWEBSOCKETS)
    target_link_libraries(Test PRIVATE uWebSockets)
endif()
if(HTTPS_BACKEND_MICROHTTPD)
    target_link_libraries(Test PRIVATE sessiondep::libmicrohttpd sessiondep::gnutls)
endif()

target_include_directories(Test PRIVATE ..)

add_executable(migrate_test migrate_test.cpp)
target_link_libraries(migrate_test PRIVATE common storage utils crypto snode rpc server)
target_include_directories(migrate_test PRIVATE ..)
