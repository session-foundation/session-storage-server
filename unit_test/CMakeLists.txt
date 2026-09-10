
add_subdirectory(Catch2)

add_executable(Test
    main.cpp

    encrypt.cpp
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
    Catch2::Catch2)

target_include_directories(Test PRIVATE ..)

add_executable(migrate_test migrate_test.cpp)
target_link_libraries(migrate_test PRIVATE common storage utils crypto snode rpc server)
target_include_directories(migrate_test PRIVATE ..)
