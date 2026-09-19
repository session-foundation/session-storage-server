
add_library(crypto STATIC
    keys.cpp
    channel_encryption.cpp
    subaccount.cpp
)

find_package(Threads)

target_link_libraries(crypto
    PRIVATE
    common
    logging
    sessiondep::gnutls
    sessiondep::libsodium)
