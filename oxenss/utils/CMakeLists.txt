add_library(utils STATIC
    random.cpp
    string_utils.cpp
)

target_link_libraries(utils PUBLIC oxenc::oxenc PRIVATE oxen::logging)
