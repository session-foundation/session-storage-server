
add_library(logging STATIC
    oxen_logger.cpp
)

# oxenc is header-only; this is for the include path, which oxen_logger.cpp needs via
# utils/string_utils.hpp.  Every other target gets it transitively from `common`, which `logging`
# (being below it) does not link.
target_link_libraries(logging PUBLIC oxen::logging oxenc::oxenc)
