set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

cmake_minimum_required(VERSION 3.18)

project(oxenss
    VERSION 2.11.3
    LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

cmake_policy(SET CMP0069 NEW) # Do LTO properly
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
option(USE_LTO "Use Link-Time Optimization" ON)
if(USE_LTO AND NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT IPO_ENABLED OUTPUT ipo_error)
  if(IPO_ENABLED)
    message(STATUS "LTO enabled")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  else()
    message(WARNING "LTO not supported by compiler: ${ipo_error}")
  endif()
else()
  message(STATUS "LTO disabled")
  set(IPO_ENABLED OFF)
endif()

option(BUILD_TESTS "build storage server unit tests" OFF)

# session-deps has its own LTO switch for static dependency builds that defaults ON regardless of
# ours; leaving the two to disagree breaks the link, because an LTO'd static archive can't be
# consumed by a non-LTO link (clang emits pure bitcode archives, which either fail to load or get
# silently dropped).  Seed it from what we actually settled on above so USE_LTO is the only knob.
set(SESSIONDEPS_LTO ${IPO_ENABLED} CACHE BOOL "Use LTO for static dependency builds, where supported" FORCE)

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

include(cmake/session-deps/Deps.cmake)

check_submodule(cmake/session-deps)

include(cmake/check_atomic.cmake)
link_libatomic()

include(cmake/check_for_std_filesystem.cmake)

add_subdirectory(external)

add_subdirectory(oxenss)

if (BUILD_TESTS)
    add_subdirectory(unit_test)
endif ()

add_executable(onion-request EXCLUDE_FROM_ALL contrib/onion-request.cpp)
set_target_properties(onion-request PROPERTIES RUNTIME_OUTPUT_DIRECTORY contrib)
target_link_libraries(onion-request common crypto cpr::cpr oxenmq::oxenmq oxen::quic)
target_include_directories(onion-request PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(quic-reach-test EXCLUDE_FROM_ALL contrib/quic-reach-test.cpp)
set_target_properties(quic-reach-test PROPERTIES RUNTIME_OUTPUT_DIRECTORY contrib)
target_link_libraries(quic-reach-test oxen::quic sessiondep::libsodium fmt::fmt)

include(cmake/archive.cmake)
