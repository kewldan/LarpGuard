cmake_minimum_required(VERSION 3.28)

project(bot_shield VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(BOT_SHIELD_BUILD_TESTS "Build unit tests" ON)
option(BOT_SHIELD_SANITIZE "Build with AddressSanitizer and UBSan" OFF)
option(BOT_SHIELD_FOXIO
  "Build JA4T/JA4H (FoxIO License 1.1, see src/fp/foxio/LICENSE.md)" ON)

if(BOT_SHIELD_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# GCC flags asio's coroutine frame allocator (operator new/delete pair it
# cannot match across the frame) as -Wmismatched-new-delete: a known false
# positive.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wno-mismatched-new-delete>)
endif()

include(cmake/dependencies.cmake)
include(cmake/tooling.cmake)

add_subdirectory(src)

if(BOT_SHIELD_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
