# Code quality tooling: clang-format and clang-tidy targets.
#
#   cmake --build build --target format        # reformat sources in place
#   cmake --build build --target format-check  # fail on unformatted sources
#   cmake --build build --target tidy          # clang-tidy over all sources
#
# -DBOT_SHIELD_CLANG_TIDY=ON additionally runs clang-tidy while compiling our
# own targets (slower builds, diagnostics inline with compiler warnings).

option(BOT_SHIELD_CLANG_TIDY "Run clang-tidy while compiling" OFF)

set(_bot_shield_llvm_hints
  /opt/homebrew/opt/llvm/bin
  /usr/local/opt/llvm/bin)
find_program(CLANG_FORMAT_EXE NAMES clang-format HINTS ${_bot_shield_llvm_hints})
find_program(CLANG_TIDY_EXE NAMES clang-tidy HINTS ${_bot_shield_llvm_hints})
find_program(RUN_CLANG_TIDY_EXE NAMES run-clang-tidy run-clang-tidy.py
  HINTS ${_bot_shield_llvm_hints})

file(GLOB_RECURSE BOT_SHIELD_FORMAT_SOURCES CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/src/*.cc
  ${PROJECT_SOURCE_DIR}/src/*.h
  ${PROJECT_SOURCE_DIR}/tests/*.cc
  ${PROJECT_SOURCE_DIR}/tests/*.h)

if(CLANG_FORMAT_EXE)
  add_custom_target(format
    COMMAND ${CLANG_FORMAT_EXE} -i ${BOT_SHIELD_FORMAT_SOURCES}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "clang-format: reformatting sources"
    VERBATIM)
  add_custom_target(format-check
    COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror ${BOT_SHIELD_FORMAT_SOURCES}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "clang-format: checking sources"
    VERBATIM)
endif()

if(RUN_CLANG_TIDY_EXE)
  add_custom_target(tidy
    COMMAND ${RUN_CLANG_TIDY_EXE} -quiet -p ${PROJECT_BINARY_DIR}
            -clang-tidy-binary ${CLANG_TIDY_EXE}
            "${PROJECT_SOURCE_DIR}/(src|tests)/.*\\.cc$"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "clang-tidy: analyzing sources"
    VERBATIM)
endif()

# Enables clang-tidy during compilation of `target` when requested.
function(bot_shield_enable_tidy target)
  if(BOT_SHIELD_CLANG_TIDY)
    if(NOT CLANG_TIDY_EXE)
      message(FATAL_ERROR "BOT_SHIELD_CLANG_TIDY=ON but clang-tidy not found")
    endif()
    set_target_properties(${target} PROPERTIES CXX_CLANG_TIDY ${CLANG_TIDY_EXE})
  endif()
endfunction()
