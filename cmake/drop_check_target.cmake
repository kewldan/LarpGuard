# PATCH_COMMAND for ngtcp2 and nghttp3: they define an unconditional
# "check" target, which nghttp2 already has (CMP0002 forbids duplicates).
# Runs in the dependency's source directory.
file(READ CMakeLists.txt contents)
string(REPLACE "add_custom_target(check COMMAND \${CMAKE_CTEST_COMMAND})" ""
       contents "${contents}")
file(WRITE CMakeLists.txt "${contents}")
