# Third-party dependencies. Everything is fetched and pinned so that macOS
# development builds and the Linux container build use identical versions.

include(FetchContent)

set(FETCHCONTENT_QUIET ON)
find_package(Threads REQUIRED)

# BoringSSL: TLS for both the client-facing side and the Traefik upstream.
FetchContent_Declare(boringssl
  URL https://github.com/google/boringssl/archive/refs/tags/0.20260903.0.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  EXCLUDE_FROM_ALL
  SYSTEM)

# Standalone Asio (header-only, no CMake project of its own).
FetchContent_Declare(asio
  URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-38-1.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SOURCE_SUBDIR do-not-add-subdirectory)

FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  EXCLUDE_FROM_ALL
  SYSTEM)

set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(YAML_CPP_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(yaml-cpp
  URL https://github.com/jbeder/yaml-cpp/archive/refs/tags/yaml-cpp-0.9.0.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  EXCLUDE_FROM_ALL
  SYSTEM)

# llhttp: passive HTTP/1.x request parsing for fingerprints.
set(LLHTTP_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(LLHTTP_BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
FetchContent_Declare(llhttp
  URL https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.4.2.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  EXCLUDE_FROM_ALL
  SYSTEM)

# nghttp2: only its HPACK decoder, to read HTTP/2 request headers.
set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(nghttp2
  URL https://github.com/nghttp2/nghttp2/releases/download/v1.69.0/nghttp2-1.69.0.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  EXCLUDE_FROM_ALL
  SYSTEM)

# zlib: gunzip of downloaded data (ASN database) and PNG images (CAPTCHA).
set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZLIB_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(zlib
  URL https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  EXCLUDE_FROM_ALL
  SYSTEM)

FetchContent_MakeAvailable(boringssl asio nlohmann_json yaml-cpp llhttp nghttp2
                           zlib)

# QUIC (ngtcp2 with its BoringSSL crypto backend) and HTTP/3 (nghttp3) for
# the HTTP/3 listener. Declared after BoringSSL, whose include directory and
# targets they build against.
set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ENABLE_OPENSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_BORINGSSL ON CACHE BOOL "" FORCE)
set(BORINGSSL_INCLUDE_DIR "${boringssl_SOURCE_DIR}/include" CACHE PATH "" FORCE)
set(BORINGSSL_LIBRARIES "ssl;crypto" CACHE STRING "" FORCE)
# ngtcp2 checks for BoringSSL by linking a test program at configure time,
# before the fetched BoringSSL is built; it is known to be BoringSSL.
set(HAVE_BORINGSSL TRUE CACHE INTERNAL "")
FetchContent_Declare(ngtcp2
  URL https://github.com/ngtcp2/ngtcp2/releases/download/v1.25.0/ngtcp2-1.25.0.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  PATCH_COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_LIST_DIR}/drop_check_target.cmake
  EXCLUDE_FROM_ALL
  SYSTEM)
FetchContent_Declare(nghttp3
  URL https://github.com/ngtcp2/nghttp3/releases/download/v1.18.0/nghttp3-1.18.0.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  PATCH_COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_LIST_DIR}/drop_check_target.cmake
  EXCLUDE_FROM_ALL
  SYSTEM)
FetchContent_MakeAvailable(ngtcp2 nghttp3)
target_include_directories(nghttp3_static SYSTEM INTERFACE
  $<BUILD_INTERFACE:${nghttp3_SOURCE_DIR}/lib/includes>
  $<BUILD_INTERFACE:${nghttp3_BINARY_DIR}/lib/includes>)
target_include_directories(ngtcp2_crypto_boringssl_static SYSTEM INTERFACE
  $<BUILD_INTERFACE:${ngtcp2_SOURCE_DIR}/crypto/includes>)
target_link_libraries(ngtcp2_crypto_boringssl_static INTERFACE
  ngtcp2_static ssl crypto)

add_library(asio INTERFACE)
target_include_directories(asio SYSTEM INTERFACE ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
target_link_libraries(asio INTERFACE Threads::Threads)

if(BOT_SHIELD_BUILD_TESTS)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    EXCLUDE_FROM_ALL
    SYSTEM)
  FetchContent_MakeAvailable(googletest)
endif()
