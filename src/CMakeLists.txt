add_library(bot_shield_core STATIC
  common/host.cc
  common/log.cc
  common/metrics.cc
  config/config.cc
  net/classifier.cc
  net/proxy_protocol.cc
  net/socket_options.cc
  net/watchdog.cc
  server/connection.cc
  server/gateway.cc
  server/metrics_server.cc
  tls/acme_watcher.cc
  tls/cert_store.cc
  tls/client_hello.cc
)

target_include_directories(bot_shield_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(bot_shield_core PRIVATE -Wall -Wextra)
target_link_libraries(bot_shield_core
  PUBLIC
    asio
    ssl
    crypto
    Threads::Threads
  PRIVATE
    nlohmann_json::nlohmann_json
    yaml-cpp::yaml-cpp
)

add_executable(bot-shield main.cc)
target_compile_options(bot-shield PRIVATE -Wall -Wextra)
target_link_libraries(bot-shield PRIVATE bot_shield_core)
