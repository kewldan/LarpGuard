add_library(bot_shield_core STATIC
  common/hash.cc
  common/host.cc
  common/log.cc
  common/metrics.cc
  config/config.cc
  events/events.cc
  events/nats_publisher.cc
  fp/h1_tap.cc
  fp/h2_fingerprint.cc
  fp/h2_tap.cc
  fp/http_fingerprint.cc
  fp/http_request.cc
  fp/ja4.cc
  fp/tcp_syn.cc
  net/classifier.cc
  net/proxy_protocol.cc
  net/socket_options.cc
  net/watchdog.cc
  proxy/exchange.cc
  proxy/h1_server.cc
  proxy/h2_connection.cc
  proxy/h2_server.cc
  proxy/h2_upstream.cc
  proxy/http_message.cc
  proxy/upstream_pool.cc
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
    llhttp::llhttp
    nghttp2
    ssl
    crypto
    Threads::Threads
  PRIVATE
    nlohmann_json::nlohmann_json
    yaml-cpp::yaml-cpp
)

# JA4+ methods under the FoxIO License 1.1 (src/fp/foxio/LICENSE.md).
if(BOT_SHIELD_FOXIO)
  target_sources(bot_shield_core PRIVATE fp/foxio/ja4plus.cc)
  target_compile_definitions(bot_shield_core PUBLIC BOT_SHIELD_FOXIO=1)
else()
  target_compile_definitions(bot_shield_core PUBLIC BOT_SHIELD_FOXIO=0)
endif()

add_executable(bot-shield main.cc)
target_compile_options(bot-shield PRIVATE -Wall -Wextra)
target_link_libraries(bot-shield PRIVATE bot_shield_core)

bot_shield_enable_tidy(bot_shield_core)
bot_shield_enable_tidy(bot-shield)
