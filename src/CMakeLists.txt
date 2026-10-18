add_library(bot_shield_core STATIC
  challenge/challenger.cc
  challenge/token.cc
  admin/attack.cc
  admin/decision_log.cc
  admin/lists.cc
  admin/server.cc
  common/hash.cc
  common/host.cc
  common/log.cc
  common/metrics.cc
  common/network.cc
  common/systemd.cc
  common/url.cc
  config/config.cc
  crawler/crawlers.cc
  crawler/verifier.cc
  docker/client.cc
  docker/labels.cc
  docker/watcher.cc
  events/events.cc
  events/nats_publisher.cc
  fp/h1_tap.cc
  fp/h2_fingerprint.cc
  fp/h2_tap.cc
  fp/http_fingerprint.cc
  fp/library.cc
  fp/user_agent.cc
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
  ratelimit/gcra.cc
  ratelimit/limits.cc
  ratelimit/store.cc
  score/policy.cc
  score/rules.cc
  score/scorer.cc
  server/connection.cc
  server/gateway.cc
  server/health.cc
  server/metrics_server.cc
  tls/acme_watcher.cc
  tls/cert_store.cc
  tls/client_hello.cc
  watchdog/fail_open.cc
)

target_include_directories(bot_shield_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(bot_shield_core PRIVATE -Wall -Wextra)
target_link_libraries(bot_shield_core
  PUBLIC
    asio
    nlohmann_json::nlohmann_json
    llhttp::llhttp
    nghttp2
    ssl
    crypto
    Threads::Threads
  PRIVATE
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

add_executable(bot-shield-watchdog watchdog/watchdog_main.cc)
target_compile_options(bot-shield-watchdog PRIVATE -Wall -Wextra)
target_link_libraries(bot-shield-watchdog PRIVATE bot_shield_core)
bot_shield_enable_tidy(bot-shield-watchdog)
