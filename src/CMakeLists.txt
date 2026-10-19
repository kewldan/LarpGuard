add_library(bot_shield_core STATIC
  action/actions.cc
  behavior/behavior.cc
  challenge/captcha.cc
  challenge/challenger.cc
  challenge/puzzle.cc
  challenge/scripts.cc
  challenge/token.cc
  admin/attack.cc
  admin/decision_log.cc
  admin/lists.cc
  admin/modes.cc
  admin/server.cc
  common/compress.cc
  common/hash.cc
  common/refresher.cc
  common/structured_fields.cc
  common/host.cc
  common/log.cc
  common/metrics.cc
  common/network.cc
  common/systemd.cc
  common/url.cc
  config/config.cc
  crawler/crawlers.cc
  crawler/ranges.cc
  crawler/verifier.cc
  crawler/web_bot_auth.cc
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
  model/features.cc
  model/gbdt.cc
  net/classifier.cc
  net/asn.cc
  net/http_client.cc
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
  quic/h3_server.cc
  ratelimit/gcra.cc
  ratelimit/limits.cc
  ratelimit/store.cc
  score/policy.cc
  score/rules.cc
  score/scorer.cc
  server/connection.cc
  server/gateway.cc
  server/health.cc
  server/verdicts.cc
  server/metrics_server.cc
  tls/acme_watcher.cc
  tls/cert_store.cc
  tls/client_hello.cc
  watchdog/fail_open.cc
  xdp/xdp_filter.cc
)

target_include_directories(bot_shield_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(bot_shield_core PRIVATE -Wall -Wextra)
target_link_libraries(bot_shield_core
  PUBLIC
    asio
    nlohmann_json::nlohmann_json
    llhttp::llhttp
    nghttp2
    ngtcp2_crypto_boringssl_static
    ngtcp2_static
    nghttp3_static
    ssl
    crypto
    Threads::Threads
  PRIVATE
    ZLIB::ZLIBSTATIC
    yaml-cpp::yaml-cpp
)

# XDP pre-filter: src/xdp/filter.bpf.c compiled for BPF with clang and
# embedded (tools/bpf_embed.py). Linux only; without clang the gateway
# builds without it (xdp.enabled then reports an error).
option(BOT_SHIELD_XDP "Build the XDP pre-filter (Linux, clang)" ON)
set(BOT_SHIELD_XDP_BUILT 0)
if(BOT_SHIELD_XDP AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_program(BOT_SHIELD_BPF_CLANG NAMES clang clang-21 clang-20 clang-19
    clang-18 clang-17 clang-16)
  find_package(Python3 COMPONENTS Interpreter)
  if(BOT_SHIELD_BPF_CLANG AND Python3_Interpreter_FOUND)
    set(_xdp_object ${CMAKE_CURRENT_BINARY_DIR}/filter.bpf.o)
    set(_xdp_source ${CMAKE_CURRENT_BINARY_DIR}/xdp_program.cc)
    add_custom_command(
      OUTPUT ${_xdp_source}
      COMMAND ${BOT_SHIELD_BPF_CLANG} -O2 -g0 -target bpfel -c
              ${CMAKE_CURRENT_SOURCE_DIR}/xdp/filter.bpf.c -o ${_xdp_object}
      COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/bpf_embed.py
              ${_xdp_object} ${_xdp_source}
      DEPENDS xdp/filter.bpf.c ${PROJECT_SOURCE_DIR}/tools/bpf_embed.py
      COMMENT "Building the XDP program"
      VERBATIM)
    target_sources(bot_shield_core PRIVATE ${_xdp_source})
    set(BOT_SHIELD_XDP_BUILT 1)
  else()
    message(WARNING "XDP pre-filter off: needs clang (BPF target) and python3")
  endif()
endif()
target_compile_definitions(bot_shield_core PUBLIC
  BOT_SHIELD_XDP=${BOT_SHIELD_XDP_BUILT})

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
