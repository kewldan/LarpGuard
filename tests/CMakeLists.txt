add_executable(bot_shield_tests
  cert_store_test.cc
  classifier_test.cc
  client_hello_test.cc
  config_test.cc
  events_test.cc
  host_test.cc
  http_tap_test.cc
  ja4_test.cc
  nats_publisher_test.cc
  prefixed_stream_test.cc
  proxy_protocol_test.cc
  proxy_test.cc
  ratelimit_test.cc
  rules_test.cc
  scoring_test.cc
  tcp_syn_test.cc
  test_util.cc
)
target_compile_options(bot_shield_tests PRIVATE -Wall -Wextra)
target_compile_definitions(bot_shield_tests PRIVATE
  BOT_SHIELD_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
target_link_libraries(bot_shield_tests PRIVATE
  bot_shield_core
  nlohmann_json::nlohmann_json
  nghttp2
  GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(bot_shield_tests)

bot_shield_enable_tidy(bot_shield_tests)

# Fake Traefik (HTTP/2 over TLS) for tests/e2e/run_e2e.py.
add_executable(bot_shield_fake_upstream e2e/fake_upstream.cc)
target_link_libraries(bot_shield_fake_upstream PRIVATE
  ssl crypto nghttp2 nlohmann_json::nlohmann_json Threads::Threads)
