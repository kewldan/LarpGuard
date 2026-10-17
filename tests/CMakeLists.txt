add_executable(bot_shield_tests
  cert_store_test.cc
  classifier_test.cc
  client_hello_test.cc
  config_test.cc
  host_test.cc
  prefixed_stream_test.cc
  proxy_protocol_test.cc
  test_util.cc
)
target_compile_options(bot_shield_tests PRIVATE -Wall -Wextra)
target_link_libraries(bot_shield_tests PRIVATE
  bot_shield_core
  nlohmann_json::nlohmann_json
  GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(bot_shield_tests)

bot_shield_enable_tidy(bot_shield_tests)
