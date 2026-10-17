#ifndef BOT_SHIELD_EVENTS_EVENT_SINK_H_
#define BOT_SHIELD_EVENTS_EVENT_SINK_H_

#include <string>
#include <string_view>

namespace bot_shield {

// Destination for analytics events (connection and request records).
class EventSink {
 public:
  virtual ~EventSink() = default;

  // `kind` is "conn" or "req"; `payload` is one JSON object. Thread-safe and
  // non-blocking: an overloaded sink drops events rather than slowing down
  // the proxy.
  virtual void Publish(std::string_view kind, std::string payload) = 0;
};

}  // namespace bot_shield

#endif  // BOT_SHIELD_EVENTS_EVENT_SINK_H_
