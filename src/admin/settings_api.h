#ifndef BOT_SHIELD_ADMIN_SETTINGS_API_H_
#define BOT_SHIELD_ADMIN_SETTINGS_API_H_

#include <cstdint>
#include <string_view>

#include "admin/server.h"

namespace bot_shield {

// /settings endpoints of the admin API (ADR-018); `rest` is the path after
// "/settings". Secrets never leave here: only whether they are set.
//   GET  /settings            every key: value, default, source, class
//   POST /settings/validate   a change, checked, with its diff
//   POST /settings            the same, written and applied
//   GET  /settings/history    earlier layers
//   POST /settings/rollback   {"revision": "..."}
AdminResponse HandleSettingsRequest(std::string_view method,
                                    std::string_view rest,
                                    std::string_view body,
                                    const AdminContext& context,
                                    int64_t now_ms);

}  // namespace bot_shield

#endif  // BOT_SHIELD_ADMIN_SETTINGS_API_H_
