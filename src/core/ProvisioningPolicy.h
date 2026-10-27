#pragma once

#include <string_view>

#include "core/api/JsonReader.h"

namespace awtrix::provisioning {

enum class Verdict { Allow, Redirect, Refuse };

inline constexpr const char* kRefusal = "setup only";

struct Request {
  std::string_view method;
  std::string_view path;
  std::string_view body;
  bool hostValid = false;
  bool originValid = false;
  bool secrets = false;
  bool methodValid = true;
};

inline bool matchesAuthority(std::string_view supplied, std::string_view expected,
                             bool defaultPort) {
  return supplied == expected ||
      (defaultPort && supplied.size() == expected.size() + 3 &&
       supplied.substr(0, expected.size()) == expected && supplied.substr(expected.size()) == ":80");
}

enum class FieldType { String, Bool, Integer };

struct SetupField {
  const char* name;
  FieldType type;
};

// Wi-Fi plus the MQTT connection, so a new clock reaches its broker after the one reboot setup
// needs anyway. Everything else waits for the regular web UI.
inline constexpr SetupField kSetupFields[] = {
    {"wifiSsid", FieldType::String},    {"wifiPass", FieldType::String},
    {"hostname", FieldType::String},    {"mqttEnabled", FieldType::Bool},
    {"mqttHost", FieldType::String},    {"mqttPort", FieldType::Integer},
    {"mqttUser", FieldType::String},    {"mqttPass", FieldType::String},
    {"mqttPrefix", FieldType::String},  {"haDiscovery", FieldType::Bool},
    {"mqttTls", FieldType::Bool},       {"mqttTlsPin", FieldType::String},
};

inline bool setupBody(std::string_view body) {
  // The header guard runs before streaming requests have a body; the route guard runs again after.
  if (body.empty()) return true;
  if (body.size() > 2048) return false;
  api::JsonReader json(body);
  if (!json.enterObject()) return false;
  unsigned seen = 0;
  while (json.nextMember()) {
    unsigned field = 0;
    FieldType type = FieldType::String;
    for (unsigned i = 0; i < sizeof(kSetupFields) / sizeof(kSetupFields[0]); ++i)
      if (json.keyEquals(kSetupFields[i].name)) { field = 1u << i; type = kSetupFields[i].type; break; }
    if (!field || (seen & field)) return false;
    const bool typed = type == FieldType::String ? json.isString() :
                       type == FieldType::Bool ? json.isBool() : json.isInteger();
    if (!typed) return false;
    seen |= field;
    if (!json.skipValue()) return false;
  }
  return json.ok() && json.atEnd() && seen;
}

inline Verdict admit(const Request& request) {
  if (!request.hostValid)
    return request.method == "GET" || request.method == "HEAD" ? Verdict::Redirect : Verdict::Refuse;
  if (!request.originValid || request.secrets || !request.methodValid) return Verdict::Refuse;
  if (request.method == "GET") {
    const auto path = request.path;
    if (path == "/" || path == "/index.html" || path == "/api/v1/device" ||
        path == "/api/v1/capabilities" || path == "/api/v1/system" ||
        path == "/api/v1/system/wifi-scan" || path == "/api/v1/mqtt/tls") return Verdict::Allow;
    if (path.substr(0, 5) != "/api/" && path.find('.', 1) == path.npos) return Verdict::Redirect;
    return Verdict::Refuse;
  }
  if (request.method == "PUT" && request.path == "/api/v1/system" && setupBody(request.body))
    return Verdict::Allow;
  // The broker CA, so a broker with its own certificate is trusted on the first connection.
  if ((request.method == "PUT" || request.method == "DELETE") && request.path == "/api/v1/mqtt/tls/ca")
    return Verdict::Allow;
  if (request.method == "POST" &&
      (request.path == "/api/v1/device/reboot" || request.path == "/api/v1/restore"))
    return Verdict::Allow;
  return Verdict::Refuse;
}

}
