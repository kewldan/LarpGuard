#include "crawler/web_bot_auth.h"

#include <openssl/base64.h>
#include <openssl/curve25519.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/structured_fields.h"
#include "fp/http_request.h"
#include "net/http_client.h"

namespace bot_shield {
namespace {

constexpr std::string_view kWellKnown =
    "/.well-known/http-message-signatures-directory";

std::string Base64Url(const uint8_t* data, std::size_t size) {
  std::size_t encoded_size = 0;
  EVP_EncodedLength(&encoded_size, size);
  std::string out(encoded_size, '\0');
  out.resize(
      EVP_EncodeBlock(reinterpret_cast<uint8_t*>(out.data()), data, size));
  for (char& c : out) {
    if (c == '+') c = '-';
    if (c == '/') c = '_';
  }
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

bool Base64UrlDecodeTo(std::string_view text, std::string* out) {
  std::string standard(text);
  for (char& c : standard) {
    if (c == '-') c = '+';
    if (c == '_') c = '/';
  }
  while (standard.size() % 4 != 0) standard.push_back('=');
  std::size_t max_size = 0;
  if (!EVP_DecodedLength(&max_size, standard.size())) return false;
  out->resize(max_size);
  std::size_t size = 0;
  if (!EVP_DecodeBase64(
          reinterpret_cast<uint8_t*>(out->data()), &size, max_size,
          reinterpret_cast<const uint8_t*>(standard.data()), standard.size())) {
    return false;
  }
  out->resize(size);
  return true;
}

// All lines of a header joined with ", " (RFC 9421 2.1).
std::string Combined(const HttpRequest& request, std::string_view name) {
  std::string out;
  for (const auto& [key, value] : request.headers) {
    if (key != name) continue;
    std::string_view trimmed = value;
    while (!trimmed.empty() &&
           (trimmed.front() == ' ' || trimmed.front() == '\t')) {
      trimmed.remove_prefix(1);
    }
    while (!trimmed.empty() &&
           (trimmed.back() == ' ' || trimmed.back() == '\t')) {
      trimmed.remove_suffix(1);
    }
    if (!out.empty()) out += ", ";
    out += trimmed;
  }
  return out;
}

std::string Lower(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

// RFC 9421 2.2.3: lowercase host, default port removed.
std::string Authority(std::string_view authority) {
  std::string out = Lower(authority);
  if (out.ends_with(":443")) out.resize(out.size() - 4);
  return out;
}

const sf::BareItem* StringParam(const sf::Parameters& params,
                                std::string_view key) {
  for (const auto& [name, value] : params) {
    if (name == key) {
      return value.type == sf::BareItem::Type::kString ? &value : nullptr;
    }
  }
  return nullptr;
}

std::optional<int64_t> IntegerParam(const sf::InnerList& list,
                                    std::string_view key) {
  const sf::BareItem* value = list.Param(key);
  if (value == nullptr || value->type != sf::BareItem::Type::kInteger) {
    return std::nullopt;
  }
  return value->integer;
}

enum class Outcome { kOk, kSkip, kInvalid };

struct AgentMember {
  std::string url;
  std::string type = "directory";
};

// Fills `signature` for one Signature-Input member.
Outcome BuildSignature(const HttpRequest& request, const std::string& label,
                       const sf::InnerList& input,
                       const sf::Dictionary* signatures, int64_t now,
                       const WebBotAuthLimits& limits,
                       WebBotAuthSignature* signature) {
  const sf::BareItem* tag = input.Param("tag");
  if (tag == nullptr || tag->type != sf::BareItem::Type::kString ||
      tag->text != "web-bot-auth") {
    return Outcome::kSkip;  // Someone else's signature.
  }
  if (const sf::BareItem* alg = input.Param("alg");
      alg != nullptr &&
      (alg->type != sf::BareItem::Type::kString || alg->text != "ed25519")) {
    return Outcome::kSkip;  // Only Ed25519 is supported.
  }
  const sf::BareItem* keyid = input.Param("keyid");
  const std::optional<int64_t> created = IntegerParam(input, "created");
  const std::optional<int64_t> expires = IntegerParam(input, "expires");
  const sf::Member* value =
      signatures != nullptr ? sf::Find(*signatures, label) : nullptr;
  if (keyid == nullptr || keyid->type != sf::BareItem::Type::kString ||
      !created || !expires || value == nullptr || value->is_inner_list ||
      value->item.value.type != sf::BareItem::Type::kBytes) {
    return Outcome::kInvalid;
  }
  if (*created > now + limits.clock_skew_seconds ||
      *expires + limits.clock_skew_seconds < now || *expires < *created ||
      *expires - *created > limits.max_validity_seconds) {
    return Outcome::kInvalid;
  }

  const std::string_view target = request.target;
  const std::size_t question = target.find('?');
  std::string base;
  bool covers_authority = false;
  std::optional<AgentMember> agent;
  for (const sf::Item& component : input.items) {
    if (component.value.type != sf::BareItem::Type::kString) {
      return Outcome::kInvalid;
    }
    const std::string& name = component.value.text;
    std::string component_value;
    if (name.starts_with('@')) {
      if (!component.params.empty()) return Outcome::kSkip;
      if (name == "@authority") {
        component_value = Authority(request.authority);
        covers_authority = true;
      } else if (name == "@target-uri") {
        component_value =
            std::format("https://{}{}", Authority(request.authority), target);
        covers_authority = true;
      } else if (name == "@method") {
        component_value = request.method;
      } else if (name == "@path") {
        component_value = std::string(target.substr(0, question));
        if (component_value.empty()) component_value = "/";
      } else if (name == "@query") {
        component_value = question == std::string_view::npos
                              ? "?"
                              : std::string(target.substr(question));
      } else if (name == "@scheme") {
        component_value = "https";
      } else if (name == "@request-target") {
        component_value = std::string(target);
      } else {
        return Outcome::kSkip;
      }
    } else {
      if (name != Lower(name)) return Outcome::kInvalid;
      const std::string field = Combined(request, name);
      if (field.empty() && !request.HasHeader(name)) return Outcome::kInvalid;
      const sf::BareItem* key = nullptr;
      for (const auto& [param, param_value] : component.params) {
        if (param != "key") return Outcome::kSkip;  // sf, bs, req, tr.
        key = StringParam(component.params, "key");
        if (key == nullptr) return Outcome::kInvalid;
      }
      if (key != nullptr) {
        const std::optional<sf::Dictionary> dictionary =
            sf::ParseDictionary(field);
        const sf::Member* member =
            dictionary ? sf::Find(*dictionary, key->text) : nullptr;
        if (member == nullptr) return Outcome::kInvalid;
        component_value = sf::Serialize(*member);
        if (name == "signature-agent") {
          if (member->is_inner_list ||
              member->item.value.type != sf::BareItem::Type::kString) {
            return Outcome::kInvalid;
          }
          AgentMember parsed{member->item.value.text, "directory"};
          if (const sf::BareItem* type = member->item.Param("type")) {
            if (type->type != sf::BareItem::Type::kToken) {
              return Outcome::kInvalid;
            }
            parsed.type = type->text;
          }
          agent = std::move(parsed);
        }
      } else {
        component_value = field;
        if (name == "signature-agent") {
          // Legacy form: the whole field is one String.
          const std::optional<sf::Item> item = sf::ParseItem(field);
          if (!item || item->value.type != sf::BareItem::Type::kString) {
            return Outcome::kInvalid;
          }
          agent = AgentMember{item->value.text, "directory"};
        }
      }
    }
    base += sf::Serialize(component);
    base += ": ";
    base += component_value;
    base += '\n';
  }
  if (!covers_authority || !agent) return Outcome::kInvalid;
  base += "\"@signature-params\": ";
  base += sf::Serialize(input);

  ParsedUrl url;
  if (!ParseUrl(agent->url, &url) || !url.tls) return Outcome::kInvalid;
  const std::string origin =
      url.port == "443"
          ? std::format("https://{}", Lower(url.host))
          : std::format("https://{}:{}", Lower(url.host), url.port);
  if (agent->type == "directory") {
    if (url.target != "/") return Outcome::kInvalid;
    signature->identifier = origin + std::string(kWellKnown);
    signature->fetch_url = signature->identifier;
  } else if (agent->type == "jwks_uri") {
    const std::string_view path = url.target;
    signature->identifier =
        origin + std::string(path.substr(0, path.find_first_of("?#")));
    signature->fetch_url = agent->url;
  } else {
    return Outcome::kSkip;  // cimd and future types.
  }
  signature->label = label;
  signature->agent = Lower(url.host);
  signature->keyid = keyid->text;
  signature->base = std::move(base);
  signature->signature = value->item.value.text;
  signature->created = *created;
  signature->expires = *expires;
  return Outcome::kOk;
}

int64_t MaxAge(std::string_view cache_control) {
  const std::size_t at = cache_control.find("max-age=");
  if (at == std::string_view::npos) return -1;
  int64_t seconds = -1;
  const std::string_view digits = cache_control.substr(at + 8);
  std::from_chars(digits.data(), digits.data() + digits.size(), seconds);
  return seconds;
}

bool DefaultFetch(const std::string& url, const std::stop_token& stop,
                  std::string* body, int64_t* max_age, std::string* error) {
  HttpClientRequest request;
  request.url = url;
  request.stop = stop;
  request.max_redirects = 0;  // The draft forbids following them.
  request.max_body = std::size_t{1} << 20;
  request.timeout = std::chrono::seconds(10);
  request.headers = {{"Accept",
                      "application/http-message-signatures-directory+json, "
                      "application/json"}};
  HttpClientResponse response;
  if (!HttpFetch(request, &response, error)) return false;
  if (response.status != 200) {
    *error = std::format("{}: HTTP {}", url, response.status);
    return false;
  }
  *max_age = MaxAge(response.Header("cache-control"));
  *body = std::move(response.body);
  return true;
}

}  // namespace

std::vector<WebBotAuthSignature> ParseWebBotAuth(const HttpRequest& request,
                                                 int64_t now,
                                                 const WebBotAuthLimits& limits,
                                                 int* invalid) {
  std::vector<WebBotAuthSignature> out;
  const std::string input_field = Combined(request, "signature-input");
  if (input_field.empty()) return out;
  const std::optional<sf::Dictionary> inputs = sf::ParseDictionary(input_field);
  if (!inputs) {
    ++*invalid;
    return out;
  }
  const std::optional<sf::Dictionary> signatures =
      sf::ParseDictionary(Combined(request, "signature"));
  for (const auto& [label, member] : *inputs) {
    if (!member.is_inner_list) continue;
    WebBotAuthSignature signature;
    switch (BuildSignature(request, label, member.inner_list,
                           signatures ? &*signatures : nullptr, now, limits,
                           &signature)) {
      case Outcome::kOk:
        out.push_back(std::move(signature));
        break;
      case Outcome::kInvalid:
        ++*invalid;
        break;
      case Outcome::kSkip:
        break;
    }
  }
  return out;
}

std::string Ed25519Thumbprint(const std::array<uint8_t, 32>& public_key) {
  // Members in lexicographic order, no whitespace (RFC 7638).
  const std::string json =
      std::format(R"({{"crv":"Ed25519","kty":"OKP","x":"{}"}})",
                  Base64Url(public_key.data(), public_key.size()));
  std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
  SHA256(reinterpret_cast<const uint8_t*>(json.data()), json.size(),
         digest.data());
  return Base64Url(digest.data(), digest.size());
}

bool ParseJwks(std::string_view json, std::map<std::string, Ed25519Key>* keys,
               std::string* error) {
  const nlohmann::json root = nlohmann::json::parse(json, nullptr, false);
  const auto list = root.is_object() ? root.find("keys") : root.end();
  if (root.is_discarded() || !root.is_object() || list == root.end() ||
      !list->is_array()) {
    *error = "not a JWK Set";
    return false;
  }
  keys->clear();
  for (const nlohmann::json& jwk : *list) {
    if (!jwk.is_object() || jwk.value("kty", "") != "OKP" ||
        jwk.value("crv", "") != "Ed25519") {
      continue;
    }
    std::string x;
    if (!jwk.contains("x") || !jwk["x"].is_string() ||
        !Base64UrlDecodeTo(jwk["x"].get<std::string>(), &x) || x.size() != 32) {
      continue;
    }
    Ed25519Key key;
    std::ranges::copy(x, key.public_key.begin());
    if (jwk.contains("nbf") && jwk["nbf"].is_number_integer()) {
      key.not_before = jwk["nbf"].get<int64_t>();
    }
    if (jwk.contains("exp") && jwk["exp"].is_number_integer()) {
      key.expires = jwk["exp"].get<int64_t>();
    }
    (*keys)[Ed25519Thumbprint(key.public_key)] = key;
  }
  if (keys->empty()) {
    *error = "no Ed25519 keys";
    return false;
  }
  return true;
}

bool VerifyEd25519(const std::array<uint8_t, 32>& public_key,
                   std::string_view message, std::string_view signature) {
  return signature.size() == 64 &&
         ED25519_verify(reinterpret_cast<const uint8_t*>(message.data()),
                        message.size(),
                        reinterpret_cast<const uint8_t*>(signature.data()),
                        public_key.data()) == 1;
}

WebBotAuthVerifier::WebBotAuthVerifier(Settings settings, Fetch fetch)
    : settings_(settings),
      fetch_(fetch ? std::move(fetch) : Fetch(DefaultFetch)),
      thread_([this](const std::stop_token& stop) { Run(stop); }) {}

WebBotAuthVerifier::~WebBotAuthVerifier() {
  thread_.request_stop();
  wake_.notify_all();
}

void WebBotAuthVerifier::Enqueue(const WebBotAuthSignature& signature) {
  if (in_flight_.contains(signature.identifier) ||
      queue_.size() >= settings_.max_queue) {
    return;
  }
  in_flight_.insert(signature.identifier);
  queue_.emplace_back(signature.identifier, signature.fetch_url);
  wake_.notify_one();
}

WebBotAuthResult WebBotAuthVerifier::Check(const HttpRequest& request,
                                           int64_t now) {
  int invalid = 0;
  const std::vector<WebBotAuthSignature> signatures =
      ParseWebBotAuth(request, now, settings_.limits, &invalid);
  WebBotAuthResult result;
  if (invalid > 0) result.status = WebBotAuthStatus::kInvalid;
  for (const WebBotAuthSignature& signature : signatures) {
    std::optional<Ed25519Key> key;
    {
      const std::scoped_lock lock(mutex_);
      const auto it = directories_.find(signature.identifier);
      if (it == directories_.end() || it->second.expires <= now) {
        Enqueue(signature);
        if (result.status == WebBotAuthStatus::kNone) {
          result.status = WebBotAuthStatus::kPending;
          result.agent = signature.agent;
        }
        if (it == directories_.end()) continue;
      }
      // An unreachable directory proves nothing either way.
      if (it->second.failed) continue;
      const auto found = it->second.keys.find(signature.keyid);
      if (found != it->second.keys.end()) key = found->second;
    }
    if (key && (key->not_before == 0 || key->not_before <= now) &&
        (key->expires == 0 || key->expires > now) &&
        VerifyEd25519(key->public_key, signature.base, signature.signature)) {
      return WebBotAuthResult{WebBotAuthStatus::kVerified, signature.agent};
    }
    result.status = WebBotAuthStatus::kInvalid;
    result.agent = signature.agent;
  }
  return result;
}

void WebBotAuthVerifier::WaitIdle() {
  std::unique_lock lock(mutex_);
  idle_.wait(lock, [this] { return queue_.empty() && running_ == 0; });
}

void WebBotAuthVerifier::Run(const std::stop_token& stop) {
  while (true) {
    std::pair<std::string, std::string> job;
    {
      std::unique_lock lock(mutex_);
      if (!wake_.wait(lock, stop, [this] { return !queue_.empty(); })) return;
      job = std::move(queue_.front());
      queue_.pop_front();
      ++running_;
    }
    std::string body;
    std::string error;
    int64_t max_age = -1;
    Directory directory;
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    if (fetch_(job.second, stop, &body, &max_age, &error) &&
        ParseJwks(body, &directory.keys, &error)) {
      const int64_t ttl =
          max_age < 0
              ? settings_.default_ttl.count()
              : std::clamp<int64_t>(max_age, 60, settings_.max_ttl.count());
      directory.expires = now + ttl;
    } else {
      directory.failed = true;
      directory.expires = now + settings_.failed_ttl.count();
    }
    {
      const std::scoped_lock lock(mutex_);
      if (directories_.size() >= settings_.max_agents &&
          !directories_.contains(job.first)) {
        directories_.erase(directories_.begin());
      }
      directories_[job.first] = std::move(directory);
      in_flight_.erase(job.first);
      --running_;
    }
    idle_.notify_all();
  }
}

}  // namespace bot_shield
