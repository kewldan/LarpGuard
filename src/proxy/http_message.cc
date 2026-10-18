#include "proxy/http_message.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <format>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace bot_shield {
namespace {

std::string Lowercase(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

std::string_view Trim(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1);
  }
  return text;
}

// Names listed in Connection headers ("Connection: close, x-foo").
std::vector<std::string> ConnectionTokens(const HeaderList& headers) {
  std::vector<std::string> tokens;
  for (const auto& [name, value] : headers) {
    if (name != "connection") continue;
    std::string_view rest = value;
    while (!rest.empty()) {
      const std::size_t comma = rest.find(',');
      const std::string_view token = Trim(rest.substr(0, comma));
      if (!token.empty()) tokens.push_back(Lowercase(token));
      if (comma == std::string_view::npos) break;
      rest.remove_prefix(comma + 1);
    }
  }
  return tokens;
}

std::string HostWithoutPort(std::string_view authority) {
  if (authority.starts_with('[')) {
    return std::string(authority.substr(0, authority.find(']') + 1));
  }
  return std::string(authority.substr(0, authority.find(':')));
}

}  // namespace

bool IsHopByHop(std::string_view lowercase_name) {
  return lowercase_name == "connection" || lowercase_name == "keep-alive" ||
         lowercase_name == "proxy-connection" ||
         lowercase_name == "transfer-encoding" || lowercase_name == "upgrade" ||
         lowercase_name == "te" || lowercase_name == "host";
}

bool IsSpoofableForwardingHeader(std::string_view lowercase_name) {
  return lowercase_name == "x-forwarded-for" ||
         lowercase_name == "x-forwarded-host" ||
         lowercase_name == "x-forwarded-proto" ||
         lowercase_name == "x-forwarded-port" ||
         lowercase_name == "x-forwarded-server" ||
         lowercase_name == "x-real-ip" || lowercase_name == "forwarded" ||
         lowercase_name.starts_with("x-bot-");
}

HeaderList FilterRequestHeaders(const HeaderList& headers) {
  const std::vector<std::string> listed = ConnectionTokens(headers);
  HeaderList out;
  out.reserve(headers.size());
  for (const auto& [name, value] : headers) {
    if (name == "te") {
      if (Lowercase(Trim(value)) == "trailers") out.emplace_back(name, value);
      continue;
    }
    if (IsHopByHop(name) || IsSpoofableForwardingHeader(name) ||
        std::ranges::find(listed, name) != listed.end()) {
      continue;
    }
    out.emplace_back(name, value);
  }
  return out;
}

HeaderList FilterResponseHeaders(const HeaderList& headers) {
  HeaderList out;
  out.reserve(headers.size());
  for (const auto& [name, value] : headers) {
    if (IsHopByHop(name)) continue;
    out.emplace_back(name, value);
  }
  return out;
}

void SetAltSvc(std::string_view alt_svc, HeaderList* headers) {
  std::erase_if(*headers,
                [](const auto& header) { return header.first == "alt-svc"; });
  if (!alt_svc.empty()) headers->emplace_back("alt-svc", alt_svc);
}

void AddForwardingHeaders(const ClientInfo& client, std::string_view authority,
                          HeaderList* headers) {
  asio::ip::address address = client.address;
  if (address.is_v6() && address.to_v6().is_v4_mapped()) {
    address = asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6());
  }
  const std::string ip = address.to_string();
  headers->emplace_back("x-forwarded-for", ip);
  headers->emplace_back("x-real-ip", ip);
  headers->emplace_back("x-forwarded-proto", "https");
  headers->emplace_back("x-forwarded-host", HostWithoutPort(authority));
  headers->emplace_back("x-forwarded-port", std::to_string(client.local_port));
}

std::string_view FindHeader(const HeaderList& headers, std::string_view name) {
  for (const auto& [header, value] : headers) {
    if (header == name) return value;
  }
  return {};
}

bool ResponseHasBody(std::string_view method, int status) {
  if (method == "HEAD") return false;
  return status >= 200 && status != 204 && status != 304;
}

std::string_view ReasonPhrase(int status) {
  switch (status) {
    case 100:
      return "Continue";
    case 101:
      return "Switching Protocols";
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 202:
      return "Accepted";
    case 204:
      return "No Content";
    case 206:
      return "Partial Content";
    case 301:
      return "Moved Permanently";
    case 302:
      return "Found";
    case 303:
      return "See Other";
    case 304:
      return "Not Modified";
    case 307:
      return "Temporary Redirect";
    case 308:
      return "Permanent Redirect";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 408:
      return "Request Timeout";
    case 413:
      return "Content Too Large";
    case 429:
      return "Too Many Requests";
    case 431:
      return "Request Header Fields Too Large";
    case 500:
      return "Internal Server Error";
    case 502:
      return "Bad Gateway";
    case 503:
      return "Service Unavailable";
    case 504:
      return "Gateway Timeout";
    default:
      return status < 300 ? "OK" : (status < 400 ? "Redirect" : "Error");
  }
}

std::string FormatH1ResponseHead(std::string_view version, int status,
                                 const HeaderList& headers) {
  std::string head =
      std::format("HTTP/{} {} {}\r\n", version, status, ReasonPhrase(status));
  for (const auto& [name, value] : headers) {
    std::format_to(std::back_inserter(head), "{}: {}\r\n", name, value);
  }
  head += "\r\n";
  return head;
}

ProxyResponse LocalResponse(int status, std::size_t body_size) {
  ProxyResponse response;
  response.status = status;
  response.headers = {{"content-type", "text/plain; charset=utf-8"},
                      {"content-length", std::to_string(body_size)},
                      {"cache-control", "no-store"}};
  return response;
}

}  // namespace bot_shield
