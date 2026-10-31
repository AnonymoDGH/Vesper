// Vesper -- local HTTP + WebSocket bridge.
//
// Two roles, one implementation:
//   * the shell-side bridge hosts it and the UI talks to it over HTTP/WS;
//   * the engine side uses the client to reach the bridge from inside Roblox.
//
// Everything is bound to loopback and authenticated with a per-session token,
// which is what the `X-Vesper-Token` header carries.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vesper::http {

struct Request {
    std::string method;
    std::string path;
    std::string query;
    std::string body;
    std::map<std::string, std::string> headers;

    std::string header(const char* name) const;
    std::string param(const char* name) const;  // query string lookup
    bool is_websocket() const;
};

struct Response {
    int status = 200;
    std::string content_type = "application/json; charset=utf-8";
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;

    static Response json(const std::string& body) { return Response{200, "application/json; charset=utf-8", body, {}}; }
    static Response text(const std::string& body) { return Response{200, "text/plain; charset=utf-8", body, {}}; }
    static Response status_only(int status, const std::string& message) {
        return Response{status, "text/plain; charset=utf-8", message, {}};
    }
};

using Handler = std::function<Response(const Request&)>;
using MessageHandler = std::function<void(const std::string& payload)>;

class Server {
public:
    Server();
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Binds to `host`:`port` (port 0 = pick a free port). Fills `port_out`.
    bool start(const std::string& host, std::uint16_t port, std::string& error);
    void stop();

    std::uint16_t port() const { return port_; }
    std::string url() const;

    void route(const std::string& path, Handler handler);
    void set_token(const std::string& token);
    const std::string& token() const { return token_; }

    // Fires whenever the UI sends a websocket text frame.
    void on_message(MessageHandler handler);
    // Pushes a text frame to every connected websocket client.
    void broadcast(const std::string& text);
    std::size_t socket_count() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::uint16_t port_ = 0;
    std::string token_;
};

struct ClientResult {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
};

// Blocking HTTP client. `timeout_ms` bounds connect + receive.
ClientResult post_json(const std::string& url, const std::string& body,
                       const std::string& token = {}, int timeout_ms = 15000);
ClientResult get(const std::string& url, const std::string& token = {}, int timeout_ms = 15000);

}  // namespace vesper::http
