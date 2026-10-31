// Vesper -- local HTTP + WebSocket server/client.
//
// The server is deliberately minimal: HTTP/1.1 with keep-alive, one thread per
// connection, a route table and a WebSocket endpoint used to stream engine
// events to the shell UI. It binds to loopback only.
#include <winsock2.h>
#include <ws2tcpip.h>

#include <vesper/http.hpp>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <thread>

#include <vesper/common.hpp>

namespace vesper::http {

namespace {

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return text;
}

std::string trim(const std::string& text) {
    const auto begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

void url_decode_into(std::map<std::string, std::string>& out, const std::string& query) {
    std::size_t index = 0;
    while (index < query.size()) {
        const std::size_t separator = query.find('&', index);
        const std::string pair =
            query.substr(index, separator == std::string::npos ? std::string::npos : separator - index);
        const std::size_t equals = pair.find('=');
        if (equals != std::string::npos) {
            out[lower(pair.substr(0, equals))] = pair.substr(equals + 1);
        } else if (!pair.empty()) {
            out[lower(pair)] = "";
        }
        if (separator == std::string::npos) break;
        index = separator + 1;
    }
}

// ------------------------------------------------------------------- base64 --

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 2 < len) {
        const unsigned value = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(kB64[(value >> 18) & 63]);
        out.push_back(kB64[(value >> 12) & 63]);
        out.push_back(kB64[(value >> 6) & 63]);
        out.push_back(kB64[value & 63]);
        i += 3;
    }
    if (i < len) {
        unsigned value = data[i] << 16;
        const bool two = i + 1 < len;
        if (two) value |= data[i + 1] << 8;
        out.push_back(kB64[(value >> 18) & 63]);
        out.push_back(kB64[(value >> 12) & 63]);
        out.push_back(two ? kB64[(value >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

// -------------------------------------------------------------------- sha1 --

struct Sha1 {
    std::uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

    static std::uint32_t rol(std::uint32_t value, int bits) {
        return (value << bits) | (value >> (32 - bits));
    }

    void block(const std::uint8_t* chunk) {
        std::uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(chunk[i * 4]) << 24) |
                   (static_cast<std::uint32_t>(chunk[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(chunk[i * 4 + 2]) << 8) |
                   static_cast<std::uint32_t>(chunk[i * 4 + 3]);
        }
        for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            std::uint32_t f = 0;
            std::uint32_t k = 0;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            const std::uint32_t temp = rol(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = temp;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }

    void operator()(const std::string& text, std::uint8_t out[20]) {
        std::vector<std::uint8_t> buffer(text.begin(), text.end());
        const std::uint64_t bit_length = static_cast<std::uint64_t>(buffer.size()) * 8;
        buffer.push_back(0x80);
        while (buffer.size() % 64 != 56) buffer.push_back(0);
        for (int i = 7; i >= 0; --i) {
            buffer.push_back(static_cast<std::uint8_t>((bit_length >> (i * 8)) & 0xff));
        }
        for (std::size_t offset = 0; offset < buffer.size(); offset += 64) block(buffer.data() + offset);
        for (int i = 0; i < 5; ++i) {
            out[i * 4] = static_cast<std::uint8_t>((h[i] >> 24) & 0xff);
            out[i * 4 + 1] = static_cast<std::uint8_t>((h[i] >> 16) & 0xff);
            out[i * 4 + 2] = static_cast<std::uint8_t>((h[i] >> 8) & 0xff);
            out[i * 4 + 3] = static_cast<std::uint8_t>(h[i] & 0xff);
        }
    }
};

// -------------------------------------------------------------- ws plumbing --

std::mutex g_ws_mutex;
std::vector<SOCKET> g_ws_clients;

bool send_all(SOCKET socket, const void* data, std::size_t len) {
    const char* cursor = static_cast<const char*>(data);
    std::size_t remaining = len;
    while (remaining > 0) {
        const int sent = send(socket, cursor, static_cast<int>(remaining), 0);
        if (sent <= 0) return false;
        cursor += sent;
        remaining -= static_cast<std::size_t>(sent);
    }
    return true;
}

bool ws_send_text(SOCKET socket, const std::string& text) {
    std::vector<std::uint8_t> frame;
    frame.push_back(0x81);  // FIN + text
    const std::size_t len = text.size();
    if (len < 126) {
        frame.push_back(static_cast<std::uint8_t>(len));
    } else if (len <= 0xffff) {
        frame.push_back(126);
        frame.push_back(static_cast<std::uint8_t>((len >> 8) & 0xff));
        frame.push_back(static_cast<std::uint8_t>(len & 0xff));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; --i) frame.push_back(static_cast<std::uint8_t>((len >> (i * 8)) & 0xff));
    }
    frame.insert(frame.end(), text.begin(), text.end());
    return send_all(socket, frame.data(), frame.size());
}

void ws_remove(SOCKET socket) {
    std::lock_guard<std::mutex> guard(g_ws_mutex);
    g_ws_clients.erase(std::remove(g_ws_clients.begin(), g_ws_clients.end(), socket),
                       g_ws_clients.end());
}

std::size_t ws_count() {
    std::lock_guard<std::mutex> guard(g_ws_mutex);
    return g_ws_clients.size();
}

// Reads one WebSocket frame. Only text/close/ping are handled; anything else is
// read and ignored so the stream stays framed.
bool ws_read_frame(SOCKET socket, std::string& payload, std::uint8_t& opcode, std::string& buffer) {
    auto read_more = [&](std::size_t needed) {
        while (buffer.size() < needed) {
            char chunk[4096];
            const int received = recv(socket, chunk, sizeof(chunk), 0);
            if (received <= 0) return false;
            buffer.append(chunk, static_cast<std::size_t>(received));
        }
        return true;
    };

    if (!read_more(2)) return false;
    const std::uint8_t first = static_cast<std::uint8_t>(buffer[0]);
    const std::uint8_t second = static_cast<std::uint8_t>(buffer[1]);
    opcode = first & 0x0f;
    const bool masked = (second & 0x80) != 0;
    std::uint64_t length = second & 0x7f;
    std::size_t header = 2;

    if (length == 126) {
        if (!read_more(4)) return false;
        length = (static_cast<std::uint8_t>(buffer[2]) << 8) | static_cast<std::uint8_t>(buffer[3]);
        header = 4;
    } else if (length == 127) {
        if (!read_more(10)) return false;
        length = 0;
        for (int i = 0; i < 8; ++i) {
            length = (length << 8) | static_cast<std::uint8_t>(buffer[2 + i]);
        }
        header = 10;
    }
    if (length > (8u << 20)) return false;

    std::uint8_t mask[4] = {};
    if (masked) {
        if (!read_more(header + 4)) return false;
        std::memcpy(mask, buffer.data() + header, 4);
        header += 4;
    }

    if (!read_more(header + static_cast<std::size_t>(length))) return false;

    payload.assign(buffer.data() + header, static_cast<std::size_t>(length));
    if (masked) {
        for (std::size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<char>(payload[i] ^ mask[i % 4]);
        }
    }
    buffer.erase(0, header + static_cast<std::size_t>(length));
    return true;
}

// ------------------------------------------------------------ ws handshake --

std::string ws_accept_key(const std::string& key) {
    const std::string combined = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::uint8_t digest[20];
    Sha1 hasher;
    hasher(combined, digest);
    return base64(digest, sizeof(digest));
}

std::string reason_for(int status) {
    switch (status) {
        case 200: return "OK";
        case 204: return "No Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        default: return "OK";
    }
}

std::string build_response(int status, const std::string& content_type, const std::string& body,
                           const std::vector<std::pair<std::string, std::string>>& extra,
                           bool cors) {
    std::string out = vformat("HTTP/1.1 %d %s\r\n", status, reason_for(status).c_str());
    out += "Server: Vesper\r\n";
    out += "Content-Type: " + content_type + "\r\n";
    out += vformat("Content-Length: %zu\r\n", body.size());
    out += "Connection: keep-alive\r\n";
    if (cors) {
        out += "Access-Control-Allow-Origin: *\r\n";
        out += "Access-Control-Allow-Headers: content-type,x-vesper-token\r\n";
        out += "Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n";
    }
    for (const auto& [key, value] : extra) out += key + ": " + value + "\r\n";
    out += "\r\n";
    out += body;
    return out;
}

}  // namespace

std::string Request::header(const char* name) const {
    const auto it = headers.find(lower(name));
    return it == headers.end() ? std::string() : it->second;
}

std::string Request::param(const char* name) const {
    std::map<std::string, std::string> parsed;
    url_decode_into(parsed, query);
    const auto it = parsed.find(lower(name));
    return it == parsed.end() ? std::string() : it->second;
}

bool Request::is_websocket() const { return lower(header("Upgrade")) == "websocket"; }

// -------------------------------------------------------------------- server --

struct Server::Impl {
    SOCKET listener = INVALID_SOCKET;
    bool running = false;
    std::thread accept_thread;
    std::map<std::string, Handler> routes;
    MessageHandler on_message;
    mutable std::mutex routes_mutex;
    int connections = 0;
    std::string token;

    void handle(SOCKET client);
    void serve_websocket(SOCKET client, const Request& request);
};

void Server::Impl::serve_websocket(SOCKET client, const Request& request) {
    const std::string key = request.header("Sec-WebSocket-Key");
    if (key.empty()) {
        const std::string response = build_response(400, "text/plain", "missing key", {}, true);
        send_all(client, response.data(), response.size());
        closesocket(client);
        return;
    }

    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " +
        ws_accept_key(key) + "\r\n\r\n";
    if (!send_all(client, response.data(), response.size())) {
        closesocket(client);
        return;
    }

    {
        std::lock_guard<std::mutex> guard(g_ws_mutex);
        g_ws_clients.push_back(client);
    }
    VSP_INFO("ws: client connected (%zu total)", ws_count());

    std::string buffer;
    for (;;) {
        std::string payload;
        std::uint8_t opcode = 0;
        if (!ws_read_frame(client, payload, opcode, buffer)) break;

        if (opcode == 0x8) break;  // close
        if (opcode == 0x9) {       // ping -> pong
            std::vector<std::uint8_t> pong{0x8a, static_cast<std::uint8_t>(payload.size())};
            pong.insert(pong.end(), payload.begin(), payload.end());
            send_all(client, pong.data(), pong.size());
            continue;
        }
        if (opcode != 0x1) continue;
        if (on_message) on_message(payload);
    }

    ws_remove(client);
    closesocket(client);
    VSP_INFO("ws: client disconnected (%zu total)", ws_count());
}

void Server::Impl::handle(SOCKET client) {
    std::string buffer;
    for (;;) {
        // Read the header block.
        std::size_t header_end = std::string::npos;
        while ((header_end = buffer.find("\r\n\r\n")) == std::string::npos) {
            char chunk[8192];
            const int received = recv(client, chunk, sizeof(chunk), 0);
            if (received <= 0) return;
            buffer.append(chunk, static_cast<std::size_t>(received));
            if (buffer.size() > (1u << 20)) return;
        }

        Request request;
        const std::string header_block = buffer.substr(0, header_end);
        buffer.erase(0, header_end + 4);

        std::size_t line_end = header_block.find("\r\n");
        const std::string request_line = header_block.substr(0, line_end);
        std::istringstream stream(request_line);
        std::string version;
        stream >> request.method >> request.path >> version;

        const std::size_t question = request.path.find('?');
        if (question != std::string::npos) {
            request.query = request.path.substr(question + 1);
            request.path = request.path.substr(0, question);
        }

        std::size_t cursor = line_end == std::string::npos ? header_block.size() : line_end + 2;
        while (cursor < header_block.size()) {
            const std::size_t next = header_block.find("\r\n", cursor);
            const std::string line =
                header_block.substr(cursor, next == std::string::npos ? std::string::npos : next - cursor);
            const std::size_t colon = line.find(':');
            if (colon != std::string::npos) {
                request.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
            }
            if (next == std::string::npos) break;
            cursor = next + 2;
        }

        std::size_t content_length = 0;
        if (!request.header("Content-Length").empty()) {
            content_length = static_cast<std::size_t>(std::stoul(request.header("Content-Length")));
        }
        if (content_length > (32u << 20)) return;

        while (buffer.size() < content_length) {
            char chunk[8192];
            const int received = recv(client, chunk, sizeof(chunk), 0);
            if (received <= 0) return;
            buffer.append(chunk, static_cast<std::size_t>(received));
        }
        request.body = buffer.substr(0, content_length);
        buffer.erase(0, content_length);

        if (request.is_websocket()) {
            serve_websocket(client, request);
            return;
        }

        if (request.method == "OPTIONS") {
            const std::string response =
                build_response(204, "text/plain; charset=utf-8", "", {}, true);
            if (!send_all(client, response.data(), response.size())) return;
            continue;
        }

        Handler handler;
        {
            std::lock_guard<std::mutex> guard(routes_mutex);
            const auto it = routes.find(request.path);
            if (it != routes.end()) handler = it->second;
        }

        Response response;
        if (!handler) {
            response = Response::status_only(404, "no route for " + request.path);
        } else {
            const bool needs_token = request.path != "/" && request.path != "/ping";
            const std::string supplied = request.header("X-Vesper-Token").empty()
                                             ? request.param("token")
                                             : request.header("X-Vesper-Token");
            if (needs_token && !token.empty() && supplied != token) {
                response = Response::status_only(401, "token required");
            } else {
                try {
                    response = handler(request);
                } catch (const std::exception& ex) {
                    response = Response::status_only(500, ex.what());
                }
            }
        }

        const std::string wire =
            build_response(response.status, response.content_type, response.body, response.headers, true);
        if (!send_all(client, wire.data(), wire.size())) return;
    }
}

Server::Server() : impl_(new Impl()) {}

Server::~Server() {
    stop();
    impl_.reset();
}

bool Server::start(const std::string& host, std::uint16_t port, std::string& error) {
    if (impl_->running) {
        error = "server already running";
        return false;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        error = "WSAStartup failed";
        return false;
    }

    impl_->listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listener == INVALID_SOCKET) {
        error = "socket failed";
        WSACleanup();
        return false;
    }

    BOOL exclusive = TRUE;
    setsockopt(impl_->listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &address.sin_addr);

    if (bind(impl_->listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        error = vformat("bind %s:%u failed (error %d)", host.c_str(), port, WSAGetLastError());
        closesocket(impl_->listener);
        impl_->listener = INVALID_SOCKET;
        WSACleanup();
        return false;
    }

    if (listen(impl_->listener, SOMAXCONN) == SOCKET_ERROR) {
        error = "listen failed";
        closesocket(impl_->listener);
        impl_->listener = INVALID_SOCKET;
        WSACleanup();
        return false;
    }

    sockaddr_in bound{};
    int bound_length = sizeof(bound);
    getsockname(impl_->listener, reinterpret_cast<sockaddr*>(&bound), &bound_length);
    port_ = ntohs(bound.sin_port);
    impl_->running = true;
    impl_->token = token_;

    impl_->accept_thread = std::thread([this] {
        for (;;) {
            SOCKET client = accept(impl_->listener, nullptr, nullptr);
            if (client == INVALID_SOCKET) {
                if (!impl_->running) break;
                Sleep(10);
                continue;
            }
            {
                std::lock_guard<std::mutex> guard(impl_->routes_mutex);
                if (impl_->connections >= 64) {
                    closesocket(client);
                    continue;
                }
                ++impl_->connections;
            }
            std::thread([this, client] {
                impl_->handle(client);
                closesocket(client);
                std::lock_guard<std::mutex> guard(impl_->routes_mutex);
                --impl_->connections;
            }).detach();
        }
    });

    return true;
}

void Server::stop() {
    if (!impl_ || !impl_->running) return;
    impl_->running = false;

    if (impl_->listener != INVALID_SOCKET) {
        shutdown(impl_->listener, SD_BOTH);
        closesocket(impl_->listener);
        impl_->listener = INVALID_SOCKET;
    }
    if (impl_->accept_thread.joinable()) impl_->accept_thread.join();

    {
        std::lock_guard<std::mutex> guard(g_ws_mutex);
        for (SOCKET client : g_ws_clients) {
            shutdown(client, SD_BOTH);
            closesocket(client);
        }
        g_ws_clients.clear();
    }

    WSACleanup();
}

std::string Server::url() const { return vformat("http://127.0.0.1:%u", port_); }

void Server::route(const std::string& path, Handler handler) {
    std::lock_guard<std::mutex> guard(impl_->routes_mutex);
    impl_->routes[path] = std::move(handler);
}

void Server::set_token(const std::string& token) {
    token_ = token;
    impl_->token = token;
}

void Server::on_message(MessageHandler handler) { impl_->on_message = std::move(handler); }

void Server::broadcast(const std::string& text) {
    std::vector<SOCKET> targets;
    {
        std::lock_guard<std::mutex> guard(g_ws_mutex);
        targets = g_ws_clients;
    }
    for (SOCKET client : targets) {
        if (!ws_send_text(client, text)) ws_remove(client);
    }
}

std::size_t Server::socket_count() const { return ws_count(); }

// -------------------------------------------------------------------- client --

ClientResult post_json(const std::string& url, const std::string& body, const std::string& token,
                       int timeout_ms) {
    ClientResult result;

    std::string host = "127.0.0.1";
    std::uint16_t port = 80;
    std::string path = "/";

    std::string rest = url;
    const std::string scheme = "http://";
    if (rest.rfind(scheme, 0) == 0) rest = rest.substr(scheme.size());
    const std::size_t slash = rest.find('/');
    const std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    path = slash == std::string::npos ? "/" : rest.substr(slash);
    const std::size_t colon = authority.find(':');
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        port = static_cast<std::uint16_t>(std::stoi(authority.substr(colon + 1)));
    } else if (!authority.empty()) {
        host = authority;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        result.error = "WSAStartup failed";
        return result;
    }

    SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) {
        result.error = "socket failed";
        WSACleanup();
        return result;
    }

    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
               sizeof(timeout));
    setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout),
               sizeof(timeout));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &address.sin_addr);

    if (connect(socket_handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        result.error = "connect failed";
        closesocket(socket_handle);
        WSACleanup();
        return result;
    }

    std::string wire = "POST " + path + " HTTP/1.1\r\n";
    wire += "Host: " + host + "\r\n";
    wire += "Content-Type: application/json\r\n";
    wire += vformat("Content-Length: %zu\r\n", body.size());
    wire += "Connection: close\r\n";
    if (!token.empty()) wire += "X-Vesper-Token: " + token + "\r\n";
    wire += "\r\n";
    wire += body;

    if (!send_all(socket_handle, wire.data(), wire.size())) {
        result.error = "send failed";
        closesocket(socket_handle);
        WSACleanup();
        return result;
    }

    std::string response;
    char chunk[8192];
    for (;;) {
        const int received = recv(socket_handle, chunk, sizeof(chunk), 0);
        if (received <= 0) break;
        response.append(chunk, static_cast<std::size_t>(received));
        if (response.size() > (32u << 20)) break;
    }
    closesocket(socket_handle);
    WSACleanup();

    const std::size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        result.error = "malformed response";
        return result;
    }
    const std::string status_line = response.substr(0, response.find("\r\n"));
    const std::size_t first_space = status_line.find(' ');
    if (first_space != std::string::npos) {
        result.status = std::stoi(status_line.substr(first_space + 1));
    }
    result.body = response.substr(header_end + 4);
    result.ok = result.status >= 200 && result.status < 300;
    return result;
}

ClientResult get(const std::string& url, const std::string& token, int timeout_ms) {
    ClientResult result;

    std::string host = "127.0.0.1";
    std::uint16_t port = 80;
    std::string path = "/";
    std::string rest = url;
    const std::string scheme = "http://";
    if (rest.rfind(scheme, 0) == 0) rest = rest.substr(scheme.size());
    const std::size_t slash = rest.find('/');
    const std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    path = slash == std::string::npos ? "/" : rest.substr(slash);
    const std::size_t colon = authority.find(':');
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        port = static_cast<std::uint16_t>(std::stoi(authority.substr(colon + 1)));
    } else if (!authority.empty()) {
        host = authority;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        result.error = "WSAStartup failed";
        return result;
    }

    SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) {
        result.error = "socket failed";
        WSACleanup();
        return result;
    }

    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
               sizeof(timeout));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &address.sin_addr);

    if (connect(socket_handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        result.error = "connect failed";
        closesocket(socket_handle);
        WSACleanup();
        return result;
    }

    std::string wire = "GET " + path + " HTTP/1.1\r\n";
    wire += "Host: " + host + "\r\n";
    wire += "Connection: close\r\n";
    if (!token.empty()) wire += "X-Vesper-Token: " + token + "\r\n";
    wire += "\r\n";

    if (!send_all(socket_handle, wire.data(), wire.size())) {
        result.error = "send failed";
        closesocket(socket_handle);
        WSACleanup();
        return result;
    }

    std::string response;
    char chunk[8192];
    for (;;) {
        const int received = recv(socket_handle, chunk, sizeof(chunk), 0);
        if (received <= 0) break;
        response.append(chunk, static_cast<std::size_t>(received));
        if (response.size() > (32u << 20)) break;
    }
    closesocket(socket_handle);
    WSACleanup();

    const std::size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        result.error = "malformed response";
        return result;
    }
    const std::string status_line = response.substr(0, response.find("\r\n"));
    const std::size_t first_space = status_line.find(' ');
    if (first_space != std::string::npos) {
        result.status = std::stoi(status_line.substr(first_space + 1));
    }
    result.body = response.substr(header_end + 4);
    result.ok = result.status >= 200 && result.status < 300;
    return result;
}

}  // namespace vesper::http
