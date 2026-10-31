// Vesper -- the local bridge hosted inside the engine.
//
// The engine is the server: it owns the port, the token and the routes the shell
// UI talks to. A companion thread keeps the Roblox bindings fresh, installs the
// environment once a place is running, and streams state over WebSocket.
#pragma once

#include <cstdint>
#include <string>

namespace vesper::bridge {

struct Config {
    std::uint16_t port = 0;  // 0 selects a free port
    std::string token;       // empty selects a generated token
};

// Starts the server and the runtime thread. `port_out` receives the bound port.
bool start(const Config& config, std::uint16_t& port_out, std::string& error);
void stop();

std::uint16_t port();
std::string url();
const std::string& token();

// Directory holding one `<pid>.json` record per injected client. The shell reads
// it to discover ports and tokens without touching the target process.
std::wstring clients_directory();

// Writes the client record with `"mode": "apc"` and no server behind it: the shell then
// reaches this process by queueing an APC and exchanging files, not by a socket.
void publish_apc_record();

// Publishes the current engine state to every connected WebSocket client.
void broadcast_state();

}  // namespace vesper::bridge
