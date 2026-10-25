#include "mcp/server.hpp"
#include <iostream>
#include <sstream>
#include <cstring>
#include <cstdio>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef int socklen_t;
#define CLOSESOCK closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define CLOSESOCK close
typedef int SOCKET;
constexpr int INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
#endif

namespace aida::mcp {

McpServer::McpServer() = default;
McpServer::~McpServer() { stop(); }

void McpServer::register_tool(ToolDef tool) {
    tools_[tool.name] = std::move(tool);
}

void McpServer::stop() {
    running_ = false;
}

void McpServer::run_stdio() {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    running_ = true;
    std::string line;
    while (running_ && std::getline(std::cin, line)) {
        if (line.empty()) continue;

        json request;
        try {
            request = json::parse(line);
        } catch (...) {
            json err;
            err["jsonrpc"] = "2.0";
            err["error"]["code"] = -32700;
            err["error"]["message"] = "Parse error";
            std::cout << err.dump() << "\n" << std::flush;
            continue;
        }

        json response = handle_request(request);
        if (!response.is_null()) {
            std::cout << response.dump() << "\n" << std::flush;
        }
    }
}

static bool recv_all(SOCKET fd, char* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = recv(fd, buf + got, (int)(len - got), 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

void McpServer::handle_http_client(int client_fd) {
    SOCKET fd = static_cast<SOCKET>(client_fd);
    std::string header_buf;
    header_buf.reserve(4096);
    char ch;

    while (header_buf.size() < 16384) {
        int n = recv(fd, &ch, 1, 0);
        if (n <= 0) { CLOSESOCK(fd); return; }
        header_buf += ch;
        if (header_buf.size() >= 4 &&
            header_buf.substr(header_buf.size() - 4) == "\r\n\r\n")
            break;
    }

    bool is_post = (header_buf.substr(0, 4) == "POST");
    bool is_options = (header_buf.substr(0, 7) == "OPTIONS");
    bool is_get = (header_buf.substr(0, 3) == "GET");

    auto send_str = [&](const std::string& s) {
        send(fd, s.c_str(), (int)s.size(), 0);
    };

    std::string cors =
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n";

    if (is_options) {
        send_str("HTTP/1.1 204 No Content\r\n" + cors + "\r\n");
        CLOSESOCK(fd);
        return;
    }

    if (is_get) {
        std::string body = "{\"name\":\"aida\",\"version\":\"2.0.0\"}";
        std::string resp = "HTTP/1.1 200 OK\r\n" + cors +
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        send_str(resp);
        CLOSESOCK(fd);
        return;
    }

    if (!is_post) {
        send_str("HTTP/1.1 405 Method Not Allowed\r\n" + cors + "\r\n");
        CLOSESOCK(fd);
        return;
    }

    size_t content_length = 0;
    std::string header_lower = header_buf;
    for (auto& c : header_lower) c = (char)tolower(c);
    auto cl_pos = header_lower.find("content-length:");
    if (cl_pos != std::string::npos) {
        content_length = std::stoull(header_buf.substr(cl_pos + 15));
    }

    if (content_length == 0 || content_length > 10 * 1024 * 1024) {
        send_str("HTTP/1.1 400 Bad Request\r\n" + cors + "\r\n");
        CLOSESOCK(fd);
        return;
    }

    std::string body(content_length, '\0');
    if (!recv_all(fd, &body[0], content_length)) {
        CLOSESOCK(fd);
        return;
    }

    json request;
    try {
        request = json::parse(body);
    } catch (...) {
        json err;
        err["jsonrpc"] = "2.0";
        err["error"]["code"] = -32700;
        err["error"]["message"] = "Parse error";
        std::string err_body = err.dump();
        std::string resp = "HTTP/1.1 200 OK\r\n" + cors +
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(err_body.size()) + "\r\n\r\n" + err_body;
        send_str(resp);
        CLOSESOCK(fd);
        return;
    }

    json response = handle_request(request);

    if (response.is_null()) {
        send_str("HTTP/1.1 202 Accepted\r\n" + cors + "\r\n");
    } else {
        std::string resp_body = response.dump();
        std::string resp = "HTTP/1.1 200 OK\r\n" + cors +
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(resp_body.size()) + "\r\n\r\n" + resp_body;
        send_str(resp);
    }

    CLOSESOCK(fd);
}

void McpServer::run_http(uint16_t port) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        fprintf(stderr, "[!] MCP HTTP: failed to create socket\n");
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[!] MCP HTTP: failed to bind port %d\n", port);
        CLOSESOCK(server_fd);
        return;
    }

    socklen_t addr_len = sizeof(addr);
    getsockname(server_fd, (struct sockaddr*)&addr, &addr_len);
    bound_port_ = ntohs(addr.sin_port);

    if (listen(server_fd, 8) == SOCKET_ERROR) {
        fprintf(stderr, "[!] MCP HTTP: listen failed\n");
        CLOSESOCK(server_fd);
        return;
    }

    fprintf(stderr, "[+] MCP HTTP server listening on http://127.0.0.1:%d/mcp\n", bound_port_);

    running_ = true;
    while (running_) {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

#ifdef _WIN32
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int sel = select(0, &readfds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;
#else
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int sel = select(server_fd + 1, &readfds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;
#endif

        SOCKET client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd == INVALID_SOCKET) continue;

        handle_http_client(static_cast<int>(client_fd));
    }

    CLOSESOCK(server_fd);
#ifdef _WIN32
    WSACleanup();
#endif
}

json McpServer::handle_request(const json& request) {
    std::string method = request.value("method", "");
    json id = request.contains("id") ? request["id"] : json(nullptr);
    json params = request.value("params", json::object());

    json result;

    if (method == "initialize") {
        result = handle_initialize(params);
    } else if (method == "tools/list") {
        result = handle_tools_list(params);
    } else if (method == "tools/call") {
        result = handle_tool_call(params);
    } else if (method == "notifications/initialized") {
        return json(nullptr);
    } else if (method == "ping") {
        result = json::object();
    } else {
        json resp;
        resp["jsonrpc"] = "2.0";
        if (!id.is_null()) resp["id"] = id;
        resp["error"]["code"] = -32601;
        resp["error"]["message"] = "Method not found: " + method;
        return resp;
    }

    json resp;
    resp["jsonrpc"] = "2.0";
    if (!id.is_null()) resp["id"] = id;
    resp["result"] = result;
    return resp;
}

json McpServer::handle_initialize(const json&) {
    json caps;
    caps["tools"] = json::object();

    json result;
    result["protocolVersion"] = "2024-11-05";
    result["capabilities"] = caps;
    result["serverInfo"]["name"] = "aida";
    result["serverInfo"]["version"] = "2.0.0";
    return result;
}

json McpServer::handle_tools_list(const json&) {
    json tool_list = json::array();
    for (auto& [name, def] : tools_) {
        json t;
        t["name"] = def.name;
        t["description"] = def.description;
        t["inputSchema"] = def.input_schema;
        tool_list.push_back(std::move(t));
    }

    json result;
    result["tools"] = tool_list;
    return result;
}

json McpServer::handle_tool_call(const json& params) {
    std::string name = params.value("name", "");
    json args = params.value("arguments", json::object());

    auto it = tools_.find(name);
    if (it == tools_.end()) {
        json result;
        result["content"] = json::array({
            {{"type", "text"}, {"text", "Unknown tool: " + name}}
        });
        result["isError"] = true;
        return result;
    }

    try {
        json tool_result = it->second.handler(args);

        json result;
        if (tool_result.is_string()) {
            result["content"] = json::array({
                {{"type", "text"}, {"text", tool_result.get<std::string>()}}
            });
        } else {
            result["content"] = json::array({
                {{"type", "text"}, {"text", tool_result.dump(2)}}
            });
        }
        return result;
    } catch (const std::exception& e) {
        json result;
        result["content"] = json::array({
            {{"type", "text"}, {"text", std::string("Error: ") + e.what()}}
        });
        result["isError"] = true;
        return result;
    }
}

}
