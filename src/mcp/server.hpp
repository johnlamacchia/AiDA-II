#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <functional>
#include <unordered_map>
#include <atomic>
#include <cstdint>

namespace aida::mcp {

using json = nlohmann::json;
using ToolHandler = std::function<json(const json& params)>;

struct ToolDef {
    std::string name;
    std::string description;
    json input_schema;
    ToolHandler handler;
};

class McpServer {
public:
    McpServer();
    ~McpServer();

    void register_tool(ToolDef tool);
    void run_stdio();
    void run_http(uint16_t port = 0);
    void stop();

    uint16_t bound_port() const { return bound_port_; }
    size_t tool_count() const { return tools_.size(); }

private:
    std::unordered_map<std::string, ToolDef> tools_;
    std::atomic<bool> running_{false};
    uint16_t bound_port_ = 0;

    json handle_request(const json& request);
    json handle_initialize(const json& params);
    json handle_tools_list(const json& params);
    json handle_tool_call(const json& params);

    void handle_http_client(int client_fd);
};

}
