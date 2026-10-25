#pragma once
#include "mcp/server.hpp"
#include "core/binary.hpp"
#ifdef AIDA_HAS_DECOMP
#include "core/decompiler.hpp"
#endif
#include <memory>
#include <mutex>
#include <atomic>
#include <string>

namespace aida::mcp {

struct McpSession {
    std::shared_ptr<BinaryImage> image;
    std::mutex mtx;

    std::atomic<uint64_t> generation{0};
    std::string notes;
    std::string last_action;

    void bump(const std::string& action) {
        last_action = action;
        generation.fetch_add(1, std::memory_order_release);
    }

#ifdef AIDA_HAS_DECOMP
    std::shared_ptr<Decompiler> decompiler;
    bool decompiler_ok = false;
#endif
};

void register_all_tools(McpServer& server, std::shared_ptr<McpSession> session);

}
