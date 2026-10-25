#pragma once
#include "core/binary.hpp"
#include "core/analysis.hpp"
#ifdef AIDA_HAS_DECOMP
#include "core/decompiler.hpp"
#endif
#ifdef AIDA_HAS_MCP
#include "mcp/tools.hpp"
#endif
#include <memory>
#include <string>
#include <atomic>
#include <thread>

namespace aida::ui {

struct AppState {
    std::shared_ptr<BinaryImage> image;
    int selected_func_idx = -1;
    uint64_t selected_addr = 0;
    std::string status_msg;
    uint16_t mcp_port = 0;
    char search_buf[256] = {};
    std::string pending_drop_path;
    bool needs_layout_rebuild = false;

    // shared notes (AI + human)
    std::string notes_text;
    char notes_input[4096] = {};

    // MCP session link -- when MCP loads a binary, GUI picks it up
#ifdef AIDA_HAS_MCP
    std::shared_ptr<aida::mcp::McpSession> mcp_session;
#endif
    std::atomic<uint64_t> mcp_generation{0};
    uint64_t gui_generation = 0;

#ifdef AIDA_HAS_DECOMP
    std::shared_ptr<Decompiler> decompiler;
    uint64_t decomp_cached_addr = 0;
    std::string decomp_cached_code;
    bool decomp_has_error = false;
#endif

    // background analysis
    std::shared_ptr<AnalysisProgress> analysis_prog;
    std::thread analysis_thread;
    bool analysis_finished_handled = true;
};

#ifdef AIDA_HAS_MCP
int run_gui(std::shared_ptr<BinaryImage> img = nullptr, uint16_t mcp_port = 0,
            std::shared_ptr<aida::mcp::McpSession> session = nullptr);
#else
int run_gui(std::shared_ptr<BinaryImage> img = nullptr, uint16_t mcp_port = 0);
#endif

}
