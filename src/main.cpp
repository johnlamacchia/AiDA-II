#include "core/loader.hpp"
#include "core/analysis.hpp"
#include "core/project.hpp"
#include "core/disasm.hpp"

#ifdef AIDA_HAS_MCP
#include "mcp/server.hpp"
#include "mcp/tools.hpp"
#endif

#ifdef AIDA_HAS_GUI
#include "ui/app.hpp"
#endif

#include <cstdio>
#include <cstring>
#include <string>
#include <memory>
#include <filesystem>
#include <thread>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace aida;
namespace fs = std::filesystem;

#ifdef AIDA_WINDOWS
#include <windows.h>
#include <shlobj.h>
#endif

static void print_banner() {
    fprintf(stderr,
        "  ___  _ ___   _\n"
        " / _ \\(_)   \\ / \\\n"
        "| |_| | | |) / _ \\\n"
        "| _  | |   / ___ \\\n"
        "|_| |_|_|_/_/   \\_\\\n"
        "  v2.0.0 | standalone RE tool\n\n"
    );
}

static void print_usage(const char* argv0) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s <binary>            Load binary in GUI mode\n", argv0);
    fprintf(stderr, "  %s --mcp [binary]      Start MCP server (stdio), optionally pre-load a binary\n", argv0);
    fprintf(stderr, "  %s --setup             Auto-configure MCP for Claude Code, Claude Desktop, Cursor, etc.\n", argv0);
    fprintf(stderr, "  %s --help              Show this help\n", argv0);
    fprintf(stderr, "\nPlatform: ");
#ifdef AIDA_WINDOWS
    fprintf(stderr, "Windows");
#ifdef AIDA_KERNEL
    fprintf(stderr, " (kernel features enabled)");
#endif
#elif defined(AIDA_LINUX)
    fprintf(stderr, "Linux (kernel features disabled)");
#elif defined(AIDA_MACOS)
    fprintf(stderr, "macOS (kernel features disabled)");
#endif
    fprintf(stderr, "\n");
}

// ---------------------------------------------------------------------------
// Auto-setup: write MCP config to all known provider locations
// ---------------------------------------------------------------------------
#ifdef AIDA_HAS_MCP
static std::string get_aida_exe_path() {
#ifdef AIDA_WINDOWS
    char buf[MAX_PATH];
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::string(buf);
#else
    return fs::read_symlink("/proc/self/exe").string();
#endif
}

static nlohmann::json read_json_file(const fs::path& p) {
    if (!fs::exists(p)) return nlohmann::json::object();
    std::ifstream f(p);
    if (!f.is_open()) return nlohmann::json::object();
    try {
        return nlohmann::json::parse(f, nullptr, false);
    } catch (...) {
        return nlohmann::json::object();
    }
}

static bool write_json_file(const fs::path& p, const nlohmann::json& j) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p);
    if (!f.is_open()) return false;
    f << j.dump(2);
    return f.good();
}

static constexpr uint16_t AIDA_MCP_PORT = 19548;

static void run_setup() {
    fprintf(stderr, "[*] AiDA MCP port: %d\n", AIDA_MCP_PORT);

    nlohmann::json aida_entry = {
        {"url", "http://127.0.0.1:" + std::to_string(AIDA_MCP_PORT) + "/mcp"}
    };

    struct Provider {
        std::string name;
        fs::path config_path;
        std::string server_key;     // key under mcpServers
        bool wrap_in_servers;       // some configs nest under "mcpServers", others don't
    };

#ifdef AIDA_WINDOWS
    std::string appdata = getenv("APPDATA") ? getenv("APPDATA") : "";
    std::string home = getenv("USERPROFILE") ? getenv("USERPROFILE") : "";
#else
    std::string appdata;
    std::string home = getenv("HOME") ? getenv("HOME") : "";
#endif

    std::vector<Provider> providers;

    // Claude Desktop
    if (!appdata.empty())
        providers.push_back({"Claude Desktop",
            fs::path(appdata) / "Claude" / "claude_desktop_config.json",
            "mcpServers", true});

    // Claude Code
    if (!home.empty())
        providers.push_back({"Claude Code",
            fs::path(home) / ".claude.json",
            "mcpServers", true});

    // Cursor
    if (!home.empty())
        providers.push_back({"Cursor",
            fs::path(home) / ".cursor" / "mcp.json",
            "mcpServers", true});

    // VS Code
    if (!home.empty())
        providers.push_back({"VS Code",
            fs::path(home) / ".vscode" / "mcp.json",
            "servers", true});

    // Windsurf
    if (!home.empty())
        providers.push_back({"Windsurf",
            fs::path(home) / ".codeium" / "windsurf" / "mcp_config.json",
            "mcpServers", true});

    int configured = 0;
    for (auto& prov : providers) {
        auto cfg = read_json_file(prov.config_path);

        if (!cfg.contains(prov.server_key))
            cfg[prov.server_key] = nlohmann::json::object();

        if (cfg[prov.server_key].contains("aida")) {
            fprintf(stderr, "[=] %-16s already configured at %s\n",
                prov.name.c_str(), prov.config_path.string().c_str());
            configured++;
            continue;
        }

        cfg[prov.server_key]["aida"] = aida_entry;

        if (write_json_file(prov.config_path, cfg)) {
            fprintf(stderr, "[+] %-16s configured at %s\n",
                prov.name.c_str(), prov.config_path.string().c_str());
            configured++;
        } else {
            fprintf(stderr, "[!] %-16s FAILED to write %s\n",
                prov.name.c_str(), prov.config_path.string().c_str());
        }
    }

    fprintf(stderr, "\n[+] %d/%zu providers configured. AiDA MCP is ready.\n",
        configured, providers.size());
    fprintf(stderr, "    Open AiDA, load a binary, then open your AI provider.\n");
    fprintf(stderr, "    MCP connects to http://127.0.0.1:%d/mcp\n", AIDA_MCP_PORT);
}
#endif // AIDA_HAS_MCP

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------
#ifdef AIDA_WINDOWS
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    int argc = __argc;
    char** argv = __argv;
#else
int main(int argc, char** argv) {
#endif
    print_banner();

    bool mcp_mode = false;
    bool setup_mode = false;
    std::string binary_path;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mcp") == 0) {
            mcp_mode = true;
        } else if (strcmp(argv[i], "--setup") == 0) {
            setup_mode = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            binary_path = argv[i];
        }
    }

    if (setup_mode) {
#ifdef AIDA_HAS_MCP
        run_setup();
#else
        fprintf(stderr, "[!] MCP support not compiled in, setup not available\n");
#endif
        return 0;
    }

    // Pre-load binary if provided on command line
    std::shared_ptr<BinaryImage> shared_img;
    if (!binary_path.empty()) {
        if (!fs::exists(binary_path)) {
            fprintf(stderr, "[!] File not found: %s\n", binary_path.c_str());
            return 1;
        }
        fprintf(stderr, "[*] Loading: %s\n", binary_path.c_str());
        auto img = load_binary(binary_path);
        if (!img) {
            fprintf(stderr, "[!] Failed to load binary\n");
            return 1;
        }
        fprintf(stderr, "[+] Format: %s | Arch: %d-bit | Base: 0x%llX | Entry: 0x%llX\n",
            img->format == BinaryFormat::PE ? "PE" :
            img->format == BinaryFormat::ELF ? "ELF" :
            img->format == BinaryFormat::MachO ? "Mach-O" : "Raw",
            arch_bits(img->arch),
            (unsigned long long)img->base,
            (unsigned long long)img->entry);

        run_full_analysis(*img);

        std::string db_path = binary_path + ".aida";
        if (fs::exists(db_path)) {
            load_project(*img, db_path);
            fprintf(stderr, "[+] Project loaded (%zu user names)\n", img->user_names.size());
        }
        shared_img = std::shared_ptr<BinaryImage>(img.release());
    }

    // --mcp: headless stdio MCP (no GUI, for scripting / non-GUI clients)
    if (mcp_mode) {
#ifdef AIDA_HAS_MCP
        auto session = std::make_shared<aida::mcp::McpSession>();
        if (shared_img) {
            session->image = shared_img;
#ifdef AIDA_HAS_DECOMP
            session->decompiler = std::make_shared<Decompiler>(shared_img);
            session->decompiler_ok = session->decompiler->init();
#endif
        }
        aida::mcp::McpServer server;
        aida::mcp::register_all_tools(server, session);
        fprintf(stderr, "[+] MCP stdio: %zu tools registered.\n", server.tool_count());
        if (!shared_img)
            fprintf(stderr, "[*] No binary -- use 'load_binary' tool to load one.\n");
        server.run_stdio();
        return 0;
#else
        fprintf(stderr, "[!] MCP support not compiled in\n");
        return 1;
#endif
    }

    // GUI mode: always starts HTTP MCP on fixed port so AI providers can connect
#ifdef AIDA_HAS_GUI
#ifdef AIDA_HAS_MCP
    {
        auto session = std::make_shared<aida::mcp::McpSession>();
        if (shared_img) {
            session->image = shared_img;
#ifdef AIDA_HAS_DECOMP
            session->decompiler = std::make_shared<Decompiler>(shared_img);
            session->decompiler_ok = session->decompiler->init();
#endif
        }
        auto mcp_server = std::make_shared<aida::mcp::McpServer>();
        aida::mcp::register_all_tools(*mcp_server, session);
        std::thread mcp_thread([mcp_server]() {
            mcp_server->run_http(AIDA_MCP_PORT);
        });
        mcp_thread.detach();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        fprintf(stderr, "[+] MCP HTTP: %zu tools on http://127.0.0.1:%d/mcp\n",
            mcp_server->tool_count(), AIDA_MCP_PORT);
        return aida::ui::run_gui(shared_img, AIDA_MCP_PORT, session);
    }
#else
    return aida::ui::run_gui(shared_img);
#endif
#else
    fprintf(stderr, "[!] GUI support not compiled in. Use --mcp for headless mode.\n");
    return 1;
#endif
}
