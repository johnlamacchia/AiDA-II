#include "ui/app.hpp"
#include "core/disasm.hpp"
#include "core/analysis.hpp"
#include "core/project.hpp"
#include "core/loader.hpp"

#include <imgui.h>
#include <imgui_internal.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>

#include <cstdio>
#include <vector>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_map>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commdlg.h>
#undef LoadImage
#endif

namespace aida::ui {

static GLFWwindow* g_window = nullptr;
static bool g_dragging = false;
static double g_drag_x = 0, g_drag_y = 0;
static bool g_maximized = false;
static AppState* g_state = nullptr;

static void glfw_drop_callback(GLFWwindow*, int count, const char** paths) {
    if (count > 0 && g_state)
        g_state->pending_drop_path = paths[0];
}

static std::string open_file_dialog() {
#ifdef _WIN32
    char path[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = "All Executables\0*.exe;*.dll;*.sys;*.elf;*.so;*.dylib;*.bin;*.o\0All Files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameA(&ofn))
        return std::string(path);
#endif
    return {};
}

struct XrefCacheData {
    uint64_t cached_addr = 0;
    struct Entry { uint64_t addr; std::string type; std::string name; ImVec4 color; };
    std::vector<Entry> to_refs;
    std::vector<Entry> from_refs;
};
static XrefCacheData g_xref_cache;

struct FuncListCache {
    std::vector<uint64_t> addrs;
    std::string last_filter;
    size_t last_func_count = 0;
    void* last_image = nullptr;
};
static FuncListCache g_func_cache;

#ifdef AIDA_HAS_DECOMP
struct DecompCache {
    std::mutex mtx;
    std::unordered_map<uint64_t, DecompResult> results;
    std::atomic<size_t> done_count{0};
    std::atomic<size_t> total_count{0};
    std::atomic<bool> running{false};
    std::thread worker;

    void stop() {
        running.store(false, std::memory_order_release);
        if (worker.joinable()) worker.join();
    }

    void start(std::shared_ptr<Decompiler> decomp, std::shared_ptr<BinaryImage> img) {
        stop();
        {
            std::lock_guard<std::mutex> lk(mtx);
            results.clear();
        }
        done_count.store(0);

        std::vector<uint64_t> addrs;
        for (auto& [addr, fn] : img->functions) {
            if (!fn.is_import) addrs.push_back(addr);
        }
        total_count.store(addrs.size());
        running.store(true, std::memory_order_release);

        worker = std::thread([this, decomp, addrs]() {
            for (size_t i = 0; i < addrs.size(); i++) {
                if (!running.load(std::memory_order_acquire)) break;
                auto r = decomp->decompile(addrs[i]);
                {
                    std::lock_guard<std::mutex> lk(mtx);
                    results[addrs[i]] = std::move(r);
                }
                done_count.fetch_add(1, std::memory_order_release);
            }
            running.store(false, std::memory_order_release);
        });
    }

    bool lookup(uint64_t addr, DecompResult& out) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = results.find(addr);
        if (it != results.end()) {
            out = it->second;
            return true;
        }
        return false;
    }

    ~DecompCache() { stop(); }
};
static DecompCache g_decomp_cache;
#endif

static void load_binary_into_state(AppState& state, const std::string& path) {
    // stop any previous analysis thread
    if (state.analysis_thread.joinable()) {
        if (state.analysis_prog) state.analysis_prog->done.store(true);
        state.analysis_thread.join();
    }
#ifdef AIDA_HAS_DECOMP
    g_decomp_cache.stop();
#endif

    auto img = load_binary(path);
    if (!img) {
        state.status_msg = "Failed to load: " + path;
        return;
    }

    fprintf(stderr, "[*] Loading: %s\n", path.c_str());

    // set image immediately so GUI is responsive (headers/sections/imports/exports already parsed)
    state.image = std::shared_ptr<BinaryImage>(img.release());
    state.selected_func_idx = -1;
    state.selected_addr = 0;
    state.search_buf[0] = 0;
    state.needs_layout_rebuild = true;
    g_xref_cache.cached_addr = 0;
    g_func_cache.last_image = nullptr;
#ifdef AIDA_HAS_DECOMP
    state.decomp_cached_addr = 0;
    state.decomp_cached_code.clear();
    state.decomp_has_error = false;
    state.decompiler.reset();
#endif

    state.status_msg = "Analyzing " + state.image->filename + "...";

    // load saved project data if it exists
    std::string db_path = path + ".aida";
    if (std::filesystem::exists(db_path))
        load_project(*state.image, db_path);

    // run analysis in background thread
    auto prog = std::make_shared<AnalysisProgress>();
    state.analysis_prog = prog;
    state.analysis_finished_handled = false;

    auto image_ptr = state.image;
    state.analysis_thread = std::thread([image_ptr, prog]() {
        run_full_analysis(*image_ptr, prog.get());
    });
}

static void setup_theme() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding    = 0.0f;
    s.FrameRounding     = 3.0f;
    s.GrabRounding      = 3.0f;
    s.ScrollbarRounding = 3.0f;
    s.TabRounding       = 3.0f;
    s.WindowBorderSize  = 0.0f;
    s.FrameBorderSize   = 0.0f;
    s.PopupBorderSize   = 1.0f;
    s.ItemSpacing       = ImVec2(8, 5);
    s.ItemInnerSpacing  = ImVec2(6, 4);
    s.WindowPadding     = ImVec2(10, 10);
    s.FramePadding      = ImVec2(6, 4);
    s.ScrollbarSize     = 14.0f;
    s.GrabMinSize       = 10.0f;
    s.TabBarBorderSize  = 1.0f;
    s.DockingSeparatorSize = 2.0f;

    ImVec4* c = s.Colors;
    ImVec4 bg0    = ImVec4(0.067f, 0.067f, 0.082f, 1.0f);
    ImVec4 bg1    = ImVec4(0.082f, 0.082f, 0.098f, 1.0f);
    ImVec4 bg2    = ImVec4(0.098f, 0.098f, 0.118f, 1.0f);
    ImVec4 bg3    = ImVec4(0.130f, 0.130f, 0.155f, 1.0f);
    ImVec4 border = ImVec4(0.180f, 0.180f, 0.220f, 0.60f);
    ImVec4 accent = ImVec4(0.310f, 0.440f, 0.700f, 1.0f);
    ImVec4 accentHi = ImVec4(0.380f, 0.520f, 0.780f, 1.0f);
    ImVec4 accentLo = ImVec4(0.220f, 0.320f, 0.550f, 1.0f);
    ImVec4 text   = ImVec4(0.850f, 0.860f, 0.880f, 1.0f);
    ImVec4 textDim= ImVec4(0.450f, 0.460f, 0.500f, 1.0f);

    c[ImGuiCol_WindowBg]          = bg1;
    c[ImGuiCol_ChildBg]           = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg]           = ImVec4(bg0.x, bg0.y, bg0.z, 0.96f);
    c[ImGuiCol_Border]            = border;
    c[ImGuiCol_BorderShadow]      = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg]           = bg0;
    c[ImGuiCol_FrameBgHovered]    = bg2;
    c[ImGuiCol_FrameBgActive]     = bg3;
    c[ImGuiCol_TitleBg]           = bg0;
    c[ImGuiCol_TitleBgActive]     = bg0;
    c[ImGuiCol_TitleBgCollapsed]  = bg0;
    c[ImGuiCol_MenuBarBg]         = bg0;
    c[ImGuiCol_ScrollbarBg]       = bg0;
    c[ImGuiCol_ScrollbarGrab]     = bg3;
    c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.20f, 0.20f, 0.24f, 1.0f);
    c[ImGuiCol_ScrollbarGrabActive]  = accent;
    c[ImGuiCol_CheckMark]         = accent;
    c[ImGuiCol_SliderGrab]        = accent;
    c[ImGuiCol_SliderGrabActive]  = accentHi;
    c[ImGuiCol_Button]            = bg3;
    c[ImGuiCol_ButtonHovered]     = accentLo;
    c[ImGuiCol_ButtonActive]      = accent;
    c[ImGuiCol_Header]            = bg2;
    c[ImGuiCol_HeaderHovered]     = bg3;
    c[ImGuiCol_HeaderActive]      = accentLo;
    c[ImGuiCol_Separator]         = border;
    c[ImGuiCol_SeparatorHovered]  = accent;
    c[ImGuiCol_SeparatorActive]   = accentHi;
    c[ImGuiCol_ResizeGrip]        = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ResizeGripHovered] = accent;
    c[ImGuiCol_ResizeGripActive]  = accentHi;
    c[ImGuiCol_Tab]               = bg0;
    c[ImGuiCol_TabHovered]        = accentLo;
    c[ImGuiCol_TabSelected]       = bg1;
    c[ImGuiCol_TabSelectedOverline] = accent;
    c[ImGuiCol_TabDimmed]         = bg0;
    c[ImGuiCol_TabDimmedSelected] = bg1;
    c[ImGuiCol_DockingPreview]    = ImVec4(accent.x, accent.y, accent.z, 0.40f);
    c[ImGuiCol_DockingEmptyBg]    = bg0;
    c[ImGuiCol_TextSelectedBg]    = ImVec4(accent.x, accent.y, accent.z, 0.30f);
    c[ImGuiCol_Text]              = text;
    c[ImGuiCol_TextDisabled]      = textDim;
    c[ImGuiCol_TableHeaderBg]     = bg0;
    c[ImGuiCol_TableBorderStrong] = border;
    c[ImGuiCol_TableBorderLight]  = ImVec4(border.x, border.y, border.z, 0.30f);
    c[ImGuiCol_TableRowBg]        = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt]     = ImVec4(1, 1, 1, 0.015f);
}

namespace col {
    // function name colors by type
    static const ImVec4 func_import  = ImVec4(0.95f, 0.65f, 0.30f, 1.0f);  // warm orange
    static const ImVec4 func_export  = ImVec4(0.30f, 0.90f, 0.55f, 1.0f);  // mint green
    static const ImVec4 func_user    = ImVec4(0.55f, 0.75f, 0.95f, 1.0f);  // light blue
    static const ImVec4 func_local   = ImVec4(0.72f, 0.73f, 0.76f, 1.0f);  // neutral gray
    static const ImVec4 func_entry   = ImVec4(0.95f, 0.40f, 0.40f, 1.0f);  // red for _entry

    // disassembly mnemonic colors
    static const ImVec4 mn_call      = ImVec4(0.95f, 0.75f, 0.30f, 1.0f);  // gold
    static const ImVec4 mn_jump      = ImVec4(0.40f, 0.82f, 0.45f, 1.0f);  // green
    static const ImVec4 mn_ret       = ImVec4(0.90f, 0.35f, 0.35f, 1.0f);  // red
    static const ImVec4 mn_nop       = ImVec4(0.30f, 0.30f, 0.35f, 1.0f);  // dim
    static const ImVec4 mn_stack     = ImVec4(0.60f, 0.50f, 0.80f, 1.0f);  // purple (push/pop)
    static const ImVec4 mn_mov       = ImVec4(0.50f, 0.70f, 0.85f, 1.0f);  // sky blue
    static const ImVec4 mn_math      = ImVec4(0.80f, 0.65f, 0.55f, 1.0f);  // tan
    static const ImVec4 mn_cmp       = ImVec4(0.75f, 0.80f, 0.40f, 1.0f);  // yellow-green
    static const ImVec4 mn_default   = ImVec4(0.78f, 0.78f, 0.80f, 1.0f);

    // operand sub-colors
    static const ImVec4 op_default   = ImVec4(0.72f, 0.73f, 0.76f, 1.0f);
    static const ImVec4 op_register  = ImVec4(0.60f, 0.75f, 0.90f, 1.0f);  // register refs
    static const ImVec4 op_immediate = ImVec4(0.75f, 0.60f, 0.85f, 1.0f);  // immediates

    // general semantic
    static const ImVec4 addr         = ImVec4(0.35f, 0.50f, 0.75f, 1.0f);  // address column
    static const ImVec4 hex_bytes    = ImVec4(0.30f, 0.30f, 0.35f, 1.0f);  // raw hex bytes
    static const ImVec4 accent       = ImVec4(0.40f, 0.55f, 0.85f, 1.0f);  // brand accent
    static const ImVec4 dim          = ImVec4(0.35f, 0.36f, 0.40f, 1.0f);  // dimmed text
    static const ImVec4 info         = ImVec4(0.50f, 0.51f, 0.55f, 1.0f);  // secondary info
    static const ImVec4 separator    = ImVec4(0.50f, 0.50f, 0.55f, 1.0f);  // pipe separators

    // string panel
    static const ImVec4 str_ascii    = ImVec4(0.70f, 0.80f, 0.65f, 1.0f);  // green tint
    static const ImVec4 str_wide     = ImVec4(0.70f, 0.65f, 0.30f, 1.0f);  // W marker
    static const ImVec4 str_narrow   = ImVec4(0.40f, 0.40f, 0.45f, 1.0f);  // A marker

    // hex panel
    static const ImVec4 hex_data     = ImVec4(0.55f, 0.56f, 0.60f, 1.0f);
    static const ImVec4 hex_ascii    = ImVec4(0.50f, 0.60f, 0.50f, 1.0f);

    // decompiler
    static const ImVec4 decomp_ok    = ImVec4(0.30f, 0.65f, 0.40f, 1.0f);  // (C) marker
    static const ImVec4 decomp_code  = ImVec4(0.75f, 0.80f, 0.70f, 1.0f);  // C pseudocode
    static const ImVec4 error        = ImVec4(0.90f, 0.35f, 0.35f, 1.0f);

    // status / chrome
    static const ImVec4 status_text  = ImVec4(0.45f, 0.46f, 0.50f, 1.0f);
    static const ImVec4 chrome_bg    = ImVec4(0.047f, 0.047f, 0.059f, 1.0f);

    // tag badges
    static const ImVec4 tag_import   = ImVec4(0.95f, 0.65f, 0.30f, 1.0f);
    static const ImVec4 tag_export   = ImVec4(0.30f, 0.90f, 0.55f, 1.0f);
    static const ImVec4 tag_user     = ImVec4(0.55f, 0.75f, 0.95f, 1.0f);
    static const ImVec4 tag_local    = ImVec4(0.60f, 0.60f, 0.65f, 1.0f);
    static const ImVec4 tag_crypto   = ImVec4(0.90f, 0.50f, 0.70f, 1.0f);  // pink for crypto
    static const ImVec4 tag_packed   = ImVec4(0.95f, 0.35f, 0.35f, 1.0f);  // red for packed
    static const ImVec4 tag_entropy  = ImVec4(0.65f, 0.55f, 0.90f, 1.0f);  // purple for entropy
}

static ImVec4 func_name_color(const Function& f) {
    if (f.name == "_entry")  return col::func_entry;
    if (f.is_import)         return col::func_import;
    if (f.is_export)         return col::func_export;
    if (f.user_named)        return col::func_user;
    return col::func_local;
}

static void draw_titlebar(AppState& state) {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    float titlebar_h = 32.0f;

    ImGui::SetNextWindowPos(vp->Pos);
    ImGui::SetNextWindowSize(ImVec2(vp->Size.x, titlebar_h));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, col::chrome_bg);

    ImGui::Begin("##Titlebar", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBringToFrontOnFocus);

    float y_center = (titlebar_h - ImGui::GetFontSize()) * 0.5f;
    ImGui::SetCursorPosY(y_center);
    ImGui::TextColored(col::accent, "AiDA");
    ImGui::SameLine();
    ImGui::SetCursorPosY(y_center);
    ImGui::TextColored(col::dim, "v2.0");

    if (state.image) {
        auto& img = *state.image;
        ImGui::SameLine(0, 20);
        ImGui::SetCursorPosY(y_center);
        ImGui::TextColored(col::info, "%s", img.filename.c_str());
        ImGui::SameLine(0, 12);
        ImGui::SetCursorPosY(y_center);
        ImGui::TextColored(col::dim, "|");
        ImGui::SameLine(0, 12);
        ImGui::SetCursorPosY(y_center);
        ImGui::TextColored(col::info, "%d-bit",
            arch_bits(img.arch));
        ImGui::SameLine(0, 12);
        ImGui::SetCursorPosY(y_center);
        ImGui::TextColored(col::dim, "|");
        ImGui::SameLine(0, 12);
        ImGui::SetCursorPosY(y_center);
        ImGui::TextColored(col::info, "%zu funcs  %zu strings",
            img.functions.size(), img.strings.size());
    }

    float btn_w = 46.0f;
    float btn_start = vp->Size.x - btn_w * 3 - 8.0f;

    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.2f, 0.25f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.3f, 0.3f, 0.35f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0);

    ImGui::SetCursorPos(ImVec2(btn_start, 0));
    if (ImGui::Button("_", ImVec2(btn_w, titlebar_h)))
        glfwIconifyWindow(g_window);
    ImGui::SameLine(0, 0);
    if (ImGui::Button(g_maximized ? "[]" : "[ ]", ImVec2(btn_w, titlebar_h))) {
        if (g_maximized) glfwRestoreWindow(g_window);
        else glfwMaximizeWindow(g_window);
        g_maximized = !g_maximized;
    }
    ImGui::SameLine(0, 0);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.70f, 0.15f, 0.15f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.85f, 0.20f, 0.20f, 1.0f));
    if (ImGui::Button("X", ImVec2(btn_w, titlebar_h)))
        glfwSetWindowShouldClose(g_window, 1);
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(3);

    // drag to move window
    ImVec2 mouse = ImGui::GetMousePos();
    float btn_abs_x = vp->Pos.x + 8.0f + btn_start;
    bool in_titlebar = mouse.y >= vp->Pos.y && mouse.y < vp->Pos.y + titlebar_h &&
                       mouse.x < btn_abs_x;
    if (in_titlebar && ImGui::IsMouseClicked(0)) {
        g_dragging = true;
        double mx, my;
        glfwGetCursorPos(g_window, &mx, &my);
        g_drag_x = mx;
        g_drag_y = my;
    }
    if (g_dragging && ImGui::IsMouseDown(0)) {
        double mx, my;
        glfwGetCursorPos(g_window, &mx, &my);
        int wx, wy;
        glfwGetWindowPos(g_window, &wx, &wy);
        glfwSetWindowPos(g_window, wx + (int)(mx - g_drag_x), wy + (int)(my - g_drag_y));
    }
    if (ImGui::IsMouseReleased(0)) g_dragging = false;

    // double click to maximize/restore
    if (in_titlebar && ImGui::IsMouseDoubleClicked(0)) {
        if (g_maximized) glfwRestoreWindow(g_window);
        else glfwMaximizeWindow(g_window);
        g_maximized = !g_maximized;
    }

    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
}

static void draw_functions_panel(AppState& state) {
    auto& img = *state.image;

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 6));
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##filter", "Search functions...", state.search_buf, sizeof(state.search_buf));
    ImGui::PopStyleVar();

    std::string filter(state.search_buf);

    // rebuild flat addr list only when filter or image changes
    if (g_func_cache.last_filter != filter ||
        g_func_cache.last_func_count != img.functions.size() ||
        g_func_cache.last_image != &img) {
        g_func_cache.addrs.clear();
        g_func_cache.addrs.reserve(img.functions.size());
        for (auto& [addr, f] : img.functions) {
            if (filter.empty() || f.name.find(filter) != std::string::npos)
                g_func_cache.addrs.push_back(addr);
        }
        g_func_cache.last_filter = filter;
        g_func_cache.last_func_count = img.functions.size();
        g_func_cache.last_image = &img;
    }

    ImGui::Spacing();
    ImGui::TextColored(col::dim, "%zu functions", g_func_cache.addrs.size());
    ImGui::Spacing();

    ImGui::BeginChild("FuncList", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_None);

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(g_func_cache.addrs.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
            uint64_t addr = g_func_cache.addrs[i];
            auto fit = img.functions.find(addr);
            if (fit == img.functions.end()) continue;
            auto& f = fit->second;

            bool selected = (state.selected_addr == addr);
            ImVec4 name_col = func_name_color(f);

            if (selected)
                ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0.22f, 0.32f, 0.55f, 0.60f));

            ImGui::PushStyleColor(ImGuiCol_Text, name_col);
            char label[320];
            snprintf(label, sizeof(label), "  %s##%llu", f.name.c_str(), (unsigned long long)addr);

            if (ImGui::Selectable(label, selected, ImGuiSelectableFlags_SpanAllColumns)) {
                state.selected_addr = addr;
                state.selected_func_idx = i;

                if (f.instructions.empty() && !f.is_import) {
                    f.instructions = disassemble_function(img, addr);
                    if (!f.instructions.empty()) {
                        auto& last = f.instructions.back();
                        f.end_addr = last.addr + last.size;
                    }
                }
            }

            ImGui::PopStyleColor();
            if (selected) ImGui::PopStyleColor();

            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::TextColored(col::addr, "0x%llX", (unsigned long long)addr);
                ImGui::SameLine();
                ImGui::TextColored(col::separator, "|");
                ImGui::SameLine();
                ImGui::Text("%zu insns", f.instructions.size());
                ImGui::SameLine();
                ImGui::TextColored(col::separator, "|");
                ImGui::SameLine();
                if (f.is_import)        ImGui::TextColored(col::tag_import, "import");
                else if (f.is_export)   ImGui::TextColored(col::tag_export, "export");
                else if (f.user_named)  ImGui::TextColored(col::tag_user, "renamed");
                else                    ImGui::TextColored(col::tag_local, "local");
                ImGui::EndTooltip();
            }
        }
    }

    ImGui::EndChild();
}

static void draw_disasm_panel(AppState& state) {
    auto& img = *state.image;
    auto it = img.functions.find(state.selected_addr);
    if (it == img.functions.end()) {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImVec2 text_size = ImGui::CalcTextSize("Select a function");
        ImGui::SetCursorPos(ImVec2(
            (avail.x - text_size.x) * 0.5f,
            (avail.y - text_size.y) * 0.5f));
        ImGui::TextColored(col::dim, "Select a function");
        return;
    }

    auto& func = it->second;

    ImGui::TextColored(func_name_color(func), "%s", func.name.c_str());
    ImGui::SameLine();
    ImGui::TextColored(col::dim, "@ 0x%llX", (unsigned long long)func.addr);
    if (func.end_addr > func.addr) {
        ImGui::SameLine(0, 16);
        ImGui::TextColored(col::dim, "%llu bytes  %zu insns",
            (unsigned long long)(func.end_addr - func.addr), func.instructions.size());
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::BeginChild("DisasmScroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    float addr_col = 0;
    float hex_col = 110;
    float mn_col = 330;
    float op_col = 410;

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(func.instructions.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
            auto& inst = func.instructions[i];

            ImGui::SetCursorPosX(addr_col);
            ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)inst.addr);

            ImGui::SameLine(hex_col);
            char hex[64] = {};
            int pos = 0;
            for (size_t b = 0; b < inst.bytes.size() && pos + 3 < 64; b++)
                pos += snprintf(hex + pos, 64 - pos, "%02X ", inst.bytes[b]);
            ImGui::TextColored(col::hex_bytes, "%-24s", hex);

            const auto& mn = inst.mnemonic;
            bool is_call = (mn == "call" || mn == "jal" || mn == "bal" || mn == "bl" || mn == "jalr");
            bool is_jmp = (!is_call && (mn[0] == 'j' || (mn[0] == 'b' && mn != "break")));
            bool is_ret = (mn == "ret" || mn == "retn");
            bool is_nop = (mn == "nop");
            bool is_stack = (mn == "push" || mn == "pop");
            bool is_mov = (mn == "mov" || mn == "movzx" || mn == "movsx" ||
                           mn == "lea" || mn == "xchg" || mn == "cmov");
            bool is_math = (mn == "add" || mn == "sub" || mn == "mul" || mn == "imul" ||
                            mn == "div" || mn == "idiv" || mn == "inc" || mn == "dec" ||
                            mn == "shl" || mn == "shr" || mn == "sar" || mn == "xor" ||
                            mn == "or" || mn == "and" || mn == "not" || mn == "neg" ||
                            mn == "rol" || mn == "ror");
            bool is_cmp = (mn == "cmp" || mn == "test");

            ImVec4 mn_color = col::mn_default;
            if (is_call)       mn_color = col::mn_call;
            else if (is_jmp)   mn_color = col::mn_jump;
            else if (is_ret)   mn_color = col::mn_ret;
            else if (is_nop)   mn_color = col::mn_nop;
            else if (is_stack) mn_color = col::mn_stack;
            else if (is_mov)   mn_color = col::mn_mov;
            else if (is_math)  mn_color = col::mn_math;
            else if (is_cmp)   mn_color = col::mn_cmp;

            ImGui::SameLine(mn_col);
            ImGui::TextColored(mn_color, "%-8s", inst.mnemonic.c_str());

            ImGui::SameLine(op_col);
            ImGui::TextColored(col::op_default, "%s", inst.operands.c_str());

            auto cit = img.user_comments.find(inst.addr);
            if (cit != img.user_comments.end()) {
                ImGui::SameLine(0, 16);
                ImGui::TextColored(col::decomp_ok, "; %s", cit->second.c_str());
            }
        }
    }

    ImGui::EndChild();
}

static void draw_xrefs_panel(AppState& state) {
    auto& img = *state.image;
    if (state.selected_addr == 0) {
        ImGui::TextColored(col::dim, "Select a function to see xrefs");
        return;
    }

    auto it = img.functions.find(state.selected_addr);
    if (it == img.functions.end()) return;

    if (g_xref_cache.cached_addr != state.selected_addr) {
        g_xref_cache.cached_addr = state.selected_addr;
        g_xref_cache.to_refs.clear();
        g_xref_cache.from_refs.clear();

        uint64_t func_end = it->second.end_addr;

        // O(1) lookup for "to" refs via pre-built index
        auto idx_it = img.xref_to_idx.find(state.selected_addr);
        if (idx_it != img.xref_to_idx.end()) {
            for (uint32_t xi : idx_it->second) {
                auto& xr = img.xrefs[xi];
                const char* ts = xr.type == XrefType::Call ? "call" :
                                 xr.type == XrefType::Jump ? "jmp" : "data";
                std::string caller_name;
                ImVec4 caller_col = col::func_local;
                auto prev = img.functions.upper_bound(xr.from);
                if (prev != img.functions.begin()) {
                    --prev;
                    caller_name = prev->second.name;
                    caller_col = func_name_color(prev->second);
                }
                g_xref_cache.to_refs.push_back({xr.from, ts, caller_name, caller_col});
            }
        }

        // Binary search for "from" refs (xrefs sorted by from addr)
        Xref lo_key; lo_key.from = state.selected_addr;
        auto from_begin = std::lower_bound(img.xrefs.begin(), img.xrefs.end(), lo_key,
            [](const Xref& a, const Xref& b) { return a.from < b.from; });
        uint64_t range_end = (func_end > 0) ? func_end : state.selected_addr + 1;
        for (auto xit = from_begin; xit != img.xrefs.end() && xit->from < range_end; ++xit) {
            const char* ts = xit->type == XrefType::Call ? "call" :
                             xit->type == XrefType::Jump ? "jmp" : "data";
            std::string tgt_name;
            ImVec4 tgt_col = col::func_local;
            auto tgt = img.functions.find(xit->to);
            if (tgt != img.functions.end()) {
                tgt_name = tgt->second.name;
                tgt_col = func_name_color(tgt->second);
            }
            g_xref_cache.from_refs.push_back({xit->to, ts, tgt_name, tgt_col});
        }
    }

    ImGui::TextColored(func_name_color(it->second), "%s", it->second.name.c_str());
    ImGui::SameLine();
    ImGui::TextColored(col::dim, "(%zu to, %zu from)",
        g_xref_cache.to_refs.size(), g_xref_cache.from_refs.size());
    ImGui::Spacing();
    ImGui::Separator();

    ImGui::TextColored(col::accent, "References TO this function:");
    ImGui::Spacing();
    ImGui::BeginChild("XrefsTo", ImVec2(0, ImGui::GetContentRegionAvail().y * 0.45f));
    ImGuiListClipper clip_to;
    clip_to.Begin(static_cast<int>(g_xref_cache.to_refs.size()));
    while (clip_to.Step()) {
        for (int i = clip_to.DisplayStart; i < clip_to.DisplayEnd; i++) {
            auto& e = g_xref_cache.to_refs[i];
            ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)e.addr);
            ImGui::SameLine(120);
            ImGui::TextColored(col::mn_call, "%s", e.type.c_str());
            ImGui::SameLine(180);
            if (!e.name.empty())
                ImGui::TextColored(e.color, "%s", e.name.c_str());
        }
    }
    ImGui::EndChild();

    ImGui::Separator();
    ImGui::TextColored(col::accent, "References FROM this function:");
    ImGui::Spacing();
    ImGui::BeginChild("XrefsFrom", ImVec2(0, 0));
    ImGuiListClipper clip_from;
    clip_from.Begin(static_cast<int>(g_xref_cache.from_refs.size()));
    while (clip_from.Step()) {
        for (int i = clip_from.DisplayStart; i < clip_from.DisplayEnd; i++) {
            auto& e = g_xref_cache.from_refs[i];
            ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)e.addr);
            ImGui::SameLine(120);
            ImGui::TextColored(col::mn_call, "%s", e.type.c_str());
            ImGui::SameLine(180);
            if (!e.name.empty())
                ImGui::TextColored(e.color, "%s", e.name.c_str());
        }
    }
    ImGui::EndChild();
}

static void draw_imports_panel(AppState& state) {
    auto& img = *state.image;
    static char imp_filter[128] = {};
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 6));
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##impfilter", "Search imports...", imp_filter, sizeof(imp_filter));
    ImGui::PopStyleVar();
    std::string filter(imp_filter);
    ImGui::Spacing();

    std::vector<size_t> filtered;
    filtered.reserve(img.imports.size());
    for (size_t i = 0; i < img.imports.size(); i++) {
        if (filter.empty() || img.imports[i].name.find(filter) != std::string::npos ||
            img.imports[i].module.find(filter) != std::string::npos)
            filtered.push_back(i);
    }

    ImGuiTableFlags tflags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                             ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV |
                             ImGuiTableFlags_SizingStretchProp;
    if (ImGui::BeginTable("ImportsTbl", 3, tflags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch, 0.55f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered.size()));
        while (clipper.Step()) {
            for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
                auto& imp = img.imports[filtered[j]];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(col::tag_import, "%s", imp.module.c_str());
                ImGui::TableNextColumn();
                ImGui::TextColored(col::func_import, "%s", imp.name.c_str());
                ImGui::TableNextColumn();
                if (imp.iat_rva)
                    ImGui::TextColored(col::addr, "0x%llX", (unsigned long long)(img.base + imp.iat_rva));
            }
        }
        ImGui::EndTable();
    }
}

static void draw_exports_panel(AppState& state) {
    auto& img = *state.image;
    ImGuiTableFlags tflags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                             ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV |
                             ImGuiTableFlags_SizingStretchProp;
    if (ImGui::BeginTable("ExportsTbl", 4, tflags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 0.20f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 0.45f);
        ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthStretch, 0.10f);
        ImGui::TableSetupColumn("Forward", ImGuiTableColumnFlags_WidthStretch, 0.25f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(img.exports.size()));
        while (clipper.Step()) {
            for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
                auto& exp = img.exports[j];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)(img.base + exp.rva));
                ImGui::TableNextColumn();
                ImGui::TextColored(col::func_export, "%s", exp.name.c_str());
                ImGui::TableNextColumn();
                ImGui::TextColored(col::dim, "%d", exp.ordinal);
                ImGui::TableNextColumn();
                if (exp.forwarded)
                    ImGui::TextColored(col::tag_import, "-> %s", exp.forward_name.c_str());
            }
        }
        ImGui::EndTable();
    }
}

static void draw_network_panel(AppState& state) {
    auto& img = *state.image;

    if (img.network_refs.empty()) {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImVec2 text_size = ImGui::CalcTextSize("No network references found");
        ImGui::SetCursorPos(ImVec2(
            (avail.x - text_size.x) * 0.5f,
            (avail.y - text_size.y) * 0.5f));
        ImGui::TextColored(col::dim, "No network references found");
        return;
    }

    static char net_filter[128] = {};
    static int type_filter = 0;
    const char* types[] = { "All", "url", "ipv4", "domain", "email", "mac", "port" };

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 6));
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##netfilter", "Search...", net_filter, sizeof(net_filter));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100);
    ImGui::Combo("##nettype", &type_filter, types, IM_ARRAYSIZE(types));
    ImGui::PopStyleVar();

    ImGui::SameLine();
    ImGui::TextColored(col::dim, "%zu refs", img.network_refs.size());
    ImGui::Spacing();

    std::string filter(net_filter);
    std::string tfilter = type_filter > 0 ? types[type_filter] : "";

    ImGui::BeginChild("NetList", ImVec2(0, 0));
    for (auto& nr : img.network_refs) {
        if (!tfilter.empty() && nr.type != tfilter) continue;
        if (!filter.empty() && nr.value.find(filter) == std::string::npos) continue;

        ImVec4 type_col = col::accent;
        if (nr.type == "url")         type_col = col::mn_call;
        else if (nr.type == "ipv4")   type_col = col::mn_jump;
        else if (nr.type == "domain") type_col = col::func_export;
        else if (nr.type == "email")  type_col = col::tag_crypto;
        else if (nr.type == "mac")    type_col = col::tag_entropy;
        else if (nr.type == "port")   type_col = col::mn_ret;

        ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)nr.addr);
        ImGui::SameLine(120);
        ImGui::TextColored(type_col, "%-7s", nr.type.c_str());
        ImGui::SameLine(200);
        ImGui::TextColored(col::str_ascii, "%s", nr.value.c_str());
    }
    ImGui::EndChild();
}

static void draw_bookmarks_panel(AppState& state) {
    auto& img = *state.image;

    if (state.selected_addr != 0) {
        bool already = false;
        for (auto a : img.bookmarks)
            if (a == state.selected_addr) { already = true; break; }
        if (!already) {
            if (ImGui::Button("Bookmark Selected")) {
                img.bookmarks.push_back(state.selected_addr);
            }
        }
    }

    if (img.bookmarks.empty()) {
        ImGui::TextColored(col::dim, "No bookmarks yet");
        return;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    int to_remove = -1;
    for (int i = 0; i < (int)img.bookmarks.size(); i++) {
        uint64_t addr = img.bookmarks[i];
        ImGui::PushID(i);

        auto fit = img.functions.find(addr);
        if (fit != img.functions.end()) {
            ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)addr);
            ImGui::SameLine(120);
            ImGui::TextColored(func_name_color(fit->second), "%s", fit->second.name.c_str());
        } else {
            ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)addr);
        }

        auto cit = img.user_comments.find(addr);
        if (cit != img.user_comments.end()) {
            ImGui::SameLine(350);
            ImGui::TextColored(col::decomp_ok, "; %s", cit->second.c_str());
        }

        ImGui::SameLine(ImGui::GetWindowWidth() - 40);
        if (ImGui::SmallButton("X")) to_remove = i;

        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
            state.selected_addr = addr;
        }

        ImGui::PopID();
    }

    if (to_remove >= 0)
        img.bookmarks.erase(img.bookmarks.begin() + to_remove);
}

static void draw_firmware_panel(AppState& state) {
    auto& img = *state.image;

    if (ImGui::BeginTabBar("FirmwareTabs")) {
        // --- Signatures ---
        if (ImGui::BeginTabItem("Signatures")) {
            if (img.signature_hits.empty()) {
                ImGui::TextColored(col::dim, "No signatures found");
            } else {
                ImGui::TextColored(col::accent, "%zu signatures", img.signature_hits.size());
                ImGui::Spacing();
                ImGuiTableFlags tf = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                                     ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV |
                                     ImGuiTableFlags_SizingStretchProp;
                if (ImGui::BeginTable("SigTbl", 4, tf)) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthStretch, 0.15f);
                    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 0.15f);
                    ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 0.50f);
                    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthStretch, 0.20f);
                    ImGui::TableHeadersRow();
                    ImGuiListClipper clip;
                    clip.Begin(static_cast<int>(img.signature_hits.size()));
                    while (clip.Step()) {
                        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                            auto& h = img.signature_hits[i];
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            ImGui::TextColored(col::addr, "0x%llX", (unsigned long long)h.offset);
                            ImGui::TableNextColumn();
                            ImGui::TextColored(col::mn_call, "%s", h.type.c_str());
                            ImGui::TableNextColumn();
                            ImGui::Text("%s", h.description.c_str());
                            ImGui::TableNextColumn();
                            if (h.estimated_size > 0)
                                ImGui::Text("%zu bytes", h.estimated_size);
                            else
                                ImGui::TextColored(col::dim, "unknown");
                        }
                    }
                    ImGui::EndTable();
                }
            }
            ImGui::EndTabItem();
        }

        // --- Entropy Heatmap ---
        if (ImGui::BeginTabItem("Entropy")) {
            if (img.entropy_heatmap.empty()) {
                ImGui::TextColored(col::dim, "No entropy data");
            } else {
                ImGui::TextColored(col::accent, "%zu blocks (256 byte windows)", img.entropy_heatmap.size());
                ImGui::Spacing();

                // draw heatmap bar
                ImVec2 avail = ImGui::GetContentRegionAvail();
                float bar_h = 40.0f;
                ImVec2 p0 = ImGui::GetCursorScreenPos();
                ImDrawList* dl = ImGui::GetWindowDrawList();
                float block_w = avail.x / static_cast<float>(img.entropy_heatmap.size());
                if (block_w < 1.0f) block_w = 1.0f;

                for (size_t i = 0; i < img.entropy_heatmap.size(); i++) {
                    float e = img.entropy_heatmap[i].entropy / 8.0f;
                    uint8_t r = static_cast<uint8_t>(e * 255);
                    uint8_t g = static_cast<uint8_t>((1.0f - std::abs(e - 0.5f) * 2.0f) * 200);
                    uint8_t b = static_cast<uint8_t>((1.0f - e) * 255);
                    float x = p0.x + static_cast<float>(i) * block_w;
                    dl->AddRectFilled(
                        ImVec2(x, p0.y),
                        ImVec2(x + block_w, p0.y + bar_h),
                        IM_COL32(r, g, b, 255));
                }
                ImGui::Dummy(ImVec2(avail.x, bar_h + 4));

                // legend
                ImGui::TextColored(ImVec4(0.0f, 0.0f, 1.0f, 1.0f), "Low");
                ImGui::SameLine();
                ImGui::Text("-");
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "High (compressed/encrypted)");
                ImGui::Spacing();

                // scrollable detail list
                ImGui::BeginChild("EntList");
                ImGuiListClipper clip;
                clip.Begin(static_cast<int>(img.entropy_heatmap.size()));
                while (clip.Step()) {
                    for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                        auto& eb = img.entropy_heatmap[i];
                        ImVec4 ecol = (eb.entropy > 7.0f) ? col::error :
                                      (eb.entropy > 6.0f) ? ImVec4(1.0f, 0.7f, 0.0f, 1.0f) :
                                      col::decomp_ok;
                        ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)eb.offset);
                        ImGui::SameLine(120);
                        ImGui::TextColored(ecol, "%.3f", eb.entropy);
                        ImGui::SameLine(200);
                        float frac = eb.entropy / 8.0f;
                        ImGui::ProgressBar(frac, ImVec2(200, 14), "");
                    }
                }
                ImGui::EndChild();
            }
            ImGui::EndTabItem();
        }

        // --- Encoded Strings ---
        if (ImGui::BeginTabItem("Encoded")) {
            if (img.encoded_strings.empty()) {
                ImGui::TextColored(col::dim, "No encoded strings found");
            } else {
                ImGui::TextColored(col::accent, "%zu encoded strings", img.encoded_strings.size());
                ImGui::Spacing();
                ImGuiTableFlags tf = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
                                     ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV |
                                     ImGuiTableFlags_SizingStretchProp;
                if (ImGui::BeginTable("EncTbl", 4, tf)) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthStretch, 0.12f);
                    ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 0.08f);
                    ImGui::TableSetupColumn("Encoded", ImGuiTableColumnFlags_WidthStretch, 0.40f);
                    ImGui::TableSetupColumn("Decoded", ImGuiTableColumnFlags_WidthStretch, 0.40f);
                    ImGui::TableHeadersRow();
                    ImGuiListClipper clip;
                    clip.Begin(static_cast<int>(img.encoded_strings.size()));
                    while (clip.Step()) {
                        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                            auto& es = img.encoded_strings[i];
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            ImGui::TextColored(col::addr, "0x%llX", (unsigned long long)es.offset);
                            ImGui::TableNextColumn();
                            ImGui::TextColored(col::mn_call, "%s", es.encoding.c_str());
                            ImGui::TableNextColumn();
                            ImGui::TextWrapped("%s", es.encoded.c_str());
                            ImGui::TableNextColumn();
                            ImGui::TextColored(col::str_ascii, "%s", es.decoded.c_str());
                        }
                    }
                    ImGui::EndTable();
                }
            }
            ImGui::EndTabItem();
        }

        // --- Certificates ---
        if (ImGui::BeginTabItem("Certs/Keys")) {
            if (img.certificate_hits.empty()) {
                ImGui::TextColored(col::dim, "No certificates or keys found");
            } else {
                ImGui::TextColored(col::accent, "%zu certificates/keys", img.certificate_hits.size());
                ImGui::Spacing();
                for (size_t i = 0; i < img.certificate_hits.size(); i++) {
                    auto& ch = img.certificate_hits[i];
                    ImGui::PushID(static_cast<int>(i));
                    ImGui::TextColored(col::addr, "0x%llX", (unsigned long long)ch.offset);
                    ImGui::SameLine(120);
                    ImGui::TextColored(col::error, "%s", ch.type.c_str());
                    ImGui::SameLine(320);
                    ImGui::TextColored(col::dim, "%zu bytes", ch.size);
                    if (ImGui::TreeNode("Details")) {
                        ImGui::TextWrapped("%s", ch.details.c_str());
                        ImGui::TreePop();
                    }
                    ImGui::Separator();
                    ImGui::PopID();
                }
            }
            ImGui::EndTabItem();
        }

        // --- Firmware Headers ---
        if (ImGui::BeginTabItem("FW Headers")) {
            if (img.firmware_headers.empty()) {
                ImGui::TextColored(col::dim, "No firmware headers found");
            } else {
                ImGui::TextColored(col::accent, "%zu firmware headers", img.firmware_headers.size());
                ImGui::Spacing();
                for (size_t i = 0; i < img.firmware_headers.size(); i++) {
                    auto& fh = img.firmware_headers[i];
                    ImGui::PushID(static_cast<int>(i));
                    ImGui::TextColored(col::addr, "0x%llX", (unsigned long long)fh.offset);
                    ImGui::SameLine(120);
                    ImGui::TextColored(col::mn_call, "%s", fh.type.c_str());
                    ImGui::TextWrapped("%s", fh.details.c_str());
                    ImGui::Separator();
                    ImGui::PopID();
                }
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }
}

static void draw_strings_panel(AppState& state) {
    auto& img = *state.image;

    static char str_filter[128] = {};
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 6));
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##strfilter", "Search strings...", str_filter, sizeof(str_filter));
    ImGui::PopStyleVar();

    std::string filter(str_filter);
    ImGui::Spacing();

    ImGui::BeginChild("StringList", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    std::vector<size_t> filtered;
    filtered.reserve(img.strings.size());
    for (size_t i = 0; i < img.strings.size(); i++) {
        if (filter.empty() || img.strings[i].value.find(filter) != std::string::npos)
            filtered.push_back(i);
    }

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(filtered.size()));
    while (clipper.Step()) {
        for (int j = clipper.DisplayStart; j < clipper.DisplayEnd; j++) {
            auto& s = img.strings[filtered[j]];
            ImGui::TextColored(col::addr, "0x%08llX", (unsigned long long)s.addr);
            ImGui::SameLine(120);
            if (s.wide)
                ImGui::TextColored(col::str_wide, "W");
            else
                ImGui::TextColored(col::str_narrow, "A");
            ImGui::SameLine(140);
            ImGui::TextColored(col::str_ascii, "%s", s.value.c_str());
        }
    }

    ImGui::EndChild();
}

static void draw_decomp_panel(AppState& state) {
#ifdef AIDA_HAS_DECOMP
    if (!state.decompiler) {
        ImGui::TextColored(col::dim, "Decompiler not available");
        return;
    }

    // progress bar while background decompilation runs
    size_t dc_done = g_decomp_cache.done_count.load(std::memory_order_acquire);
    size_t dc_total = g_decomp_cache.total_count.load(std::memory_order_acquire);
    if (dc_total > 0 && dc_done < dc_total) {
        float frac = static_cast<float>(dc_done) / static_cast<float>(dc_total);
        char overlay[64];
        snprintf(overlay, sizeof(overlay), "Decompiling %zu / %zu", dc_done, dc_total);
        ImGui::ProgressBar(frac, ImVec2(-1, 0), overlay);
        ImGui::Spacing();
    }

    if (state.selected_addr == 0) {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImVec2 text_size = ImGui::CalcTextSize("Select a function");
        ImGui::SetCursorPos(ImVec2(
            (avail.x - text_size.x) * 0.5f,
            (avail.y - text_size.y) * 0.5f));
        ImGui::TextColored(col::dim, "Select a function");
        return;
    }

    auto it = state.image->functions.find(state.selected_addr);
    if (it == state.image->functions.end() || it->second.is_import) {
        ImGui::TextColored(col::dim, "Cannot decompile this function");
        return;
    }

    if (state.decomp_cached_addr != state.selected_addr) {
        DecompResult cached;
        if (g_decomp_cache.lookup(state.selected_addr, cached)) {
            state.decomp_cached_addr = state.selected_addr;
            if (cached.ok) {
                state.decomp_cached_code = cached.code;
                state.decomp_has_error = false;
            } else {
                state.decomp_cached_code = cached.error;
                state.decomp_has_error = true;
            }
        } else {
            ImGui::TextColored(col::dim, "Decompiling...");
            return;
        }
    }

    ImGui::TextColored(func_name_color(it->second), "%s", it->second.name.c_str());
    ImGui::SameLine();
    if (state.decomp_has_error)
        ImGui::TextColored(col::error, "(error)");
    else
        ImGui::TextColored(col::decomp_ok, "(C)");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::BeginChild("DecompScroll", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    if (state.decomp_has_error)
        ImGui::TextColored(col::error, "%s", state.decomp_cached_code.c_str());
    else
        ImGui::TextColored(col::decomp_code, "%s", state.decomp_cached_code.c_str());

    ImGui::EndChild();
#else
    ImGui::TextColored(col::dim, "Decompiler not compiled in");
#endif
}

static void draw_hex_panel(AppState& state) {
    auto& img = *state.image;
    if (state.selected_addr == 0) {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImVec2 text_size = ImGui::CalcTextSize("Select a function to view hex");
        ImGui::SetCursorPos(ImVec2(
            (avail.x - text_size.x) * 0.5f,
            (avail.y - text_size.y) * 0.5f));
        ImGui::TextColored(col::dim, "Select a function to view hex");
        return;
    }

    size_t avail = 0;
    const uint8_t* bytes = img.bytes_at_va(state.selected_addr, &avail);
    if (!bytes || avail == 0) {
        ImGui::TextColored(col::dim, "No data at selected address");
        return;
    }

    size_t show = std::min<size_t>(avail, 0x1000);
    ImGui::BeginChild("HexView", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    ImGuiListClipper clipper;
    int rows = (int)((show + 15) / 16);
    clipper.Begin(rows);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++) {
            size_t off = (size_t)row * 16;
            ImGui::TextColored(col::addr, "%08llX",
                (unsigned long long)(state.selected_addr + off));
            ImGui::SameLine(100);

            char hex_part[64] = {};
            char ascii_part[20] = {};
            int hp = 0;
            size_t count = std::min<size_t>(16, show - off);
            for (size_t i = 0; i < count; i++) {
                uint8_t b = bytes[off + i];
                hp += snprintf(hex_part + hp, sizeof(hex_part) - hp, "%02X ", b);
                ascii_part[i] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
            }
            ascii_part[count] = 0;

            ImGui::TextColored(col::hex_data, "%-48s", hex_part);
            ImGui::SameLine(560);
            ImGui::TextColored(col::hex_ascii, "%s", ascii_part);
        }
    }

    ImGui::EndChild();
}

static void draw_notes_panel(AppState& state) {
    ImGui::TextColored(col::accent, "Shared Notes");
    ImGui::SameLine();
    ImGui::TextColored(col::dim, "(AI + Human)");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

#ifdef AIDA_HAS_MCP
    if (state.mcp_session) {
        std::lock_guard<std::mutex> lock(state.mcp_session->mtx);
        size_t len = state.mcp_session->notes.size();
        if (len < sizeof(state.notes_input)) {
            if (strcmp(state.notes_input, state.mcp_session->notes.c_str()) != 0 &&
                !ImGui::IsItemActive()) {
                memcpy(state.notes_input, state.mcp_session->notes.c_str(), len + 1);
            }
        }
    }
#endif

    ImVec2 avail = ImGui::GetContentRegionAvail();
    if (ImGui::InputTextMultiline("##notes", state.notes_input, sizeof(state.notes_input),
            ImVec2(avail.x, avail.y), ImGuiInputTextFlags_AllowTabInput)) {
#ifdef AIDA_HAS_MCP
        if (state.mcp_session) {
            std::lock_guard<std::mutex> lock(state.mcp_session->mtx);
            state.mcp_session->notes = state.notes_input;
        }
#endif
    }
}

static void draw_statusbar(AppState& state) {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    float bar_h = 24.0f;
    ImGui::SetNextWindowPos(ImVec2(vp->Pos.x, vp->Pos.y + vp->Size.y - bar_h));
    ImGui::SetNextWindowSize(ImVec2(vp->Size.x, bar_h));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 3));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, col::chrome_bg);

    ImGui::Begin("##StatusBar", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBringToFrontOnFocus);

    float text_y = (bar_h - ImGui::GetFontSize()) * 0.5f;
    ImGui::SetCursorPosY(text_y);
    ImGui::TextColored(col::status_text, "%s", state.status_msg.c_str());

    // right-aligned items: measure widths, lay out from right edge
    float right_edge = ImGui::GetWindowWidth() - 14;
    float spacing = 16.0f;

    if (state.mcp_port > 0) {
        char mcp_label[64];
        snprintf(mcp_label, sizeof(mcp_label), "MCP @ 127.0.0.1:%d", state.mcp_port);
        float mcp_w = ImGui::CalcTextSize(mcp_label).x;
        right_edge -= mcp_w;
        ImGui::SameLine(right_edge);
        ImGui::SetCursorPosY(text_y);
        ImGui::TextColored(col::decomp_ok, "%s", mcp_label);
        right_edge -= spacing;
    }

    if (state.image) {
        float btn_w = ImGui::CalcTextSize("Save").x + 16;
        right_edge -= btn_w;
        ImGui::SameLine(right_edge);
        ImGui::SetCursorPosY(text_y - 1);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.30f, 0.15f, 0.80f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.45f, 0.20f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.25f, 0.55f, 0.25f, 1.0f));
        if (ImGui::SmallButton("Save")) {
            std::string db_path = state.image->path + ".aida";
            save_project(*state.image, db_path);
            state.status_msg = "Saved: " + db_path;
        }
        ImGui::PopStyleColor(3);
    }

    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
}

static void build_default_layout(ImGuiID dockspace_id) {
    ImGui::DockBuilderRemoveNode(dockspace_id);
    ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);

    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::DockBuilderSetNodeSize(dockspace_id, vp->Size);

    ImGuiID left, center;
    ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Left, 0.22f, &left, &center);

    ImGuiID main_area, bottom;
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.25f, &bottom, &main_area);

    ImGuiID left_top, left_bottom;
    ImGui::DockBuilderSplitNode(left, ImGuiDir_Down, 0.30f, &left_bottom, &left_top);

    ImGui::DockBuilderDockWindow("Functions", left_top);
    ImGui::DockBuilderDockWindow("Bookmarks", left_bottom);
    ImGui::DockBuilderDockWindow("Disassembly", main_area);
    ImGui::DockBuilderDockWindow("Decompiler", main_area);
    ImGui::DockBuilderDockWindow("Notes", main_area);
    ImGui::DockBuilderDockWindow("Xrefs", main_area);
    ImGui::DockBuilderDockWindow("Strings", main_area);
    ImGui::DockBuilderDockWindow("Imports", main_area);
    ImGui::DockBuilderDockWindow("Exports", main_area);
    ImGui::DockBuilderDockWindow("Network", main_area);
    ImGui::DockBuilderDockWindow("Hex View", bottom);

    ImGuiDockNodeFlags node_flags = ImGuiDockNodeFlags_NoCloseButton | ImGuiDockNodeFlags_NoWindowMenuButton;
    ImGuiDockNode* n;
    n = ImGui::DockBuilderGetNode(left_top);    if (n) n->LocalFlags |= node_flags;
    n = ImGui::DockBuilderGetNode(left_bottom); if (n) n->LocalFlags |= node_flags;
    n = ImGui::DockBuilderGetNode(main_area);   if (n) n->LocalFlags |= node_flags;
    n = ImGui::DockBuilderGetNode(bottom);      if (n) n->LocalFlags |= node_flags;

    ImGui::DockBuilderFinish(dockspace_id);
}

static void draw_drop_zone(AppState& state) {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    float titlebar_h = 32.0f;
    float statusbar_h = 24.0f;

    ImGui::SetNextWindowPos(ImVec2(vp->Pos.x, vp->Pos.y + titlebar_h));
    ImGui::SetNextWindowSize(ImVec2(vp->Size.x, vp->Size.y - titlebar_h - statusbar_h));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##DropZone", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoSavedSettings);
    ImGui::PopStyleVar();

    ImVec2 avail = ImGui::GetContentRegionAvail();
    float cx = avail.x * 0.5f;
    float cy = avail.y * 0.5f;

    const char* line1 = "Drop a binary here";
    const char* line2 = "PE / ELF / Raw";
    ImVec2 t1 = ImGui::CalcTextSize(line1);
    ImVec2 t2 = ImGui::CalcTextSize(line2);
    float font_h = ImGui::GetFontSize();
    float btn_w = 120.0f, btn_h = 30.0f;
    float gap = 12.0f;

    float content_h = font_h + gap + font_h + gap * 2 + btn_h;
    float box_pad = 40.0f;
    float box_w = std::max({t1.x, t2.x, btn_w}) + box_pad * 2;
    float box_h = content_h + box_pad * 2;

    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 box_min(wp.x + cx - box_w * 0.5f, wp.y + cy - box_h * 0.5f);
    ImVec2 box_max(box_min.x + box_w, box_min.y + box_h);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 border_col = IM_COL32(80, 112, 180, 100);
    float dash = 8.0f;
    for (float x = box_min.x; x < box_max.x; x += dash * 2)
        dl->AddLine(ImVec2(x, box_min.y), ImVec2(std::min(x + dash, box_max.x), box_min.y), border_col, 2.0f);
    for (float x = box_min.x; x < box_max.x; x += dash * 2)
        dl->AddLine(ImVec2(x, box_max.y), ImVec2(std::min(x + dash, box_max.x), box_max.y), border_col, 2.0f);
    for (float y = box_min.y; y < box_max.y; y += dash * 2)
        dl->AddLine(ImVec2(box_min.x, y), ImVec2(box_min.x, std::min(y + dash, box_max.y)), border_col, 2.0f);
    for (float y = box_min.y; y < box_max.y; y += dash * 2)
        dl->AddLine(ImVec2(box_max.x, y), ImVec2(box_max.x, std::min(y + dash, box_max.y)), border_col, 2.0f);

    float top_y = cy - content_h * 0.5f;

    ImGui::SetCursorPos(ImVec2(cx - t1.x * 0.5f, top_y));
    ImGui::TextColored(col::info, "%s", line1);

    ImGui::SetCursorPos(ImVec2(cx - t2.x * 0.5f, top_y + font_h + gap));
    ImGui::TextColored(col::dim, "%s", line2);

    ImGui::SetCursorPos(ImVec2(cx - btn_w * 0.5f, top_y + font_h + gap + font_h + gap * 2));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.22f, 0.32f, 0.55f, 0.60f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.28f, 0.40f, 0.65f, 0.80f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.31f, 0.44f, 0.70f, 1.0f));
    if (ImGui::Button("Open File", ImVec2(btn_w, btn_h))) {
        std::string path = open_file_dialog();
        if (!path.empty())
            state.pending_drop_path = path;
    }
    ImGui::PopStyleColor(3);

    ImGui::End();
}

#ifdef AIDA_HAS_MCP
int run_gui(std::shared_ptr<BinaryImage> img, uint16_t mcp_port,
            std::shared_ptr<aida::mcp::McpSession> session) {
#else
int run_gui(std::shared_ptr<BinaryImage> img, uint16_t mcp_port) {
#endif
    if (!glfwInit()) return 1;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);
    glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_FALSE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif

    GLFWmonitor* monitor = glfwGetPrimaryMonitor();
    const GLFWvidmode* mode = glfwGetVideoMode(monitor);
    int win_w = (int)(mode->width * 0.80f);
    int win_h = (int)(mode->height * 0.80f);
    int win_x = (mode->width - win_w) / 2;
    int win_y = (mode->height - win_h) / 2;

    g_window = glfwCreateWindow(win_w, win_h, "AiDA", nullptr, nullptr);
    if (!g_window) { glfwTerminate(); return 1; }
    glfwSetWindowPos(g_window, win_x, win_y);
    glfwMakeContextCurrent(g_window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.IniFilename = nullptr;

    setup_theme();

    io.Fonts->AddFontDefault();

    ImGui_ImplGlfw_InitForOpenGL(g_window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    AppState state;
    state.image = img;
    state.mcp_port = mcp_port;
#ifdef AIDA_HAS_MCP
    state.mcp_session = session;
#endif
    g_state = &state;

    glfwSetDropCallback(g_window, glfw_drop_callback);

    if (img) {
        state.status_msg = "Loaded " + img->filename;
#ifdef AIDA_HAS_DECOMP
        state.decompiler = std::make_shared<Decompiler>(img);
        if (state.decompiler->init()) {
            state.status_msg += " | Ghidra decompiler ready";
        } else {
            state.decompiler.reset();
            state.status_msg += " | Decompiler failed to init";
        }
#endif
    } else {
        state.status_msg = "Drop a binary to begin";
    }

    bool first_frame = true;

    while (!glfwWindowShouldClose(g_window)) {
        glfwPollEvents();

        if (!state.pending_drop_path.empty()) {
            load_binary_into_state(state, state.pending_drop_path);
            state.pending_drop_path.clear();
#ifdef AIDA_HAS_MCP
            if (state.mcp_session && state.image) {
                std::lock_guard<std::mutex> lock(state.mcp_session->mtx);
                state.mcp_session->image = state.image;
            }
#endif
        }

        // poll background analysis progress
        if (state.analysis_prog && !state.analysis_finished_handled) {
            auto& prog = *state.analysis_prog;
            if (prog.done.load(std::memory_order_acquire)) {
                // analysis complete -- join thread, start decompiler
                if (state.analysis_thread.joinable())
                    state.analysis_thread.join();

                state.status_msg = "Loaded " + state.image->filename +
                    " | " + std::to_string(state.image->functions.size()) + " funcs" +
                    " | " + std::to_string(state.image->strings.size()) + " strings" +
                    " | " + std::to_string(state.image->xrefs.size()) + " xrefs";
                if (!state.image->crypto_hits.empty())
                    state.status_msg += " | " + std::to_string(state.image->crypto_hits.size()) + " crypto";
                if (!state.image->imphash.empty())
                    state.status_msg += " | imphash:" + state.image->imphash.substr(0, 8);

                g_func_cache.last_image = nullptr;
                g_xref_cache.cached_addr = 0;

#ifdef AIDA_HAS_DECOMP
                state.decompiler = std::make_shared<Decompiler>(state.image);
                if (state.decompiler->init()) {
                    state.status_msg += " | Ghidra decompiler ready";
                    g_decomp_cache.start(state.decompiler, state.image);
                } else {
                    state.decompiler.reset();
                }
#endif
#ifdef AIDA_HAS_MCP
                if (state.mcp_session) {
                    std::lock_guard<std::mutex> lock(state.mcp_session->mtx);
                    state.mcp_session->image = state.image;
#ifdef AIDA_HAS_DECOMP
                    state.mcp_session->decompiler = state.decompiler;
                    state.mcp_session->decompiler_ok = (state.decompiler != nullptr);
#endif
                    state.mcp_session->bump("analysis_complete");
                }
#endif
                state.analysis_finished_handled = true;
            } else {
                // update status with live progress
                int cur_stage = prog.stage.load(std::memory_order_acquire);
                size_t fc = prog.func_count.load(std::memory_order_acquire);
                std::string msg = prog.get_msg();
                state.status_msg = state.image->filename + " | " + msg;
                if (fc > 0)
                    state.status_msg += " | " + std::to_string(fc) + " funcs";
                // functions map is safe to read once discover_functions (stage 2) is done
                if (cur_stage > 2 && g_func_cache.last_func_count != fc)
                    g_func_cache.last_image = nullptr;
            }
        }

#ifdef AIDA_HAS_MCP
        if (state.mcp_session) {
            uint64_t gen = state.mcp_session->generation.load(std::memory_order_acquire);
            if (gen != state.gui_generation) {
                state.gui_generation = gen;
                std::lock_guard<std::mutex> lock(state.mcp_session->mtx);
                if (state.mcp_session->image && state.mcp_session->image != state.image) {
                    state.image = state.mcp_session->image;
                    state.selected_func_idx = -1;
                    state.selected_addr = 0;
                    state.search_buf[0] = 0;
                    state.needs_layout_rebuild = true;
                    state.status_msg = "MCP loaded: " + state.image->filename;
#ifdef AIDA_HAS_DECOMP
                    state.decompiler = state.mcp_session->decompiler;
                    state.decomp_cached_addr = 0;
                    state.decomp_cached_code.clear();
                    state.decomp_has_error = false;
#endif
                }
                state.status_msg = "MCP: " + state.mcp_session->last_action;
            }
        }
#endif

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        float titlebar_h = 32.0f;
        float statusbar_h = 24.0f;
        draw_titlebar(state);

        if (!state.image) {
            draw_drop_zone(state);
        } else {
            ImGuiViewport* vp = ImGui::GetMainViewport();
            ImGui::SetNextWindowPos(ImVec2(vp->Pos.x, vp->Pos.y + titlebar_h));
            ImGui::SetNextWindowSize(ImVec2(vp->Size.x, vp->Size.y - titlebar_h - statusbar_h));
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
            ImGui::Begin("##DockArea", nullptr,
                ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoSavedSettings);
            ImGui::PopStyleVar();

            ImGuiID dockspace_id = ImGui::GetID("MainDock");
            ImGui::DockSpace(dockspace_id, ImVec2(0, 0),
                ImGuiDockNodeFlags_NoCloseButton | ImGuiDockNodeFlags_NoWindowMenuButton);

            if (first_frame || state.needs_layout_rebuild) {
                build_default_layout(dockspace_id);
                first_frame = false;
                state.needs_layout_rebuild = false;
            }

            ImGui::End();

            ImGui::Begin("Functions", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_functions_panel(state);
            ImGui::End();

            ImGui::Begin("Disassembly", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_disasm_panel(state);
            ImGui::End();

            ImGui::Begin("Decompiler", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_decomp_panel(state);
            ImGui::End();

            ImGui::Begin("Strings", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_strings_panel(state);
            ImGui::End();

            ImGui::Begin("Hex View", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_hex_panel(state);
            ImGui::End();

            ImGui::Begin("Notes", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_notes_panel(state);
            ImGui::End();

            ImGui::Begin("Xrefs", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_xrefs_panel(state);
            ImGui::End();

            ImGui::Begin("Imports", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_imports_panel(state);
            ImGui::End();

            ImGui::Begin("Exports", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_exports_panel(state);
            ImGui::End();

            ImGui::Begin("Network", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_network_panel(state);
            ImGui::End();

            ImGui::Begin("Bookmarks", nullptr, ImGuiWindowFlags_NoCollapse);
            draw_bookmarks_panel(state);
            ImGui::End();
        }

        draw_statusbar(state);

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(g_window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.047f, 0.047f, 0.059f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(g_window);
    }

    g_state = nullptr;
    if (state.analysis_thread.joinable()) {
        if (state.analysis_prog) state.analysis_prog->done.store(true);
        state.analysis_thread.join();
    }
#ifdef AIDA_HAS_DECOMP
    g_decomp_cache.stop();
#endif
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(g_window);
    glfwTerminate();
    return 0;
}

}
