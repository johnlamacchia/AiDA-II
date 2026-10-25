#include "mcp/tools.hpp"
#include "core/disasm.hpp"
#include "core/analysis.hpp"
#include "core/loader.hpp"
#include "core/project.hpp"
#include "core/crypto_scan.hpp"
#include "core/entropy.hpp"
#include "core/imphash.hpp"
#include "core/decrypt.hpp"
#include <sstream>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <set>

namespace aida::mcp {

using json = nlohmann::json;

static json schema_prop(const std::string& type, const std::string& desc) {
    return {{"type", type}, {"description", desc}};
}

static json err(const std::string& msg) { return json(msg); }

static uint64_t parse_addr(const json& p, const std::string& key) {
    if (!p.contains(key)) return 0;
    if (p[key].is_string()) return std::stoull(p[key].get<std::string>(), nullptr, 0);
    return p[key].get<uint64_t>();
}

static uint64_t resolve_func_addr(const BinaryImage& img, const json& p) {
    uint64_t addr = parse_addr(p, "addr");
    if (addr) return addr;
    if (p.contains("name")) {
        std::string name = p["name"].get<std::string>();
        for (auto& [a, f] : img.functions)
            if (f.name == name) return a;
    }
    return 0;
}

void register_all_tools(McpServer& server, std::shared_ptr<McpSession> sess) {

    // -------------------------------------------------------------------------
    // load_binary - load a new binary for analysis
    // -------------------------------------------------------------------------
    server.register_tool({
        "load_binary",
        "Load a binary file for analysis. Can be called at any time to switch targets. Runs full analysis (functions, strings, xrefs, crypto scan, entropy, imphash).",
        {{"type", "object"}, {"properties", {
            {"path", schema_prop("string", "Absolute path to the binary file")}
        }}, {"required", json::array({"path"})}},
        [sess](const json& p) -> json {
            std::string path = p["path"].get<std::string>();
            if (!std::filesystem::exists(path))
                return err("File not found: " + path);

            auto img = load_binary(path);
            if (!img) return err("Failed to parse binary: " + path);

            fprintf(stderr, "[*] Loading: %s\n", path.c_str());
            run_full_analysis(*img);
            fprintf(stderr, "[+] Found %zu functions, %zu strings, %zu xrefs\n",
                img->functions.size(), img->strings.size(), img->xrefs.size());
            if (!img->crypto_hits.empty())
                fprintf(stderr, "[+] Crypto: %zu constant hits\n", img->crypto_hits.size());
            if (img->overall_entropy > 0.0)
                fprintf(stderr, "[+] Entropy: %.2f%s\n", img->overall_entropy,
                    img->likely_packed ? " (LIKELY PACKED)" : "");
            if (!img->imphash.empty())
                fprintf(stderr, "[+] Imphash: %s\n", img->imphash.c_str());

            std::string db_path = path + ".aida";
            if (std::filesystem::exists(db_path)) {
                load_project(*img, db_path);
                fprintf(stderr, "[+] Project loaded (%zu user names)\n", img->user_names.size());
            }

            std::lock_guard<std::mutex> lock(sess->mtx);
            sess->image = std::shared_ptr<BinaryImage>(img.release());

#ifdef AIDA_HAS_DECOMP
            sess->decompiler = std::make_shared<Decompiler>(sess->image);
            sess->decompiler_ok = sess->decompiler->init();
            fprintf(stderr, sess->decompiler_ok ?
                "[+] Ghidra decompiler initialized\n" :
                "[!] Ghidra decompiler failed to init\n");
#endif

            json r;
            r["success"] = true;
            r["file"] = sess->image->filename;
            r["format"] = static_cast<int>(sess->image->format);
            r["arch"] = static_cast<int>(sess->image->arch);
            r["bits"] = arch_bits(sess->image->arch);
            r["base"] = sess->image->base;
            r["entry"] = sess->image->entry;
            r["num_functions"] = sess->image->functions.size();
            size_t nsubs = 0;
            for (auto& [a, f] : sess->image->functions) if (f.is_nullsub) nsubs++;
            r["null_stubs"] = nsubs;
            r["num_strings"] = sess->image->strings.size();
            r["num_imports"] = sess->image->imports.size();
            r["num_exports"] = sess->image->exports.size();
            r["overall_entropy"] = sess->image->overall_entropy;
            r["crypto_hits"] = sess->image->crypto_hits.size();
            if (!sess->image->imphash.empty()) r["imphash"] = sess->image->imphash;
            sess->bump("load_binary: " + sess->image->filename);
            return r;
        }
    });

    // helper macro to check image is loaded
    #define REQUIRE_IMAGE() \
        if (!sess->image) return err("No binary loaded. Use load_binary first.")

    // -------------------------------------------------------------------------
    // survey_binary
    // -------------------------------------------------------------------------
    server.register_tool({
        "survey_binary",
        "Get an overview of the loaded binary: format, arch, sections, imports, exports, function count, string count, entropy, crypto hits, imphash.",
        {{"type", "object"}, {"properties", json::object()}},
        [sess](const json&) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            json r;
            r["file"] = img.filename;
            r["format"] = static_cast<int>(img.format);
            r["arch"] = static_cast<int>(img.arch);
            r["bits"] = arch_bits(img.arch);
            r["base"] = img.base;
            r["entry"] = img.entry;

            json secs = json::array();
            for (auto& s : img.sections) {
                secs.push_back({
                    {"name", s.name}, {"vaddr", s.vaddr}, {"vsize", s.vsize},
                    {"file_size", s.file_size}, {"exec", s.executable},
                    {"write", s.writable}
                });
            }
            r["sections"] = secs;
            r["num_functions"] = img.functions.size();
            r["num_imports"] = img.imports.size();
            r["num_exports"] = img.exports.size();
            r["num_strings"] = img.strings.size();
            r["num_symbols"] = img.symbols.size();

            size_t named = 0, unnamed = 0, nullsubs = 0;
            for (auto& [a, f] : img.functions) {
                if (f.is_nullsub) nullsubs++;
                if (f.name.substr(0, 4) == "sub_") unnamed++;
                else named++;
            }
            r["named_functions"] = named;
            r["unnamed_functions"] = unnamed;
            r["null_stubs"] = nullsubs;
            r["overall_entropy"] = img.overall_entropy;
            r["likely_packed"] = img.likely_packed;
            r["crypto_hits"] = img.crypto_hits.size();
            if (!img.imphash.empty()) r["imphash"] = img.imphash;

            if (!img.crypto_hits.empty()) {
                std::map<std::string, int> algo_counts;
                for (auto& h : img.crypto_hits) algo_counts[h.algorithm]++;
                json ac = json::object();
                for (auto& [algo, count] : algo_counts) ac[algo] = count;
                r["crypto_algorithms"] = ac;
            }
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // list_funcs
    // -------------------------------------------------------------------------
    server.register_tool({
        "list_funcs",
        "List functions. Optional filter by name substring. Returns addr, name, size, instruction count.",
        {{"type", "object"}, {"properties", {
            {"filter", schema_prop("string", "Substring to filter function names")},
            {"offset", schema_prop("integer", "Skip first N results")},
            {"limit", schema_prop("integer", "Max results to return (default 100)")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            std::string filter = p.value("filter", "");
            size_t offset = p.value("offset", 0);
            size_t limit = p.value("limit", 100);

            json funcs = json::array();
            size_t idx = 0;
            for (auto& [addr, f] : img.functions) {
                if (!filter.empty() && f.name.find(filter) == std::string::npos) continue;
                if (idx < offset) { idx++; continue; }
                if (funcs.size() >= limit) break;
                json fj;
                fj["addr"] = addr;
                fj["name"] = f.name;
                fj["size"] = f.end_addr > f.addr ? f.end_addr - f.addr : 0;
                fj["num_instructions"] = f.instructions.size();
                fj["is_import"] = f.is_import;
                fj["is_export"] = f.is_export;
                fj["is_nullsub"] = f.is_nullsub;
                fj["user_named"] = f.user_named;
                funcs.push_back(std::move(fj));
                idx++;
            }
            json r;
            r["functions"] = funcs;
            r["total"] = img.functions.size();
            r["returned"] = funcs.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // decompile
    // -------------------------------------------------------------------------
    server.register_tool({
        "decompile",
        "Decompile a function to C pseudocode (Ghidra decompiler) or disassembly. Provide addr or name.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Function address (decimal or hex string)")},
            {"name", schema_prop("string", "Function name to look up")},
            {"asm", schema_prop("boolean", "Force assembly output instead of decompiled C")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = resolve_func_addr(img, p);
            if (!addr) return err("Provide 'addr' or 'name'");

            auto it = img.functions.find(addr);
            if (it == img.functions.end())
                return err("No function at that address");

            bool force_asm = p.value("asm", false);

#ifdef AIDA_HAS_DECOMP
            if (sess->decompiler_ok && !force_asm && !it->second.is_import) {
                auto result = sess->decompiler->decompile(addr);
                if (result.ok) {
                    json r;
                    r["function"] = it->second.name;
                    r["addr"] = addr;
                    r["language"] = "c";
                    r["code"] = result.code;
                    return r;
                }
            }
#endif
            auto& func = it->second;
            if (func.instructions.empty() && !func.is_import) {
                func.instructions = disassemble_function(img, addr);
                if (!func.instructions.empty()) {
                    auto& last = func.instructions.back();
                    func.end_addr = last.addr + last.size;
                }
            }
            std::ostringstream ss;
            ss << "; Function: " << func.name << "\n";
            ss << "; Address:  0x" << std::hex << func.addr << "\n";
            if (func.end_addr > func.addr)
                ss << "; Size:     " << std::dec << (func.end_addr - func.addr) << " bytes\n";
            ss << "\n";
            for (auto& inst : func.instructions) {
                ss << std::hex << inst.addr << "  ";
                for (auto b : inst.bytes) { char h[4]; snprintf(h, sizeof(h), "%02X ", b); ss << h; }
                size_t byte_col = inst.bytes.size() * 3;
                while (byte_col < 24) { ss << ' '; byte_col++; }
                ss << inst.mnemonic;
                if (!inst.operands.empty()) ss << " " << inst.operands;
                ss << "\n";
            }
            json r;
            r["function"] = func.name;
            r["addr"] = addr;
            r["language"] = "asm";
            r["code"] = ss.str();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // find
    // -------------------------------------------------------------------------
    server.register_tool({
        "find",
        "Search for strings, function names, or hex patterns in the binary.",
        {{"type", "object"}, {"properties", {
            {"query", schema_prop("string", "Search query")},
            {"type", schema_prop("string", "Search type: 'string', 'function', 'bytes' (default: auto)")}
        }}, {"required", json::array({"query"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            std::string query = p["query"].get<std::string>();
            std::string type = p.value("type", "auto");

            json results = json::array();

            auto search_strings = [&]() {
                for (auto& s : img.strings) {
                    if (s.value.find(query) != std::string::npos) {
                        results.push_back({{"type", "string"}, {"addr", s.addr}, {"value", s.value}, {"wide", s.wide}});
                        if (results.size() >= 50) break;
                    }
                }
            };
            auto search_funcs = [&]() {
                for (auto& [a, f] : img.functions) {
                    if (f.name.find(query) != std::string::npos) {
                        results.push_back({{"type", "function"}, {"addr", a}, {"name", f.name}});
                        if (results.size() >= 50) break;
                    }
                }
            };
            if (type == "string") search_strings();
            else if (type == "function") search_funcs();
            else { search_funcs(); search_strings(); }

            json r;
            r["results"] = results;
            r["count"] = results.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // xrefs_to - who references this address
    // -------------------------------------------------------------------------
    server.register_tool({
        "xrefs_to",
        "Find all cross-references TO a given address (who calls/references this).",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Target address")},
            {"name", schema_prop("string", "Function/string name to find xrefs to")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = resolve_func_addr(img, p);
            if (!addr && p.contains("name")) {
                std::string name = p["name"].get<std::string>();
                for (auto& s : img.strings)
                    if (s.value == name) { addr = s.addr; break; }
            }

            json refs = json::array();
            for (auto& xr : img.xrefs) {
                if (xr.to == addr) {
                    std::string from_func = "unknown";
                    for (auto& [fa, f] : img.functions)
                        if (fa <= xr.from && f.end_addr > xr.from) { from_func = f.name; break; }
                    refs.push_back({{"from", xr.from}, {"to", xr.to},
                        {"type", static_cast<int>(xr.type)}, {"from_function", from_func}});
                }
            }
            json r;
            r["xrefs"] = refs;
            r["count"] = refs.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // xrefs_from - what does this function reference
    // -------------------------------------------------------------------------
    server.register_tool({
        "xrefs_from",
        "Find all cross-references FROM a function (what it calls/references).",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Function address")},
            {"name", schema_prop("string", "Function name")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = resolve_func_addr(img, p);
            if (!addr) return err("Provide 'addr' or 'name'");

            auto it = img.functions.find(addr);
            if (it == img.functions.end()) return err("No function at that address");
            auto& func = it->second;

            json refs = json::array();
            for (auto& xr : img.xrefs) {
                if (xr.from >= func.addr && (func.end_addr == 0 || xr.from < func.end_addr)) {
                    std::string target_name;
                    auto tit = img.functions.find(xr.to);
                    if (tit != img.functions.end()) target_name = tit->second.name;
                    else {
                        for (auto& s : img.strings)
                            if (s.addr == xr.to) { target_name = "\"" + s.value.substr(0, 80) + "\""; break; }
                    }
                    refs.push_back({{"from", xr.from}, {"to", xr.to},
                        {"type", static_cast<int>(xr.type)}, {"target_name", target_name}});
                }
            }
            json r;
            r["function"] = func.name;
            r["xrefs"] = refs;
            r["count"] = refs.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // get_imports
    // -------------------------------------------------------------------------
    server.register_tool({
        "get_imports",
        "List all imports with module name, function name, ordinal, and IAT address.",
        {{"type", "object"}, {"properties", {
            {"filter", schema_prop("string", "Filter by module or function name substring")},
            {"limit", schema_prop("integer", "Max results (default 200)")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            std::string filter = p.value("filter", "");
            size_t limit = p.value("limit", 200);

            json imps = json::array();
            for (auto& imp : img.imports) {
                if (!filter.empty() && imp.module.find(filter) == std::string::npos &&
                    imp.name.find(filter) == std::string::npos) continue;
                imps.push_back({{"module", imp.module}, {"name", imp.name},
                    {"ordinal", imp.ordinal}, {"iat_rva", imp.iat_rva}});
                if (imps.size() >= limit) break;
            }
            json r;
            r["imports"] = imps;
            r["total"] = img.imports.size();
            r["returned"] = imps.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // get_exports
    // -------------------------------------------------------------------------
    server.register_tool({
        "get_exports",
        "List all exports with name, RVA, ordinal, and forward info.",
        {{"type", "object"}, {"properties", {
            {"filter", schema_prop("string", "Filter by name substring")},
            {"limit", schema_prop("integer", "Max results (default 200)")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            std::string filter = p.value("filter", "");
            size_t limit = p.value("limit", 200);

            json exps = json::array();
            for (auto& exp : img.exports) {
                if (!filter.empty() && exp.name.find(filter) == std::string::npos) continue;
                json ej = {{"name", exp.name}, {"rva", exp.rva}, {"ordinal", exp.ordinal}};
                if (exp.forwarded) { ej["forwarded"] = true; ej["forward_name"] = exp.forward_name; }
                exps.push_back(std::move(ej));
                if (exps.size() >= limit) break;
            }
            json r;
            r["exports"] = exps;
            r["total"] = img.exports.size();
            r["returned"] = exps.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // get_sections
    // -------------------------------------------------------------------------
    server.register_tool({
        "get_sections",
        "List all sections with name, addresses, sizes, permissions, and entropy.",
        {{"type", "object"}, {"properties", json::object()}},
        [sess](const json&) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            json secs = json::array();
            size_t eidx = 0;
            for (auto& s : img.sections) {
                json sj = {{"name", s.name}, {"vaddr", s.vaddr}, {"vsize", s.vsize},
                    {"file_offset", s.file_off}, {"file_size", s.file_size},
                    {"executable", s.executable}, {"writable", s.writable}, {"readable", s.readable}};
                if (eidx < img.section_entropy.size())
                    sj["entropy"] = img.section_entropy[eidx].entropy;
                secs.push_back(std::move(sj));
                eidx++;
            }
            json r;
            r["sections"] = secs;
            r["count"] = secs.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // get_bytes - hex dump at address
    // -------------------------------------------------------------------------
    server.register_tool({
        "get_bytes",
        "Read raw bytes at a virtual address. Returns hex dump and ASCII.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Virtual address to read from")},
            {"length", schema_prop("integer", "Number of bytes to read (default 256, max 4096)")}
        }}, {"required", json::array({"addr"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = parse_addr(p, "addr");
            size_t length = std::min<size_t>(p.value("length", 256), 4096);

            size_t avail = 0;
            const uint8_t* bytes = img.bytes_at_va(addr, &avail);
            if (!bytes || avail == 0) return err("No data at that address");

            size_t actual = std::min(avail, length);
            std::ostringstream hex_ss, ascii_ss;
            json lines = json::array();

            for (size_t off = 0; off < actual; off += 16) {
                std::ostringstream lhex, lascii;
                char addr_str[32];
                snprintf(addr_str, sizeof(addr_str), "%08llX", (unsigned long long)(addr + off));
                size_t count = std::min<size_t>(16, actual - off);
                for (size_t i = 0; i < count; i++) {
                    char h[4]; snprintf(h, sizeof(h), "%02X ", bytes[off + i]);
                    lhex << h;
                    lascii << (char)((bytes[off + i] >= 0x20 && bytes[off + i] < 0x7F) ? bytes[off + i] : '.');
                }
                lines.push_back({{"offset", addr_str}, {"hex", lhex.str()}, {"ascii", lascii.str()}});
            }

            std::string raw_hex;
            for (size_t i = 0; i < actual; i++) {
                char h[3]; snprintf(h, sizeof(h), "%02x", bytes[i]);
                raw_hex += h;
            }

            json r;
            r["addr"] = addr;
            r["length"] = actual;
            r["hex"] = raw_hex;
            r["dump"] = lines;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // add_comment
    // -------------------------------------------------------------------------
    server.register_tool({
        "add_comment",
        "Add or update a comment at an address. Persists to the .aida project file on save.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Address to comment")},
            {"comment", schema_prop("string", "Comment text (empty to delete)")}
        }}, {"required", json::array({"addr", "comment"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = parse_addr(p, "addr");
            std::string comment = p["comment"].get<std::string>();

            if (comment.empty())
                img.user_comments.erase(addr);
            else
                img.user_comments[addr] = comment;

            sess->bump("add_comment @ 0x" + std::to_string(addr));
            json r;
            r["success"] = true;
            r["addr"] = addr;
            r["comment"] = comment;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // get_comments
    // -------------------------------------------------------------------------
    server.register_tool({
        "get_comments",
        "Get all user comments, or the comment at a specific address.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Specific address (omit for all comments)")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            if (p.contains("addr")) {
                uint64_t addr = parse_addr(p, "addr");
                auto cit = img.user_comments.find(addr);
                if (cit != img.user_comments.end())
                    return json({{"addr", addr}, {"comment", cit->second}});
                return err("No comment at that address");
            }
            json comments = json::array();
            for (auto& [addr, comment] : img.user_comments)
                comments.push_back({{"addr", addr}, {"comment", comment}});
            json r;
            r["comments"] = comments;
            r["count"] = comments.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // call_graph - N-level caller/callee tree
    // -------------------------------------------------------------------------
    server.register_tool({
        "call_graph",
        "Get the call graph for a function: who calls it (callers) and what it calls (callees), up to N levels deep.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Function address")},
            {"name", schema_prop("string", "Function name")},
            {"depth", schema_prop("integer", "Max depth to traverse (default 2, max 5)")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t root_addr = resolve_func_addr(img, p);
            if (!root_addr) return err("Provide 'addr' or 'name'");

            auto fit = img.functions.find(root_addr);
            if (fit == img.functions.end()) return err("No function at that address");

            int max_depth = std::min(p.value("depth", 2), 5);

            // build adjacency
            std::map<uint64_t, std::set<uint64_t>> callers, callees;
            for (auto& xr : img.xrefs) {
                if (xr.type != XrefType::Call) continue;
                // find which function xr.from belongs to
                for (auto& [fa, f] : img.functions) {
                    if (fa <= xr.from && (f.end_addr == 0 || xr.from < f.end_addr)) {
                        callees[fa].insert(xr.to);
                        callers[xr.to].insert(fa);
                        break;
                    }
                }
            }

            std::function<json(uint64_t, int, bool, std::set<uint64_t>&)> build_tree;
            build_tree = [&](uint64_t addr, int depth, bool up, std::set<uint64_t>& visited) -> json {
                json node;
                auto nit = img.functions.find(addr);
                node["addr"] = addr;
                node["name"] = nit != img.functions.end() ? nit->second.name : "unknown";

                if (depth <= 0 || visited.count(addr)) return node;
                visited.insert(addr);

                auto& refs = up ? callers[addr] : callees[addr];
                if (!refs.empty()) {
                    json children = json::array();
                    for (uint64_t child : refs)
                        children.push_back(build_tree(child, depth - 1, up, visited));
                    node[up ? "callers" : "callees"] = children;
                }
                return node;
            };

            std::set<uint64_t> v1, v2;
            json r;
            r["function"] = fit->second.name;
            r["addr"] = root_addr;

            // callers tree
            json caller_tree = json::array();
            if (callers.count(root_addr)) {
                for (uint64_t c : callers[root_addr])
                    caller_tree.push_back(build_tree(c, max_depth - 1, true, v1));
            }
            r["callers"] = caller_tree;

            // callees tree
            json callee_tree = json::array();
            if (callees.count(root_addr)) {
                for (uint64_t c : callees[root_addr])
                    callee_tree.push_back(build_tree(c, max_depth - 1, false, v2));
            }
            r["callees"] = callee_tree;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // strings_in_function
    // -------------------------------------------------------------------------
    server.register_tool({
        "strings_in_function",
        "Get all strings referenced by a specific function (via xrefs).",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Function address")},
            {"name", schema_prop("string", "Function name")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = resolve_func_addr(img, p);
            if (!addr) return err("Provide 'addr' or 'name'");

            auto it = img.functions.find(addr);
            if (it == img.functions.end()) return err("No function at that address");
            auto& func = it->second;

            std::set<uint64_t> str_addrs;
            for (auto& s : img.strings) str_addrs.insert(s.addr);

            json strs = json::array();
            for (auto& xr : img.xrefs) {
                if (xr.from >= func.addr && (func.end_addr == 0 || xr.from < func.end_addr)) {
                    if (str_addrs.count(xr.to)) {
                        for (auto& s : img.strings) {
                            if (s.addr == xr.to) {
                                strs.push_back({{"addr", s.addr}, {"value", s.value},
                                    {"wide", s.wide}, {"referenced_from", xr.from}});
                                break;
                            }
                        }
                    }
                }
            }
            json r;
            r["function"] = func.name;
            r["strings"] = strs;
            r["count"] = strs.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // search_bytes - hex pattern search
    // -------------------------------------------------------------------------
    server.register_tool({
        "search_bytes",
        "Search for a hex byte pattern across all sections. Supports ?? wildcards for single bytes.",
        {{"type", "object"}, {"properties", {
            {"pattern", schema_prop("string", "Hex string to search for, e.g. '48 8B 05' with '?' '?' wildcards, or '488B05'")},
            {"limit", schema_prop("integer", "Max results (default 50)")}
        }}, {"required", json::array({"pattern"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            std::string pat_str = p["pattern"].get<std::string>();
            size_t limit = p.value("limit", 50);

            // parse hex pattern with wildcards
            std::vector<int16_t> pattern; // -1 = wildcard
            for (size_t i = 0; i < pat_str.size(); ) {
                if (pat_str[i] == ' ') { i++; continue; }
                if (pat_str[i] == '?' && i + 1 < pat_str.size() && pat_str[i+1] == '?') {
                    pattern.push_back(-1);
                    i += 2;
                } else if (i + 1 < pat_str.size()) {
                    char hex[3] = { pat_str[i], pat_str[i+1], 0 };
                    pattern.push_back((int16_t)strtol(hex, nullptr, 16));
                    i += 2;
                } else break;
            }

            if (pattern.empty()) return err("Invalid pattern");

            json results = json::array();
            for (auto& sec : img.sections) {
                if (sec.file_off + sec.file_size > img.raw.size()) continue;
                const uint8_t* data = img.raw.data() + sec.file_off;
                size_t len = sec.file_size;

                if (len < pattern.size()) continue;
                for (size_t i = 0; i <= len - pattern.size(); i++) {
                    bool match = true;
                    for (size_t j = 0; j < pattern.size(); j++) {
                        if (pattern[j] >= 0 && data[i + j] != (uint8_t)pattern[j]) {
                            match = false; break;
                        }
                    }
                    if (match) {
                        std::string hex_match;
                        for (size_t j = 0; j < pattern.size(); j++) {
                            char h[4]; snprintf(h, sizeof(h), "%02X ", data[i + j]);
                            hex_match += h;
                        }
                        results.push_back({{"addr", sec.vaddr + i}, {"section", sec.name},
                            {"bytes", hex_match}});
                        if (results.size() >= limit) break;
                    }
                }
                if (results.size() >= limit) break;
            }
            json r;
            r["results"] = results;
            r["count"] = results.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // patch_bytes - modify bytes in memory
    // -------------------------------------------------------------------------
    server.register_tool({
        "patch_bytes",
        "Modify bytes at a virtual address (in-memory only). Useful for patching checks, NOPing out code, etc.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Virtual address to patch")},
            {"bytes", schema_prop("string", "Hex bytes to write (e.g. '90 90 90' for NOPs)")}
        }}, {"required", json::array({"addr", "bytes"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = parse_addr(p, "addr");
            std::string hex_str = p["bytes"].get<std::string>();

            std::vector<uint8_t> patch_bytes;
            for (size_t i = 0; i < hex_str.size(); ) {
                if (hex_str[i] == ' ') { i++; continue; }
                if (i + 1 < hex_str.size()) {
                    char h[3] = { hex_str[i], hex_str[i+1], 0 };
                    patch_bytes.push_back((uint8_t)strtol(h, nullptr, 16));
                    i += 2;
                } else break;
            }

            auto file_off = img.va_to_offset(addr);
            if (!file_off) return err("Address not mapped");
            if (*file_off + patch_bytes.size() > img.raw.size())
                return err("Patch extends beyond section");

            std::string old_hex;
            for (size_t i = 0; i < patch_bytes.size(); i++) {
                char h[4]; snprintf(h, sizeof(h), "%02X ", img.raw[*file_off + i]);
                old_hex += h;
            }

            memcpy(img.raw.data() + *file_off, patch_bytes.data(), patch_bytes.size());
            sess->bump("patch_bytes @ 0x" + std::to_string(addr));

            json r;
            r["success"] = true;
            r["addr"] = addr;
            r["old_bytes"] = old_hex;
            r["new_bytes"] = hex_str;
            r["length"] = patch_bytes.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // rename
    // -------------------------------------------------------------------------
    server.register_tool({
        "rename",
        "Rename a function at the given address.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Address of the function to rename")},
            {"old_name", schema_prop("string", "Current name (used to find the function)")},
            {"new_name", schema_prop("string", "New name for the function")}
        }}, {"required", json::array({"new_name"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            std::string new_name = p["new_name"].get<std::string>();
            uint64_t addr = parse_addr(p, "addr");
            if (!addr && p.contains("old_name")) {
                std::string old = p["old_name"].get<std::string>();
                for (auto& [a, f] : img.functions)
                    if (f.name == old) { addr = a; break; }
            }
            if (!addr) return err("Could not find function to rename");
            auto it = img.functions.find(addr);
            if (it == img.functions.end()) return err("No function at that address");

            std::string old_name = it->second.name;
            it->second.name = new_name;
            it->second.user_named = true;
            img.user_names[addr] = new_name;
            sess->bump("rename: " + old_name + " -> " + new_name);

            json r;
            r["success"] = true;
            r["addr"] = addr;
            r["old_name"] = old_name;
            r["new_name"] = new_name;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // get_string
    // -------------------------------------------------------------------------
    server.register_tool({
        "get_string",
        "Get the string value at a specific address.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Address of the string")}
        }}, {"required", json::array({"addr"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = parse_addr(p, "addr");
            for (auto& s : img.strings)
                if (s.addr == addr) return json({{"addr", s.addr}, {"value", s.value}, {"wide", s.wide}});
            size_t avail = 0;
            const uint8_t* bytes = img.bytes_at_va(addr, &avail);
            if (bytes && avail > 0) {
                std::string val;
                for (size_t i = 0; i < std::min<size_t>(avail, 256) && bytes[i]; i++)
                    val += static_cast<char>(bytes[i]);
                if (!val.empty())
                    return json({{"addr", addr}, {"value", val}, {"wide", false}, {"note", "raw read"}});
            }
            return err("No string at that address");
        }
    });

    // -------------------------------------------------------------------------
    // crypto_scan
    // -------------------------------------------------------------------------
    server.register_tool({
        "crypto_scan",
        "Scan for known cryptographic constants (AES, SHA, MD5, DES, ChaCha20, Blowfish, CRC32, Base64, RC4, TEA, etc).",
        {{"type", "object"}, {"properties", json::object()}},
        [sess](const json&) -> json {
            REQUIRE_IMAGE();
            auto result = scan_crypto_constants(*sess->image);
            json hits = json::array();
            for (auto& h : result.hits)
                hits.push_back({{"addr", h.addr}, {"algorithm", h.algorithm},
                    {"constant", h.constant_name}, {"match_bytes", h.match_len}});
            std::map<std::string, int> algo_counts;
            for (auto& h : result.hits) algo_counts[h.algorithm]++;
            json summary = json::object();
            for (auto& [algo, count] : algo_counts) summary[algo] = count;
            json r;
            r["hits"] = hits;
            r["total"] = result.hits.size();
            r["algorithms_found"] = summary;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // entropy
    // -------------------------------------------------------------------------
    server.register_tool({
        "entropy",
        "Calculate Shannon entropy per section and overall. Flags packed (>6.8) or encrypted (>7.5) sections.",
        {{"type", "object"}, {"properties", {
            {"window_size", schema_prop("integer", "Sliding window size (default 256, 0 disables)")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            size_t window = p.value("window_size", 256);
            auto result = analyze_entropy(*sess->image, window);
            json secs = json::array();
            for (auto& se : result.sections) {
                secs.push_back({{"name", se.name}, {"vaddr", se.vaddr}, {"size", se.size},
                    {"entropy", se.entropy}, {"likely_packed", se.packed}, {"likely_encrypted", se.encrypted}});
            }
            json regions = json::array();
            for (auto& ew : result.high_entropy_regions)
                regions.push_back({{"file_offset", ew.offset}, {"entropy", ew.entropy}});
            json r;
            r["overall_entropy"] = result.overall_entropy;
            r["likely_packed"] = result.likely_packed;
            r["sections"] = secs;
            r["high_entropy_regions"] = regions;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // imphash
    // -------------------------------------------------------------------------
    server.register_tool({
        "imphash",
        "Compute the import hash (imphash) of a PE binary for malware clustering.",
        {{"type", "object"}, {"properties", json::object()}},
        [sess](const json&) -> json {
            REQUIRE_IMAGE();
            std::string hash = compute_imphash(*sess->image);
            json r;
            if (hash.empty()) {
                r["imphash"] = nullptr;
                r["reason"] = sess->image->format != BinaryFormat::PE ? "not a PE binary" : "no imports found";
            } else {
                r["imphash"] = hash;
                r["num_imports"] = sess->image->imports.size();
            }
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // decrypt - decrypt/decode data at an address
    // -------------------------------------------------------------------------
    server.register_tool({
        "decrypt",
        "Decrypt or decode data at a virtual address using various algorithms: xor (single/multi-byte), xor_bruteforce, rc4, rot, base64, not, add, sub, rolling_xor, reverse, or auto (tries all).",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Virtual address of encrypted data")},
            {"length", schema_prop("integer", "Number of bytes to decrypt (default 256, max 65536)")},
            {"algorithm", schema_prop("string", "Algorithm: xor, xor_bruteforce, rc4, rot, base64, not, add, sub, rolling_xor, reverse, auto (default: auto)")},
            {"key", schema_prop("string", "Hex key for xor/rc4/add/sub (e.g. 'FF' or '4142434445')")},
            {"rot_n", schema_prop("integer", "Rotation amount for ROT-N (default 13)")},
            {"seed", schema_prop("string", "Hex seed byte for rolling_xor (default '00')")},
            {"write_back", schema_prop("boolean", "Write decrypted bytes back to the binary in-memory (default false)")},
            {"save_to", schema_prop("string", "Save decrypted output to this file path")}
        }}, {"required", json::array({"addr"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = parse_addr(p, "addr");
            size_t length = std::min<size_t>(p.value("length", 256), 65536);
            std::string algo = p.value("algorithm", "auto");

            size_t avail = 0;
            const uint8_t* data = img.bytes_at_va(addr, &avail);
            if (!data || avail == 0) return err("No data at that address");
            size_t actual = std::min(avail, length);

            // parse hex key
            auto parse_hex_key = [](const std::string& hex) -> std::vector<uint8_t> {
                std::vector<uint8_t> key;
                for (size_t i = 0; i < hex.size(); ) {
                    if (hex[i] == ' ') { i++; continue; }
                    if (i + 1 < hex.size()) {
                        char h[3] = { hex[i], hex[i+1], 0 };
                        key.push_back((uint8_t)strtol(h, nullptr, 16));
                        i += 2;
                    } else break;
                }
                return key;
            };

            DecryptResult dr;
            if (algo == "xor" || algo == "xor_single" || algo == "xor_multi") {
                std::string key_hex = p.value("key", "00");
                auto key = parse_hex_key(key_hex);
                if (key.size() == 1)
                    dr = xor_decrypt(data, actual, key[0]);
                else if (key.size() > 1)
                    dr = xor_decrypt(data, actual, key.data(), key.size());
                else return err("Invalid key");
            } else if (algo == "xor_bruteforce") {
                dr = xor_bruteforce(data, actual);
            } else if (algo == "rc4") {
                std::string key_hex = p.value("key", "");
                if (key_hex.empty()) return err("RC4 requires a key");
                auto key = parse_hex_key(key_hex);
                dr = rc4_decrypt(data, actual, key.data(), key.size());
            } else if (algo == "rot") {
                int n = p.value("rot_n", 13);
                dr = rot_decrypt(data, actual, n);
            } else if (algo == "base64") {
                dr = base64_decode(data, actual);
            } else if (algo == "not") {
                dr = not_decrypt(data, actual);
            } else if (algo == "add") {
                auto key = parse_hex_key(p.value("key", "01"));
                dr = add_decrypt(data, actual, key.empty() ? 1 : key[0]);
            } else if (algo == "sub") {
                auto key = parse_hex_key(p.value("key", "01"));
                dr = sub_decrypt(data, actual, key.empty() ? 1 : key[0]);
            } else if (algo == "rolling_xor") {
                auto seed_bytes = parse_hex_key(p.value("seed", "00"));
                dr = rolling_xor_decrypt(data, actual, seed_bytes.empty() ? 0 : seed_bytes[0]);
            } else if (algo == "reverse") {
                dr = reverse_bytes(data, actual);
            } else {
                dr = auto_decrypt(data, actual);
            }

            if (!dr.success) return err(dr.note.empty() ? "Decryption failed" : dr.note);

            // write back to binary if requested
            if (p.value("write_back", false) && !dr.output.empty()) {
                auto off = img.va_to_offset(addr);
                if (off && *off + dr.output.size() <= img.raw.size()) {
                    memcpy(img.raw.data() + *off, dr.output.data(), dr.output.size());
                }
            }

            // save to file if requested
            if (p.contains("save_to") && !dr.output.empty()) {
                std::string save_path = p["save_to"].get<std::string>();
                FILE* f = fopen(save_path.c_str(), "wb");
                if (f) {
                    fwrite(dr.output.data(), 1, dr.output.size(), f);
                    fclose(f);
                }
            }

            // build hex preview of first 256 bytes
            std::string hex_preview;
            size_t preview_len = std::min(dr.output.size(), (size_t)256);
            for (size_t i = 0; i < preview_len; i++) {
                char h[4]; snprintf(h, sizeof(h), "%02X ", dr.output[i]);
                hex_preview += h;
            }

            // ASCII preview
            std::string ascii_preview;
            for (size_t i = 0; i < preview_len; i++) {
                ascii_preview += (dr.output[i] >= 0x20 && dr.output[i] < 0x7F) ?
                    (char)dr.output[i] : '.';
            }

            json r;
            r["success"] = true;
            r["algorithm"] = dr.algorithm;
            r["note"] = dr.note;
            r["input_length"] = actual;
            r["output_length"] = dr.output.size();
            r["entropy_before"] = dr.entropy_before;
            r["entropy_after"] = dr.entropy_after;
            r["hex_preview"] = hex_preview;
            r["ascii_preview"] = ascii_preview;
            r["wrote_back"] = p.value("write_back", false);
            if (p.value("write_back", false))
                sess->bump("decrypt write_back @ 0x" + std::to_string(addr));
            if (p.contains("save_to")) r["saved_to"] = p["save_to"];
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // vuln_scan - identify potential vulnerabilities based on imports/strings
    // -------------------------------------------------------------------------
    server.register_tool({
        "vuln_scan",
        "Scan the loaded binary for potential vulnerabilities, dangerous API usage, known-vulnerable patterns, and generate a list of relevant CVEs. Checks imports for unsafe functions, strings for hardcoded credentials/keys, and known vulnerable library versions.",
        {{"type", "object"}, {"properties", {
            {"deep", schema_prop("boolean", "Enable deep scan: also check xrefs and function patterns (slower, default false)")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            bool deep = p.value("deep", false);

            struct Finding {
                std::string category;
                std::string severity; // critical, high, medium, low, info
                std::string description;
                uint64_t addr;
                std::string detail;
                std::vector<std::string> cves;
            };
            std::vector<Finding> findings;

            // ---- dangerous imports ----
            struct DangerousAPI {
                std::string name;
                std::string severity;
                std::string desc;
                std::vector<std::string> cves;
            };
            std::vector<DangerousAPI> dangerous_apis = {
                {"strcpy",   "high",   "Buffer overflow: unbounded string copy", {"CWE-120"}},
                {"strcat",   "high",   "Buffer overflow: unbounded string concatenation", {"CWE-120"}},
                {"sprintf",  "high",   "Buffer overflow: unbounded formatted write", {"CWE-120"}},
                {"gets",     "critical","Buffer overflow: reads until newline with no bounds", {"CWE-120", "CWE-676"}},
                {"scanf",    "medium", "Buffer overflow: unbounded input without width specifier", {"CWE-120"}},
                {"vsprintf", "high",   "Buffer overflow: unbounded formatted write (variadic)", {"CWE-120"}},
                {"lstrcpyA", "high",   "Buffer overflow: Win32 unbounded string copy", {"CWE-120"}},
                {"lstrcpyW", "high",   "Buffer overflow: Win32 unbounded string copy (wide)", {"CWE-120"}},
                {"lstrcatA", "high",   "Buffer overflow: Win32 unbounded string concat", {"CWE-120"}},
                {"memcpy",   "info",   "Potential buffer overflow if size is user-controlled", {"CWE-120"}},
                {"alloca",   "medium", "Stack overflow: dynamic stack allocation", {"CWE-770"}},
                {"system",   "high",   "Command injection: executes shell command", {"CWE-78"}},
                {"_popen",   "high",   "Command injection: pipe to shell", {"CWE-78"}},
                {"popen",    "high",   "Command injection: pipe to shell", {"CWE-78"}},
                {"WinExec",  "high",   "Command injection: executes program", {"CWE-78"}},
                {"ShellExecuteA", "medium", "Process execution: may be used for command injection", {"CWE-78"}},
                {"ShellExecuteW", "medium", "Process execution: may be used for command injection", {"CWE-78"}},
                {"LoadLibraryA",  "medium", "DLL loading: potential DLL hijacking if path not absolute", {"CWE-426", "CWE-427"}},
                {"LoadLibraryW",  "medium", "DLL loading: potential DLL hijacking if path not absolute", {"CWE-426", "CWE-427"}},
                {"SetWindowsHookExA", "medium", "API hooking: used for keylogging/injection", {}},
                {"SetWindowsHookExW", "medium", "API hooking: used for keylogging/injection", {}},
                {"VirtualAllocEx",    "medium", "Remote memory allocation: used for process injection", {}},
                {"WriteProcessMemory","medium", "Remote memory write: used for process injection", {}},
                {"CreateRemoteThread","high",   "Remote thread creation: classic injection technique", {}},
                {"NtCreateThreadEx",  "high",   "Remote thread creation (NT): stealthier injection", {}},
                {"RtlCreateUserThread","high",  "Remote thread creation (undocumented): injection", {}},
                {"OpenProcess",       "info",   "Process handle acquisition: prerequisite for injection", {}},
                {"VirtualProtect",    "info",   "Memory permission change: may indicate shellcode execution", {}},
                {"VirtualProtectEx",  "medium", "Remote memory permission change", {}},
                {"InternetOpenA",     "info",   "Network activity: HTTP client initialization", {}},
                {"InternetOpenUrlA",  "info",   "Network activity: URL fetch", {}},
                {"URLDownloadToFileA","medium", "Network download: may fetch second-stage payload", {}},
                {"URLDownloadToFileW","medium", "Network download: may fetch second-stage payload", {}},
                {"CryptEncrypt",  "info",   "Crypto API: may indicate ransomware behavior", {}},
                {"CryptDecrypt",  "info",   "Crypto API: decryption routine", {}},
                {"RegSetValueExA","info",   "Registry write: possible persistence mechanism", {}},
                {"RegSetValueExW","info",   "Registry write: possible persistence mechanism", {}},
                {"NtQuerySystemInformation","info","NT API: system enumeration, may indicate anti-debug/evasion",{}},
                {"IsDebuggerPresent",       "info","Anti-debug check", {}},
                {"CheckRemoteDebuggerPresent","info","Anti-debug check (remote)", {}},
                {"NtSetInformationThread",  "info","May be used to hide threads from debugger", {}},
            };

            for (auto& imp : img.imports) {
                for (auto& da : dangerous_apis) {
                    if (imp.name == da.name) {
                        Finding f;
                        f.category = "dangerous_import";
                        f.severity = da.severity;
                        f.description = da.desc;
                        f.addr = imp.iat_rva + img.base;
                        f.detail = imp.module + "!" + imp.name;
                        f.cves = da.cves;
                        findings.push_back(std::move(f));
                    }
                }
            }

            // ---- string-based indicators ----
            struct StringPattern {
                std::string pattern;
                std::string category;
                std::string severity;
                std::string desc;
            };
            std::vector<StringPattern> string_patterns = {
                {"password",    "hardcoded_cred", "high",   "Possible hardcoded password"},
                {"passwd",      "hardcoded_cred", "high",   "Possible hardcoded password"},
                {"secret",      "hardcoded_cred", "medium", "Possible hardcoded secret"},
                {"api_key",     "hardcoded_cred", "high",   "Possible hardcoded API key"},
                {"apikey",      "hardcoded_cred", "high",   "Possible hardcoded API key"},
                {"private_key", "hardcoded_cred", "critical","Possible hardcoded private key"},
                {"BEGIN RSA",   "hardcoded_cred", "critical","Embedded RSA private key"},
                {"BEGIN PRIVATE","hardcoded_cred","critical","Embedded private key"},
                {"BEGIN CERTIFICATE","crypto",    "info",   "Embedded X.509 certificate"},
                {"SELECT ",     "sql_injection",  "medium", "SQL query in binary (potential SQLi)"},
                {"INSERT INTO", "sql_injection",  "medium", "SQL query in binary"},
                {"DROP TABLE",  "sql_injection",  "high",   "Destructive SQL in binary"},
                {"cmd.exe",     "command_exec",   "medium", "Reference to command shell"},
                {"powershell",  "command_exec",   "medium", "Reference to PowerShell"},
                {"/bin/sh",     "command_exec",   "medium", "Reference to Unix shell"},
                {"/bin/bash",   "command_exec",   "medium", "Reference to Bash shell"},
                {"\\\\PIPE\\",  "ipc",            "info",   "Named pipe communication"},
                {"HKEY_",       "registry",       "info",   "Registry access"},
                {"CurrentVersion\\Run","persistence","medium","Run key persistence mechanism"},
                {"Software\\Microsoft\\Windows\\CurrentVersion\\Run","persistence","high","Autorun persistence"},
                {".onion",      "network",        "medium", "Tor hidden service reference"},
                {"bitcoin",     "crypto_currency","info",   "Cryptocurrency reference"},
                {"wallet",      "crypto_currency","info",   "Wallet reference"},
                {"ransom",      "ransomware",     "critical","Ransom-related string"},
                {"encrypt",     "crypto",         "info",   "Encryption reference"},
                {"decrypt",     "crypto",         "info",   "Decryption reference"},
                {"OpenSSL",     "library_version","info",   "OpenSSL library detected"},
                {"libcurl",     "library_version","info",   "libcurl detected"},
                {"sqlite",      "library_version","info",   "SQLite detected"},
            };

            for (auto& s : img.strings) {
                std::string lower = s.value;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                for (auto& sp : string_patterns) {
                    std::string pat_lower = sp.pattern;
                    std::transform(pat_lower.begin(), pat_lower.end(), pat_lower.begin(), ::tolower);
                    if (lower.find(pat_lower) != std::string::npos) {
                        Finding f;
                        f.category = sp.category;
                        f.severity = sp.severity;
                        f.description = sp.desc;
                        f.addr = s.addr;
                        f.detail = s.value.substr(0, 120);
                        findings.push_back(std::move(f));
                        break;
                    }
                }
            }

            // ---- known vulnerable library versions from strings ----
            struct VulnLib {
                std::string prefix;
                std::string lib;
                std::vector<std::string> cves;
                std::string note;
            };
            std::vector<VulnLib> vuln_libs = {
                {"OpenSSL 1.0.", "OpenSSL", {"CVE-2014-0160", "CVE-2016-2107"}, "OpenSSL 1.0.x: Heartbleed, padding oracle"},
                {"OpenSSL 1.1.0", "OpenSSL", {"CVE-2017-3735", "CVE-2018-0732"}, "OpenSSL 1.1.0: multiple vulns"},
                {"OpenSSL 3.0.", "OpenSSL", {"CVE-2022-3602", "CVE-2022-3786"}, "OpenSSL 3.0.x: X.509 buffer overflows"},
                {"libcurl/7.", "libcurl", {"CVE-2023-27533", "CVE-2023-27534"}, "libcurl 7.x: TELNET/SFTP path traversal"},
                {"sqlite 3.3", "SQLite", {"CVE-2020-15358"}, "SQLite 3.3x: heap overflow"},
                {"zlib 1.2.1", "zlib", {"CVE-2022-37434"}, "zlib 1.2.1x: heap-based buffer overflow in inflate"},
                {"expat_2.1", "Expat XML", {"CVE-2022-25313", "CVE-2022-25314"}, "Expat 2.1.x: stack exhaustion, integer overflow"},
                {"log4j", "Log4j", {"CVE-2021-44228"}, "Log4Shell: critical RCE"},
            };

            for (auto& s : img.strings) {
                for (auto& vl : vuln_libs) {
                    if (s.value.find(vl.prefix) != std::string::npos) {
                        Finding f;
                        f.category = "vulnerable_library";
                        f.severity = "high";
                        f.description = vl.note;
                        f.addr = s.addr;
                        f.detail = s.value.substr(0, 120);
                        f.cves = vl.cves;
                        findings.push_back(std::move(f));
                    }
                }
            }

            // ---- deep scan: check for no-ASLR / no-DEP / no-stack-cookie ----
            if (img.format == BinaryFormat::PE) {
                // check PE optional header DllCharacteristics
                // bit 0x40 = DYNAMIC_BASE (ASLR), bit 0x100 = NX_COMPAT (DEP)
                if (img.raw.size() > 0x40) {
                    uint32_t pe_off = *(uint32_t*)(img.raw.data() + 0x3C);
                    if (pe_off + 0x5E < img.raw.size()) {
                        uint16_t dll_chars = *(uint16_t*)(img.raw.data() + pe_off + 0x5E);
                        bool is_64 = *(uint16_t*)(img.raw.data() + pe_off + 0x18) == 0x20B;
                        if (is_64 && pe_off + 0x70 < img.raw.size())
                            dll_chars = *(uint16_t*)(img.raw.data() + pe_off + 0x70);

                        if (!(dll_chars & 0x0040)) {
                            findings.push_back({"mitigation", "high",
                                "ASLR disabled: DllCharacteristics missing DYNAMIC_BASE (0x40)",
                                img.base, "Exploitation is significantly easier without ASLR",
                                {"CWE-119"}});
                        }
                        if (!(dll_chars & 0x0100)) {
                            findings.push_back({"mitigation", "high",
                                "DEP/NX disabled: DllCharacteristics missing NX_COMPAT (0x100)",
                                img.base, "Stack/heap shellcode execution is possible",
                                {"CWE-119"}});
                        }
                        if (!(dll_chars & 0x0400)) {
                            findings.push_back({"mitigation", "medium",
                                "No SEH protection: DllCharacteristics missing NO_SEH (0x0400)",
                                img.base, "SEH overwrite attacks possible", {}});
                        }
                    }
                }
                // check for /GS cookie via __security_check_cookie import
                bool has_gs = false;
                for (auto& imp : img.imports)
                    if (imp.name == "__security_check_cookie" || imp.name == "__stack_chk_fail")
                        has_gs = true;
                if (!has_gs && img.functions.size() > 5) {
                    findings.push_back({"mitigation", "medium",
                        "No stack canary: __security_check_cookie not imported",
                        0, "Stack buffer overflows may be exploitable without cookie checks",
                        {"CWE-121"}});
                }
            }

            // ---- deep scan: RWX sections ----
            for (auto& sec : img.sections) {
                if (sec.executable && sec.writable && sec.file_size > 0) {
                    findings.push_back({"mitigation", "high",
                        "RWX section: " + sec.name + " is both writable and executable",
                        sec.vaddr, "Attacker can write and execute shellcode directly",
                        {"CWE-119"}});
                }
            }

            // ---- deep scan: look for format string vulns via xrefs ----
            if (deep) {
                std::set<std::string> fmt_funcs = {
                    "printf", "fprintf", "sprintf", "snprintf", "vprintf",
                    "vfprintf", "vsprintf", "vsnprintf", "wprintf", "swprintf",
                    "syslog", "OutputDebugStringA"
                };
                for (auto& [fa, func] : img.functions) {
                    if (fmt_funcs.count(func.name)) {
                        for (auto& xr : img.xrefs) {
                            if (xr.to == fa && xr.type == XrefType::Call) {
                                findings.push_back({"format_string", "medium",
                                    "Call to format function " + func.name,
                                    xr.from, "Verify format string is not user-controlled",
                                    {"CWE-134"}});
                            }
                        }
                    }
                }
            }

            // build response
            json result = json::object();
            json findings_json = json::array();
            std::map<std::string, int> severity_counts;
            std::set<std::string> all_cves;

            for (auto& f : findings) {
                json fj;
                fj["category"] = f.category;
                fj["severity"] = f.severity;
                fj["description"] = f.description;
                if (f.addr) fj["addr"] = f.addr;
                if (!f.detail.empty()) fj["detail"] = f.detail;
                if (!f.cves.empty()) {
                    fj["cves"] = f.cves;
                    for (auto& c : f.cves) all_cves.insert(c);
                }
                findings_json.push_back(std::move(fj));
                severity_counts[f.severity]++;
            }

            result["findings"] = findings_json;
            result["total_findings"] = findings.size();
            result["severity_summary"] = severity_counts;
            result["cves_referenced"] = std::vector<std::string>(all_cves.begin(), all_cves.end());
            result["deep_scan"] = deep;
            return result;
        }
    });

    // -------------------------------------------------------------------------
    // idb_save
    // -------------------------------------------------------------------------
    server.register_tool({
        "idb_save",
        "Save the current analysis state (renames, comments) to the .aida project database.",
        {{"type", "object"}, {"properties", json::object()}},
        [sess](const json&) -> json {
            REQUIRE_IMAGE();
            std::string db_path = sess->image->path + ".aida";
            bool ok = save_project(*sess->image, db_path);
            json r;
            r["success"] = ok;
            r["path"] = db_path;
            r["user_names"] = sess->image->user_names.size();
            r["user_comments"] = sess->image->user_comments.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // get_notes - read shared notes (AI + human editable)
    // -------------------------------------------------------------------------
    server.register_tool({
        "get_notes",
        "Read the shared notes pad. Both the AI and the human GUI user can edit this.",
        {{"type", "object"}, {"properties", json::object()}},
        [sess](const json&) -> json {
            std::lock_guard<std::mutex> lock(sess->mtx);
            json r;
            r["notes"] = sess->notes;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // set_notes - write shared notes
    // -------------------------------------------------------------------------
    server.register_tool({
        "set_notes",
        "Write to the shared notes pad. Replaces all notes content. Both AI and human can edit.",
        {{"type", "object"}, {"properties", {
            {"text", schema_prop("string", "Full notes text to set")},
            {"append", schema_prop("string", "Text to append to existing notes (use instead of text to add without replacing)")}
        }}},
        [sess](const json& p) -> json {
            std::lock_guard<std::mutex> lock(sess->mtx);
            if (p.contains("append")) {
                std::string add = p["append"].get<std::string>();
                if (!sess->notes.empty() && sess->notes.back() != '\n')
                    sess->notes += "\n";
                sess->notes += add;
            } else if (p.contains("text")) {
                sess->notes = p["text"].get<std::string>();
            }
            sess->bump("set_notes");
            json r;
            r["success"] = true;
            r["length"] = sess->notes.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // network_scan - get URLs, IPs, domains, emails, MACs from the binary
    // -------------------------------------------------------------------------
    server.register_tool({
        "network_scan",
        "Get all network references found in the binary: URLs, IPv4 addresses, domains, emails, MAC addresses, port references. Essential for firmware analysis.",
        {{"type", "object"}, {"properties", {
            {"type_filter", schema_prop("string", "Filter by type: url, ipv4, domain, email, mac, port (omit for all)")},
            {"filter", schema_prop("string", "Substring filter on value")}
        }}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;

            std::string type_f = p.value("type_filter", "");
            std::string val_f = p.value("filter", "");

            json refs = json::array();
            for (auto& nr : img.network_refs) {
                if (!type_f.empty() && nr.type != type_f) continue;
                if (!val_f.empty() && nr.value.find(val_f) == std::string::npos) continue;
                refs.push_back({
                    {"addr", nr.addr}, {"type", nr.type}, {"value", nr.value}
                });
            }

            json r;
            r["total_network_refs"] = img.network_refs.size();
            r["returned"] = refs.size();
            r["refs"] = refs;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // add_bookmark - bookmark an address for quick access
    // -------------------------------------------------------------------------
    server.register_tool({
        "add_bookmark",
        "Bookmark an address for quick navigation. Shows in the GUI Bookmarks panel.",
        {{"type", "object"}, {"properties", {
            {"addr", schema_prop("integer", "Address to bookmark")}
        }}, {"required", json::array({"addr"})}},
        [sess](const json& p) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            uint64_t addr = parse_addr(p, "addr");

            for (auto a : img.bookmarks)
                if (a == addr) return err("Already bookmarked");

            img.bookmarks.push_back(addr);
            sess->bump("bookmark 0x" + std::to_string(addr));

            json r;
            r["success"] = true;
            r["addr"] = addr;
            r["total_bookmarks"] = img.bookmarks.size();
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // get_bookmarks - list all bookmarks
    // -------------------------------------------------------------------------
    server.register_tool({
        "get_bookmarks",
        "List all bookmarked addresses.",
        {{"type", "object"}, {"properties", json::object()}},
        [sess](const json&) -> json {
            REQUIRE_IMAGE();
            auto& img = *sess->image;
            json bmarks = json::array();
            for (auto addr : img.bookmarks) {
                json b;
                b["addr"] = addr;
                auto fit = img.functions.find(addr);
                if (fit != img.functions.end())
                    b["name"] = fit->second.name;
                auto cit = img.user_comments.find(addr);
                if (cit != img.user_comments.end())
                    b["comment"] = cit->second;
                bmarks.push_back(b);
            }
            json r;
            r["bookmarks"] = bmarks;
            return r;
        }
    });

    // -------------------------------------------------------------------------
    // server_health
    // -------------------------------------------------------------------------
    server.register_tool({
        "server_health",
        "Check the MCP server health and loaded binary status.",
        {{"type", "object"}, {"properties", json::object()}},
        [sess](const json&) -> json {
            json r;
            r["status"] = "ok";
            r["binary_loaded"] = sess->image != nullptr;
            if (sess->image) {
                r["binary_path"] = sess->image->path;
                r["binary_format"] = static_cast<int>(sess->image->format);
                r["num_functions"] = sess->image->functions.size();
            }
            r["num_tools"] = 32;
            r["generation"] = sess->generation.load();
            r["last_action"] = sess->last_action;
            return r;
        }
    });

    #undef REQUIRE_IMAGE
}

}
