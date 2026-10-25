#include "core/analysis.hpp"
#include "core/disasm.hpp"
#include "core/crypto_scan.hpp"
#include "core/entropy.hpp"
#include "core/imphash.hpp"
#include "core/firmware.hpp"
#include <capstone/capstone.h>
#include <algorithm>
#include <set>
#include <cstring>
#include <regex>

static csh cs_handle() { return reinterpret_cast<csh>(aida::cs_handle_raw()); }

namespace aida {

void apply_imports_as_functions(BinaryImage& img) {
    for (auto& imp : img.imports) {
        if (imp.iat_rva && !imp.name.empty()) {
            if (img.functions.find(imp.iat_rva) == img.functions.end()) {
                Function f;
                f.addr = imp.iat_rva;
                f.end_addr = f.addr;
                f.name = imp.module + "!" + imp.name;
                f.is_import = true;
                img.functions[f.addr] = std::move(f);
            }
        }
    }
}

void apply_exports_as_functions(BinaryImage& img) {
    for (auto& exp : img.exports) {
        if (exp.forwarded) continue;
        uint64_t addr = img.base + exp.rva;
        auto it = img.functions.find(addr);
        if (it != img.functions.end()) {
            if (!exp.name.empty() && !it->second.user_named)
                it->second.name = exp.name;
            it->second.is_export = true;
        } else {
            Function f;
            f.addr = addr;
            f.name = exp.name.empty() ? "export_" + std::to_string(exp.ordinal) : exp.name;
            f.is_export = true;
            img.functions[f.addr] = std::move(f);
        }
    }
}

void apply_symbols_as_functions(BinaryImage& img) {
    for (auto& sym : img.symbols) {
        if (!sym.is_func || sym.addr == 0) continue;
        auto it = img.functions.find(sym.addr);
        if (it != img.functions.end()) {
            if (!sym.name.empty() && !it->second.user_named)
                it->second.name = sym.name;
        } else {
            Function f;
            f.addr = sym.addr;
            f.end_addr = sym.size ? sym.addr + sym.size : 0;
            f.name = sym.name;
            img.functions[f.addr] = std::move(f);
        }
    }
}

static void scan_prologues_x86(BinaryImage& img, std::set<uint64_t>& found) {
    bool is_64 = (img.arch == Arch::X86_64);

    for (auto& sec : img.sections) {
        if (!sec.executable) continue;
        if (sec.file_off + sec.file_size > img.raw.size()) continue;

        const uint8_t* code = img.raw.data() + sec.file_off;
        size_t sz = sec.file_size;
        uint64_t base = sec.vaddr;

        for (size_t i = 0; i + 4 < sz; i++) {
            uint64_t addr = base + i;
            if (img.functions.count(addr) || found.count(addr)) continue;

            bool match = false;

            if (is_64) {
                // push rbp; mov rbp, rsp (55 48 89 E5)
                if (i + 4 <= sz && code[i] == 0x55 && code[i+1] == 0x48 &&
                    code[i+2] == 0x89 && code[i+3] == 0xE5)
                    match = true;
                // sub rsp, imm8 (48 83 EC xx)
                else if (i + 4 <= sz && code[i] == 0x48 && code[i+1] == 0x83 &&
                         code[i+2] == 0xEC)
                    match = true;
                // push rbx; sub rsp (common MSVC 64-bit)
                else if (i + 5 <= sz && code[i] == 0x40 && code[i+1] == 0x53 &&
                         code[i+2] == 0x48 && code[i+3] == 0x83 && code[i+4] == 0xEC)
                    match = true;
                // mov [rsp+8], rcx (MSVC fastcall home) (48 89 4C 24 08)
                else if (i + 5 <= sz && code[i] == 0x48 && code[i+1] == 0x89 &&
                         code[i+2] == 0x4C && code[i+3] == 0x24 && code[i+4] == 0x08)
                    match = true;
                // mov qword ptr [rsp+X], rbx (48 89 5C 24 xx) -- MSVC nonvol save
                else if (i + 5 <= sz && code[i] == 0x48 && code[i+1] == 0x89 &&
                         code[i+2] == 0x5C && code[i+3] == 0x24)
                    match = true;
            } else {
                // push ebp; mov ebp, esp (55 8B EC or 55 89 E5)
                if (i + 3 <= sz && code[i] == 0x55 &&
                    ((code[i+1] == 0x8B && code[i+2] == 0xEC) ||
                     (code[i+1] == 0x89 && code[i+2] == 0xE5)))
                    match = true;
            }

            // CC padding -> non-CC = function boundary (MSVC)
            if (!match && i > 0 && code[i-1] == 0xCC && code[i] != 0xCC && code[i] != 0x00) {
                // verify the new byte is a plausible instruction start
                if (code[i] == 0x55 || code[i] == 0x53 || code[i] == 0x56 || code[i] == 0x57 ||
                    code[i] == 0x41 || code[i] == 0x48 || code[i] == 0x40 || code[i] == 0xB8 ||
                    code[i] == 0xE9 || code[i] == 0x33 || code[i] == 0x31)
                    match = true;
            }

            if (match) found.insert(addr);
        }
    }
}

static void scan_prologues_arm64(BinaryImage& img, std::set<uint64_t>& found) {
    for (auto& sec : img.sections) {
        if (!sec.executable) continue;
        if (sec.file_off + sec.file_size > img.raw.size()) continue;

        const uint8_t* code = img.raw.data() + sec.file_off;
        size_t sz = sec.file_size;
        uint64_t base = sec.vaddr;

        for (size_t i = 0; i + 8 <= sz; i += 4) {
            uint64_t addr = base + i;
            if (img.functions.count(addr) || found.count(addr)) continue;

            uint32_t insn = code[i] | (code[i+1] << 8) | (code[i+2] << 16) | (code[i+3] << 24);
            // stp x29, x30, [sp, #-N]! -- typical prologue
            // encoding: 1010100110xxxxxx 011111xx xxxxxxxx (A9B = STP pre-index, x29+x30)
            if ((insn & 0xFFE07FFF) == 0xA9A07BFD || // stp x29, x30, [sp, #-imm]!
                (insn & 0xFFC003FF) == 0xA98003E0)   // stp xN, xN, [sp, #-imm]! (broad)
                found.insert(addr);
            // sub sp, sp, #imm (D10003FF mask)
            else if ((insn & 0xFF0003FF) == 0xD10003FF)
                found.insert(addr);
        }
    }
}

void discover_functions(BinaryImage& img) {
    if (!init_disassembler(img.arch)) {
        fprintf(stderr, "[!] Disassembler failed to init for arch %d\n", static_cast<int>(img.arch));
        return;
    }

    fprintf(stderr, "[*] Phase 1: Seeding entry/imports/exports/symbols...\n");

    if (img.entry) {
        if (img.functions.find(img.entry) == img.functions.end()) {
            Function f;
            f.addr = img.entry;
            f.name = "_entry";
            img.functions[f.addr] = std::move(f);
        }
    }

    apply_imports_as_functions(img);
    apply_exports_as_functions(img);
    apply_symbols_as_functions(img);

    size_t seed_count = img.functions.size();
    fprintf(stderr, "[+] Seeded %zu functions (entry + imports + exports + symbols)\n", seed_count);

    fprintf(stderr, "[*] Phase 2: Linear sweep for call targets...\n");

    std::set<uint64_t> call_targets;
    bool is_x86 = (img.arch == Arch::X86 || img.arch == Arch::X86_64);
    bool is_mips = (img.arch == Arch::MIPS_LE || img.arch == Arch::MIPS_BE ||
                    img.arch == Arch::MIPS64_LE || img.arch == Arch::MIPS64_BE);
    bool is_arm = (img.arch == Arch::ARM || img.arch == Arch::ARM64);

    for (auto& sec : img.sections) {
        if (!sec.executable) continue;
        if (sec.file_off + sec.file_size > img.raw.size()) continue;

        const uint8_t* code = img.raw.data() + sec.file_off;
        size_t code_sz = sec.file_size;
        uint64_t base = sec.vaddr;

        fprintf(stderr, "[*]   Scanning %s (0x%llX, %zu bytes)...\n",
            sec.name.c_str(), (unsigned long long)base, code_sz);

        cs_insn* insns = nullptr;
        size_t count = cs_disasm(cs_handle(), code, code_sz, base, 0, &insns);

        if (count == 0) {
            fprintf(stderr, "[!]   Section %s: 0 instructions decoded (encrypted/obfuscated?)\n", sec.name.c_str());
        } else {
            fprintf(stderr, "[+]   Decoded %zu instructions\n", count);
        }

        for (size_t i = 0; i < count; i++) {
            cs_detail* d = insns[i].detail;
            if (!d) continue;

            if (is_x86) {
                for (uint8_t g = 0; g < d->groups_count; g++) {
                    if (d->groups[g] == X86_GRP_CALL) {
                        auto& x86 = d->x86;
                        for (uint8_t o = 0; o < x86.op_count; o++) {
                            if (x86.operands[o].type == X86_OP_IMM) {
                                call_targets.insert(static_cast<uint64_t>(x86.operands[o].imm));
                            }
                        }
                    }
                }
            } else if (is_mips) {
                const char* mn = insns[i].mnemonic;
                if (strncmp(mn, "jal", 3) == 0 || strncmp(mn, "bal", 3) == 0) {
                    auto& mips = d->mips;
                    for (uint8_t o = 0; o < mips.op_count; o++) {
                        if (mips.operands[o].type == MIPS_OP_IMM) {
                            call_targets.insert(static_cast<uint64_t>(mips.operands[o].imm));
                        }
                    }
                }
            } else if (is_arm) {
                for (uint8_t g = 0; g < d->groups_count; g++) {
                    if (d->groups[g] == ARM_GRP_CALL || d->groups[g] == ARM64_GRP_CALL) {
                        auto& arm = d->arm;
                        for (uint8_t o = 0; o < arm.op_count; o++) {
                            if (arm.operands[o].type == ARM_OP_IMM) {
                                call_targets.insert(static_cast<uint64_t>(arm.operands[o].imm));
                            }
                        }
                    }
                }
            }
        }

        if (insns) cs_free(insns, count);
    }

    size_t call_funcs = 0;
    for (uint64_t target : call_targets) {
        if (img.functions.count(target)) continue;
        auto* sec = img.section_for_va(target);
        if (!sec || !sec->executable) continue;

        Function f;
        f.addr = target;
        char buf[32];
        snprintf(buf, sizeof(buf), "sub_%llX", (unsigned long long)target);
        f.name = buf;
        img.functions[f.addr] = std::move(f);
        call_funcs++;
    }
    fprintf(stderr, "[+] Found %zu call targets -> %zu new functions\n", call_targets.size(), call_funcs);

    // Phase 3: prologue pattern scanning
    fprintf(stderr, "[*] Phase 3: Prologue pattern scan...\n");
    std::set<uint64_t> prologue_funcs;

    if (is_x86)
        scan_prologues_x86(img, prologue_funcs);
    else if (img.arch == Arch::ARM64)
        scan_prologues_arm64(img, prologue_funcs);

    size_t prologue_count = 0;
    for (uint64_t addr : prologue_funcs) {
        if (img.functions.count(addr)) continue;
        Function f;
        f.addr = addr;
        char buf[32];
        snprintf(buf, sizeof(buf), "sub_%llX", (unsigned long long)addr);
        f.name = buf;
        img.functions[f.addr] = std::move(f);
        prologue_count++;
    }
    fprintf(stderr, "[+] Prologue scan found %zu new functions\n", prologue_count);
    fprintf(stderr, "[+] Total: %zu functions discovered\n", img.functions.size());
}

void extract_strings(BinaryImage& img, size_t min_len) {
    img.strings.clear();

    for (auto& sec : img.sections) {
        if (sec.executable) continue;
        if (sec.file_off + sec.file_size > img.raw.size()) continue;

        const uint8_t* p = img.raw.data() + sec.file_off;
        size_t sz = sec.file_size;

        size_t run_start = 0;
        bool in_run = false;
        for (size_t i = 0; i < sz; i++) {
            bool printable = (p[i] >= 0x20 && p[i] < 0x7F) || p[i] == '\t' || p[i] == '\n' || p[i] == '\r';
            if (printable) {
                if (!in_run) { run_start = i; in_run = true; }
            } else {
                if (in_run && (i - run_start) >= min_len && p[i] == 0) {
                    FoundString fs;
                    fs.addr = sec.vaddr + run_start;
                    fs.value = std::string(reinterpret_cast<const char*>(p + run_start), i - run_start);
                    fs.wide = false;
                    img.strings.push_back(std::move(fs));
                }
                in_run = false;
            }
        }

        if (sz >= 4) {
            run_start = 0;
            in_run = false;
            for (size_t i = 0; i + 1 < sz; i += 2) {
                uint16_t ch = p[i] | (p[i + 1] << 8);
                bool printable = (ch >= 0x20 && ch < 0x7F) || ch == '\t' || ch == '\n' || ch == '\r';
                if (printable) {
                    if (!in_run) { run_start = i; in_run = true; }
                } else {
                    if (in_run && ((i - run_start) / 2) >= min_len && ch == 0) {
                        FoundString fs;
                        fs.addr = sec.vaddr + run_start;
                        for (size_t j = run_start; j < i; j += 2) {
                            uint16_t c = p[j] | (p[j + 1] << 8);
                            if (c < 0x80) fs.value += static_cast<char>(c);
                            else fs.value += '?';
                        }
                        fs.wide = true;
                        img.strings.push_back(std::move(fs));
                    }
                    in_run = false;
                }
            }
        }
    }

    std::sort(img.strings.begin(), img.strings.end(),
              [](const FoundString& a, const FoundString& b) { return a.addr < b.addr; });
}

void build_xrefs(BinaryImage& img) {
    img.xrefs.clear();
    if (!init_disassembler(img.arch)) {
        fprintf(stderr, "[!] Disassembler failed to init for xref analysis\n");
        return;
    }

    std::set<uint64_t> func_addrs;
    for (auto& [addr, _] : img.functions) func_addrs.insert(addr);

    std::set<uint64_t> str_addrs;
    for (auto& s : img.strings) str_addrs.insert(s.addr);

    bool is_x86 = (img.arch == Arch::X86 || img.arch == Arch::X86_64);
    bool is_mips = (img.arch == Arch::MIPS_LE || img.arch == Arch::MIPS_BE ||
                    img.arch == Arch::MIPS64_LE || img.arch == Arch::MIPS64_BE);

    for (auto& sec : img.sections) {
        if (!sec.executable) continue;
        if (sec.file_off + sec.file_size > img.raw.size()) continue;

        const uint8_t* code = img.raw.data() + sec.file_off;
        size_t code_sz = sec.file_size;
        uint64_t base = sec.vaddr;

        cs_insn* insns = nullptr;
        size_t count = cs_disasm(cs_handle(), code, code_sz, base, 0, &insns);

        for (size_t i = 0; i < count; i++) {
            cs_detail* d = insns[i].detail;
            if (!d) continue;

            std::set<uint64_t> referenced;

            if (is_x86) {
                auto& x86 = d->x86;
                for (uint8_t o = 0; o < x86.op_count; o++) {
                    if (x86.operands[o].type == X86_OP_IMM)
                        referenced.insert(static_cast<uint64_t>(x86.operands[o].imm));
                    else if (x86.operands[o].type == X86_OP_MEM && x86.operands[o].mem.disp)
                        referenced.insert(static_cast<uint64_t>(x86.operands[o].mem.disp));
                }
            } else if (is_mips) {
                auto& mips = d->mips;
                for (uint8_t o = 0; o < mips.op_count; o++) {
                    if (mips.operands[o].type == MIPS_OP_IMM)
                        referenced.insert(static_cast<uint64_t>(mips.operands[o].imm));
                    else if (mips.operands[o].type == MIPS_OP_MEM && mips.operands[o].mem.disp)
                        referenced.insert(static_cast<uint64_t>(mips.operands[o].mem.disp));
                }
            } else {
                auto& arm = d->arm;
                for (uint8_t o = 0; o < arm.op_count; o++) {
                    if (arm.operands[o].type == ARM_OP_IMM)
                        referenced.insert(static_cast<uint64_t>(arm.operands[o].imm));
                }
            }

            uint64_t from = insns[i].address;
            for (uint64_t target : referenced) {
                if (func_addrs.count(target)) {
                    Xref xr;
                    xr.from = from;
                    xr.to = target;
                    xr.type = XrefType::Call;
                    img.xrefs.push_back(xr);
                }
                if (str_addrs.count(target)) {
                    Xref xr;
                    xr.from = from;
                    xr.to = target;
                    xr.type = XrefType::String;
                    img.xrefs.push_back(xr);
                }
            }
        }

        if (insns) cs_free(insns, count);
    }

    // Pre-build xref_to_idx: target addr -> list of xref indices pointing TO it
    img.xref_to_idx.clear();
    img.xref_to_idx.reserve(img.xrefs.size() / 2);
    for (uint32_t i = 0; i < static_cast<uint32_t>(img.xrefs.size()); i++) {
        img.xref_to_idx[img.xrefs[i].to].push_back(i);
    }

    // Sort xrefs by 'from' address for fast range queries on outgoing refs
    std::sort(img.xrefs.begin(), img.xrefs.end(),
              [](const Xref& a, const Xref& b) { return a.from < b.from; });

    // Rebuild xref_to_idx after sort since indices changed
    img.xref_to_idx.clear();
    for (uint32_t i = 0; i < static_cast<uint32_t>(img.xrefs.size()); i++) {
        img.xref_to_idx[img.xrefs[i].to].push_back(i);
    }
}

void detect_nullsubs(BinaryImage& img) {
    bool is_x86 = (img.arch == Arch::X86 || img.arch == Arch::X86_64);
    bool is_arm64 = (img.arch == Arch::ARM64);
    bool is_arm32 = (img.arch == Arch::ARM);
    bool is_mips = (img.arch == Arch::MIPS_LE || img.arch == Arch::MIPS_BE ||
                    img.arch == Arch::MIPS64_LE || img.arch == Arch::MIPS64_BE);

    size_t null_count = 0;
    for (auto& [addr, func] : img.functions) {
        if (func.is_import) continue;

        size_t avail = 0;
        const uint8_t* bytes = img.bytes_at_va(addr, &avail);
        if (!bytes || avail < 1) continue;

        bool is_null = false;

        if (is_x86) {
            // ret
            if (avail >= 1 && bytes[0] == 0xC3)
                is_null = true;
            // xor eax,eax; ret  (return 0)
            else if (avail >= 3 && bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                is_null = true;
            // xor eax,eax; ret  (33 C0 C3 MSVC style)
            else if (avail >= 3 && bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                is_null = true;
            // mov eax, 0; ret (B8 00000000 C3)
            else if (avail >= 6 && bytes[0] == 0xB8 && bytes[1] == 0 && bytes[2] == 0 &&
                     bytes[3] == 0 && bytes[4] == 0 && bytes[5] == 0xC3)
                is_null = true;
            // int 3 (breakpoint stub)
            else if (avail >= 1 && bytes[0] == 0xCC)
                is_null = true;
            // ret N (C2 xx xx)
            else if (avail >= 3 && bytes[0] == 0xC2)
                is_null = true;
            // nop; ret
            else if (avail >= 2 && bytes[0] == 0x90 && bytes[1] == 0xC3)
                is_null = true;
        } else if (is_arm64) {
            // ret (D65F03C0)
            if (avail >= 4) {
                uint32_t insn = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
                if (insn == 0xD65F03C0) is_null = true;
                // mov w0, #0; ret
                if (avail >= 8) {
                    uint32_t insn2 = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
                    if (insn == 0x52800000 && insn2 == 0xD65F03C0) is_null = true;
                }
            }
        } else if (is_arm32) {
            // bx lr (1E FF 2F E1)
            if (avail >= 4) {
                uint32_t insn = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
                if (insn == 0xE12FFF1E) is_null = true;
            }
        } else if (is_mips) {
            // jr $ra; nop (delay slot)
            if (avail >= 8) {
                bool le = (img.arch == Arch::MIPS_LE || img.arch == Arch::MIPS64_LE);
                uint32_t insn;
                if (le) insn = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
                else     insn = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
                if (insn == 0x03E00008) is_null = true; // jr $ra
            }
        }

        if (is_null) {
            func.is_nullsub = true;
            null_count++;
        }
    }

    if (null_count > 0)
        fprintf(stderr, "[+] Detected %zu null/stub functions\n", null_count);
}

void run_crypto_scan(BinaryImage& img) {
    auto result = scan_crypto_constants(img);
    img.crypto_hits.clear();
    for (auto& h : result.hits) {
        BinaryImage::CryptoHitRef ref;
        ref.addr = h.addr;
        ref.algorithm = h.algorithm;
        ref.constant_name = h.constant_name;
        ref.match_len = h.match_len;
        img.crypto_hits.push_back(std::move(ref));
    }
}

void run_entropy_analysis(BinaryImage& img) {
    auto result = analyze_entropy(img);
    img.overall_entropy = result.overall_entropy;
    img.likely_packed = result.likely_packed;
    img.section_entropy.clear();
    for (auto& se : result.sections) {
        BinaryImage::SectionEntropyRef ref;
        ref.name = se.name;
        ref.entropy = se.entropy;
        ref.packed = se.packed;
        img.section_entropy.push_back(std::move(ref));
    }
}

void run_imphash(BinaryImage& img) {
    img.imphash = compute_imphash(img);
}

void run_network_scan(BinaryImage& img) {
    img.network_refs.clear();

    static const std::regex re_url(R"((https?|ftp|mqtt|coap|ws|wss)://[^\s\x00"'<>\)\]]{4,256})", std::regex::optimize);
    static const std::regex re_ipv4(R"(\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b)", std::regex::optimize);
    static const std::regex re_email(R"(\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b)", std::regex::optimize);
    static const std::regex re_mac(R"(\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b)", std::regex::optimize);
    static const std::regex re_domain(R"(\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|dev|gov|edu|mil|co|info|biz|ru|cn|de|uk|fr|jp|kr|br|in|au|local|lan|internal|onion|i2p)\b)", std::regex::optimize);
    static const std::regex re_port(R"(\b(?:port|PORT|listen|bind|connect)\s*[=:(]\s*(\d{2,5})\b)", std::regex::optimize);

    std::set<std::string> seen;

    for (auto& s : img.strings) {
        const std::string& v = s.value;
        std::smatch m;

        auto try_add = [&](const std::string& val, const std::string& type) {
            std::string key = type + ":" + val;
            if (seen.insert(key).second)
                img.network_refs.push_back({s.addr, val, type});
        };

        // URLs
        auto it = v.cbegin();
        while (std::regex_search(it, v.cend(), m, re_url)) {
            try_add(m[0].str(), "url");
            it = m.suffix().first;
        }

        // IPv4
        it = v.cbegin();
        while (std::regex_search(it, v.cend(), m, re_ipv4)) {
            int a = std::stoi(m[1]), b = std::stoi(m[2]), c = std::stoi(m[3]), d = std::stoi(m[4]);
            if (a <= 255 && b <= 255 && c <= 255 && d <= 255 &&
                !(a == 0 && b == 0 && c == 0 && d == 0))
                try_add(m[0].str(), "ipv4");
            it = m.suffix().first;
        }

        // Email
        it = v.cbegin();
        while (std::regex_search(it, v.cend(), m, re_email)) {
            try_add(m[0].str(), "email");
            it = m.suffix().first;
        }

        // MAC
        it = v.cbegin();
        while (std::regex_search(it, v.cend(), m, re_mac)) {
            try_add(m[0].str(), "mac");
            it = m.suffix().first;
        }

        // Domains (only if no URL already captured it)
        it = v.cbegin();
        while (std::regex_search(it, v.cend(), m, re_domain)) {
            std::string dom = m[0].str();
            std::string key_check = "url:" + dom;
            bool already_in_url = false;
            for (auto& nr : img.network_refs)
                if (nr.type == "url" && nr.value.find(dom) != std::string::npos) {
                    already_in_url = true; break;
                }
            if (!already_in_url)
                try_add(dom, "domain");
            it = m.suffix().first;
        }

        // Port references
        it = v.cbegin();
        while (std::regex_search(it, v.cend(), m, re_port)) {
            int port = std::stoi(m[1].str());
            if (port > 0 && port <= 65535)
                try_add(m[1].str(), "port");
            it = m.suffix().first;
        }
    }
}

void run_full_analysis(BinaryImage& img) {
    run_full_analysis(img, nullptr);
}

void run_full_analysis(BinaryImage& img, AnalysisProgress* prog) {
    auto stage = [&](int n, const char* msg) {
        fprintf(stderr, "[*] %s\n", msg);
        if (prog) prog->set_stage(n, msg);
    };

    stage(1, "Extracting strings...");
    extract_strings(img);
    fprintf(stderr, "[+] Found %zu strings\n", img.strings.size());
    if (prog) prog->string_count.store(img.strings.size(), std::memory_order_release);

    stage(2, "Discovering functions...");
    discover_functions(img);
    if (prog) prog->func_count.store(img.functions.size(), std::memory_order_release);

    stage(3, "Detecting null stubs...");
    detect_nullsubs(img);

    stage(4, "Building cross-references...");
    build_xrefs(img);
    fprintf(stderr, "[+] Built %zu xrefs\n", img.xrefs.size());
    if (prog) prog->xref_count.store(img.xrefs.size(), std::memory_order_release);

    stage(5, "Scanning for crypto constants...");
    run_crypto_scan(img);
    if (!img.crypto_hits.empty())
        fprintf(stderr, "[+] Found %zu crypto constant hits\n", img.crypto_hits.size());

    stage(6, "Analyzing entropy...");
    run_entropy_analysis(img);
    fprintf(stderr, "[+] Overall entropy: %.2f%s\n", img.overall_entropy,
        img.likely_packed ? " (LIKELY PACKED)" : "");

    stage(7, "Computing imphash...");
    run_imphash(img);
    if (!img.imphash.empty())
        fprintf(stderr, "[+] Imphash: %s\n", img.imphash.c_str());

    stage(8, "Scanning for network references...");
    run_network_scan(img);
    if (!img.network_refs.empty())
        fprintf(stderr, "[+] Found %zu network refs (URLs, IPs, domains, etc.)\n", img.network_refs.size());

    stage(9, "Scanning file signatures...");
    scan_signatures(img);

    stage(10, "Computing entropy heatmap...");
    compute_entropy_heatmap(img, 256);

    stage(11, "Detecting encoded strings...");
    detect_encoded_strings(img);

    stage(12, "Extracting certificates and keys...");
    extract_certificates(img);

    stage(13, "Parsing firmware headers...");
    parse_firmware_headers(img);

    fprintf(stderr, "[+] Analysis complete.\n");
    if (prog) {
        prog->set_stage(14, "Analysis complete");
        prog->done.store(true, std::memory_order_release);
    }
}

}
