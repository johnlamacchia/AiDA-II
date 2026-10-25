#include "core/pe.hpp"
#include <cstring>
#include <algorithm>

namespace aida {

#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;
    uint8_t  pad[58];
    uint32_t e_lfanew;
};

struct CoffHeader {
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t symtab_ptr;
    uint32_t num_symbols;
    uint16_t opt_hdr_size;
    uint16_t characteristics;
};

struct OptionalHeader32 {
    uint16_t magic;
    uint8_t  linker_major, linker_minor;
    uint32_t size_of_code;
    uint32_t size_of_init;
    uint32_t size_of_uninit;
    uint32_t entry;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_align;
    uint32_t file_align;
    uint16_t os_major, os_minor;
    uint16_t img_major, img_minor;
    uint16_t subsys_major, subsys_minor;
    uint32_t win32_ver;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_chars;
    uint32_t stack_reserve, stack_commit;
    uint32_t heap_reserve, heap_commit;
    uint32_t loader_flags;
    uint32_t num_data_dirs;
};

struct OptionalHeader64 {
    uint16_t magic;
    uint8_t  linker_major, linker_minor;
    uint32_t size_of_code;
    uint32_t size_of_init;
    uint32_t size_of_uninit;
    uint32_t entry;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_align;
    uint32_t file_align;
    uint16_t os_major, os_minor;
    uint16_t img_major, img_minor;
    uint16_t subsys_major, subsys_minor;
    uint32_t win32_ver;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_chars;
    uint64_t stack_reserve, stack_commit;
    uint64_t heap_reserve, heap_commit;
    uint32_t loader_flags;
    uint32_t num_data_dirs;
};

struct DataDirectory {
    uint32_t rva;
    uint32_t size;
};

struct SectionHeader {
    char     name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t reloc_ptr;
    uint32_t linenum_ptr;
    uint16_t num_relocs;
    uint16_t num_linenums;
    uint32_t characteristics;
};

struct ImportDescriptor {
    uint32_t original_first_thunk;
    uint32_t timestamp;
    uint32_t forwarder_chain;
    uint32_t name_rva;
    uint32_t first_thunk;
};

struct ExportDirectory {
    uint32_t characteristics;
    uint32_t timestamp;
    uint16_t major, minor;
    uint32_t name_rva;
    uint32_t ordinal_base;
    uint32_t num_functions;
    uint32_t num_names;
    uint32_t addr_of_functions;
    uint32_t addr_of_names;
    uint32_t addr_of_ordinals;
};
#pragma pack(pop)

static const uint8_t* rva_ptr(const BinaryImage& img, uint32_t rva) {
    for (auto& sec : img.sections) {
        if (rva >= sec.vaddr - img.base &&
            rva < (sec.vaddr - img.base) + sec.file_size) {
            uint64_t off = sec.file_off + (rva - (sec.vaddr - img.base));
            if (off < img.raw.size())
                return img.raw.data() + off;
        }
    }
    return nullptr;
}

static std::string read_cstr(const uint8_t* p, const uint8_t* end) {
    std::string s;
    while (p && p < end && *p) {
        s += static_cast<char>(*p++);
    }
    return s;
}

bool parse_pe(BinaryImage& img) {
    const uint8_t* data = img.raw.data();
    size_t sz = img.raw.size();
    if (sz < sizeof(DosHeader)) return false;

    auto* dos = reinterpret_cast<const DosHeader*>(data);
    if (dos->e_magic != 0x5A4D) return false;

    uint32_t pe_off = dos->e_lfanew;
    if (pe_off + 4 + sizeof(CoffHeader) > sz) return false;

    uint32_t pe_sig;
    memcpy(&pe_sig, data + pe_off, 4);
    if (pe_sig != 0x00004550) return false;

    auto* coff = reinterpret_cast<const CoffHeader*>(data + pe_off + 4);
    uint32_t opt_off = pe_off + 4 + sizeof(CoffHeader);

    switch (coff->machine) {
    case 0x014C: img.arch = Arch::X86; break;
    case 0x8664: img.arch = Arch::X86_64; break;
    case 0x01C0: case 0x01C4: img.arch = Arch::ARM; break;
    case 0xAA64: img.arch = Arch::ARM64; break;
    default: img.arch = Arch::Unknown; break;
    }

    img.format = BinaryFormat::PE;

    uint16_t opt_magic;
    if (opt_off + 2 > sz) return false;
    memcpy(&opt_magic, data + opt_off, 2);

    uint32_t num_data_dirs = 0;
    const DataDirectory* data_dirs = nullptr;
    uint32_t sections_off = 0;

    if (opt_magic == 0x10B) {
        if (opt_off + sizeof(OptionalHeader32) > sz) return false;
        auto* opt = reinterpret_cast<const OptionalHeader32*>(data + opt_off);
        img.base = opt->image_base;
        img.entry = img.base + opt->entry;
        num_data_dirs = std::min(opt->num_data_dirs, 16u);
        data_dirs = reinterpret_cast<const DataDirectory*>(data + opt_off + sizeof(OptionalHeader32));
        sections_off = opt_off + coff->opt_hdr_size;
    } else if (opt_magic == 0x20B) {
        if (opt_off + sizeof(OptionalHeader64) > sz) return false;
        auto* opt = reinterpret_cast<const OptionalHeader64*>(data + opt_off);
        img.base = opt->image_base;
        img.entry = img.base + opt->entry;
        num_data_dirs = std::min(opt->num_data_dirs, 16u);
        data_dirs = reinterpret_cast<const DataDirectory*>(data + opt_off + sizeof(OptionalHeader64));
        sections_off = opt_off + coff->opt_hdr_size;
    } else {
        return false;
    }

    // sections
    for (uint16_t i = 0; i < coff->num_sections; i++) {
        uint32_t sh_off = sections_off + i * sizeof(SectionHeader);
        if (sh_off + sizeof(SectionHeader) > sz) break;
        auto* sh = reinterpret_cast<const SectionHeader*>(data + sh_off);

        Section sec;
        sec.name = std::string(sh->name, strnlen(sh->name, 8));
        sec.vaddr = img.base + sh->virtual_address;
        sec.vsize = sh->virtual_size;
        sec.file_off = sh->raw_offset;
        sec.file_size = sh->raw_size;
        sec.executable = (sh->characteristics & 0x20000000) != 0;
        sec.writable   = (sh->characteristics & 0x80000000) != 0;
        sec.readable   = (sh->characteristics & 0x40000000) != 0;
        img.sections.push_back(std::move(sec));
    }

    // imports
    if (num_data_dirs > 1 && data_dirs[1].rva && data_dirs[1].size) {
        uint32_t import_rva = data_dirs[1].rva;
        for (uint32_t off = 0; ; off += sizeof(ImportDescriptor)) {
            auto* desc_ptr = rva_ptr(img, import_rva + off);
            if (!desc_ptr) break;
            ImportDescriptor desc;
            memcpy(&desc, desc_ptr, sizeof(desc));
            if (!desc.name_rva) break;

            auto* name_ptr = rva_ptr(img, desc.name_rva);
            std::string mod_name = name_ptr ? read_cstr(name_ptr, data + sz) : "???";

            uint32_t thunk_rva = desc.original_first_thunk ? desc.original_first_thunk : desc.first_thunk;
            uint32_t iat_rva = desc.first_thunk;
            bool is64 = (img.arch == Arch::X86_64);
            size_t entry_size = is64 ? 8 : 4;

            for (uint32_t ti = 0; ; ti++) {
                auto* th = rva_ptr(img, thunk_rva + ti * entry_size);
                if (!th) break;

                uint64_t thunk_val = 0;
                if (is64) memcpy(&thunk_val, th, 8);
                else { uint32_t v; memcpy(&v, th, 4); thunk_val = v; }
                if (!thunk_val) break;

                ImportEntry imp;
                imp.module = mod_name;
                imp.iat_rva = img.base + iat_rva + ti * entry_size;

                uint64_t ordinal_flag = is64 ? 0x8000000000000000ULL : 0x80000000ULL;
                if (thunk_val & ordinal_flag) {
                    imp.ordinal = static_cast<uint16_t>(thunk_val & 0xFFFF);
                    imp.name = "Ordinal_" + std::to_string(imp.ordinal);
                } else {
                    uint32_t hint_rva = static_cast<uint32_t>(thunk_val);
                    auto* hint = rva_ptr(img, hint_rva);
                    if (hint && hint + 2 < data + sz) {
                        imp.ordinal = *reinterpret_cast<const uint16_t*>(hint);
                        imp.name = read_cstr(hint + 2, data + sz);
                    }
                }
                img.imports.push_back(std::move(imp));
            }
        }
    }

    // exports
    if (num_data_dirs > 0 && data_dirs[0].rva && data_dirs[0].size) {
        auto* exp_ptr = rva_ptr(img, data_dirs[0].rva);
        if (exp_ptr) {
            ExportDirectory edir;
            memcpy(&edir, exp_ptr, sizeof(edir));

            auto* funcs = rva_ptr(img, edir.addr_of_functions);
            auto* names = rva_ptr(img, edir.addr_of_names);
            auto* ords  = rva_ptr(img, edir.addr_of_ordinals);

            for (uint32_t i = 0; i < edir.num_functions; i++) {
                if (!funcs) break;
                uint32_t func_rva;
                memcpy(&func_rva, funcs + i * 4, 4);
                if (!func_rva) continue;

                ExportEntry exp;
                exp.rva = func_rva;
                exp.ordinal = static_cast<uint16_t>(i + edir.ordinal_base);

                if (names && ords) {
                    for (uint32_t ni = 0; ni < edir.num_names; ni++) {
                        uint16_t ord_idx;
                        memcpy(&ord_idx, ords + ni * 2, 2);
                        if (ord_idx == i) {
                            uint32_t name_rva;
                            memcpy(&name_rva, names + ni * 4, 4);
                            auto* np = rva_ptr(img, name_rva);
                            if (np) exp.name = read_cstr(np, data + sz);
                            break;
                        }
                    }
                }

                if (func_rva >= data_dirs[0].rva &&
                    func_rva < data_dirs[0].rva + data_dirs[0].size) {
                    exp.forwarded = true;
                    auto* fwd = rva_ptr(img, func_rva);
                    if (fwd) exp.forward_name = read_cstr(fwd, data + sz);
                }

                img.exports.push_back(std::move(exp));
            }
        }
    }

    return true;
}

}
