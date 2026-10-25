#include "core/elf.hpp"
#include <cstring>

namespace aida {

static inline uint16_t bswap16(uint16_t v) { return (v >> 8) | (v << 8); }
static inline uint32_t bswap32(uint32_t v) {
    return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) |
           ((v << 8) & 0xFF0000) | ((v << 24) & 0xFF000000);
}
static inline uint64_t bswap64(uint64_t v) {
    return ((uint64_t)bswap32((uint32_t)v) << 32) | bswap32((uint32_t)(v >> 32));
}

struct ElfReader {
    const uint8_t* data;
    size_t sz;
    bool swap;

    uint16_t u16(size_t off) const {
        uint16_t v; memcpy(&v, data + off, 2);
        return swap ? bswap16(v) : v;
    }
    uint32_t u32(size_t off) const {
        uint32_t v; memcpy(&v, data + off, 4);
        return swap ? bswap32(v) : v;
    }
    uint64_t u64(size_t off) const {
        uint64_t v; memcpy(&v, data + off, 8);
        return swap ? bswap64(v) : v;
    }
};

static Arch elf_machine_to_arch(uint16_t machine, uint8_t ei_class, uint8_t ei_data) {
    bool big = (ei_data == 2);
    switch (machine) {
    case 3:  return Arch::X86;
    case 62: return Arch::X86_64;
    case 40: return Arch::ARM;
    case 183: return Arch::ARM64;
    case 8:
        if (ei_class == 2) return big ? Arch::MIPS64_BE : Arch::MIPS64_LE;
        return big ? Arch::MIPS_BE : Arch::MIPS_LE;
    case 20: case 21: return big ? Arch::PPC : Arch::PPC;
    case 243:
        return (ei_class == 2) ? Arch::RISCV64 : Arch::RISCV32;
    default: return Arch::Unknown;
    }
}

static std::string read_cstr_at(const uint8_t* base, size_t max, size_t off) {
    std::string s;
    for (size_t i = off; i < max && base[i]; i++)
        s += static_cast<char>(base[i]);
    return s;
}

bool parse_elf(BinaryImage& img) {
    const uint8_t* data = img.raw.data();
    size_t sz = img.raw.size();
    if (sz < 16) return false;
    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F')
        return false;

    img.format = BinaryFormat::ELF;
    uint8_t ei_class = data[4];
    uint8_t ei_data  = data[5];
    bool is64 = (ei_class == 2);
    bool big  = (ei_data == 2);

    ElfReader r{data, sz, big};

    if (is64) {
        if (sz < 64) return false;
        uint16_t machine = r.u16(18);
        img.arch = elf_machine_to_arch(machine, ei_class, ei_data);
        img.entry = r.u64(24);
        uint64_t phoff = r.u64(32);
        uint64_t shoff = r.u64(40);
        uint16_t phentsize = r.u16(54);
        uint16_t phnum = r.u16(56);
        uint16_t shentsize = r.u16(58);
        uint16_t shnum = r.u16(60);
        uint16_t shstrndx = r.u16(62);

        uint64_t base_min = UINT64_MAX;
        for (uint16_t i = 0; i < phnum; i++) {
            uint64_t off = phoff + i * phentsize;
            if (off + 56 > sz) break;
            uint32_t p_type = r.u32(off);
            uint64_t p_vaddr = r.u64(off + 16);
            if (p_type == 1 && p_vaddr < base_min) base_min = p_vaddr;
        }
        img.base = (base_min != UINT64_MAX) ? base_min : 0;

        const uint8_t* shstrtab = nullptr;
        size_t shstrtab_sz = 0;
        if (shstrndx < shnum) {
            uint64_t ss_off = shoff + shstrndx * shentsize;
            if (ss_off + 64 <= sz) {
                uint64_t ss_offset = r.u64(ss_off + 24);
                uint64_t ss_size = r.u64(ss_off + 32);
                if (ss_offset + ss_size <= sz) {
                    shstrtab = data + ss_offset;
                    shstrtab_sz = ss_size;
                }
            }
        }

        for (uint16_t i = 0; i < shnum; i++) {
            uint64_t off = shoff + i * shentsize;
            if (off + 64 > sz) break;

            uint32_t sh_name = r.u32(off);
            uint32_t sh_type = r.u32(off + 4);
            uint64_t sh_flags = r.u64(off + 8);
            uint64_t sh_addr = r.u64(off + 16);
            uint64_t sh_offset = r.u64(off + 24);
            uint64_t sh_size = r.u64(off + 32);
            uint32_t sh_link = r.u32(off + 40);
            uint64_t sh_entsize = r.u64(off + 56);

            Section sec;
            if (shstrtab && sh_name < shstrtab_sz)
                sec.name = read_cstr_at(shstrtab, shstrtab_sz, sh_name);
            sec.vaddr = sh_addr;
            sec.vsize = sh_size;
            sec.file_off = sh_offset;
            sec.file_size = (sh_type != 8) ? sh_size : 0;
            sec.executable = (sh_flags & 4) != 0;
            sec.writable   = (sh_flags & 1) != 0;
            sec.readable   = true;
            img.sections.push_back(std::move(sec));

            if (sh_type == 2 || sh_type == 11) {
                const uint8_t* strtab = nullptr;
                size_t strtab_sz = 0;
                if (sh_link < shnum) {
                    uint64_t str_sh_off = shoff + sh_link * shentsize;
                    if (str_sh_off + 64 <= sz) {
                        uint64_t str_offset = r.u64(str_sh_off + 24);
                        uint64_t str_size = r.u64(str_sh_off + 32);
                        if (str_offset + str_size <= sz) {
                            strtab = data + str_offset;
                            strtab_sz = str_size;
                        }
                    }
                }

                size_t count = sh_entsize ? sh_size / sh_entsize : 0;
                for (size_t si = 0; si < count; si++) {
                    uint64_t sym_off = sh_offset + si * sh_entsize;
                    if (sym_off + 24 > sz) break;

                    uint32_t st_name_v = r.u32(sym_off);
                    uint8_t st_info = data[sym_off + 4];
                    uint64_t st_value = r.u64(sym_off + 8);
                    uint64_t st_size_v = r.u64(sym_off + 16);

                    uint8_t st_type = st_info & 0xF;
                    if (st_type != 1 && st_type != 2) continue;
                    if (st_value == 0) continue;

                    Symbol s;
                    if (strtab && st_name_v < strtab_sz)
                        s.name = read_cstr_at(strtab, strtab_sz, st_name_v);
                    s.addr = st_value;
                    s.size = st_size_v;
                    s.is_func = (st_type == 2);
                    img.symbols.push_back(std::move(s));
                }
            }
        }
    } else {
        // 32-bit ELF
        if (sz < 52) return false;
        uint16_t machine = r.u16(18);
        img.arch = elf_machine_to_arch(machine, ei_class, ei_data);
        img.entry = r.u32(24);
        uint32_t phoff = r.u32(28);
        uint32_t shoff = r.u32(32);
        uint16_t phentsize = r.u16(42);
        uint16_t phnum = r.u16(44);
        uint16_t shentsize = r.u16(46);
        uint16_t shnum = r.u16(48);
        uint16_t shstrndx = r.u16(50);

        uint64_t base_min = UINT64_MAX;
        for (uint16_t i = 0; i < phnum; i++) {
            uint32_t off = phoff + i * phentsize;
            if (off + 32 > sz) break;
            uint32_t p_type = r.u32(off);
            uint32_t p_vaddr = r.u32(off + 8);
            if (p_type == 1 && p_vaddr < base_min) base_min = p_vaddr;
        }
        img.base = (base_min != UINT64_MAX) ? base_min : 0;

        const uint8_t* shstrtab = nullptr;
        size_t shstrtab_sz = 0;
        if (shstrndx < shnum) {
            uint32_t ss_off = shoff + shstrndx * shentsize;
            if (ss_off + 40 <= sz) {
                uint32_t ss_offset = r.u32(ss_off + 16);
                uint32_t ss_size = r.u32(ss_off + 20);
                if (ss_offset + ss_size <= sz) {
                    shstrtab = data + ss_offset;
                    shstrtab_sz = ss_size;
                }
            }
        }

        for (uint16_t i = 0; i < shnum; i++) {
            uint32_t off = shoff + i * shentsize;
            if (off + 40 > sz) break;

            uint32_t sh_name = r.u32(off);
            uint32_t sh_type = r.u32(off + 4);
            uint32_t sh_flags = r.u32(off + 8);
            uint32_t sh_addr = r.u32(off + 12);
            uint32_t sh_offset = r.u32(off + 16);
            uint32_t sh_size = r.u32(off + 20);
            uint32_t sh_link = r.u32(off + 24);
            uint32_t sh_entsize = r.u32(off + 36);

            Section sec;
            if (shstrtab && sh_name < shstrtab_sz)
                sec.name = read_cstr_at(shstrtab, shstrtab_sz, sh_name);
            sec.vaddr = sh_addr;
            sec.vsize = sh_size;
            sec.file_off = sh_offset;
            sec.file_size = (sh_type != 8) ? sh_size : 0;
            sec.executable = (sh_flags & 4) != 0;
            sec.writable   = (sh_flags & 1) != 0;
            sec.readable   = true;
            img.sections.push_back(std::move(sec));

            if (sh_type == 2 || sh_type == 11) {
                const uint8_t* strtab = nullptr;
                size_t strtab_sz = 0;
                if (sh_link < shnum) {
                    uint32_t str_sh_off = shoff + sh_link * shentsize;
                    if (str_sh_off + 40 <= sz) {
                        uint32_t str_offset = r.u32(str_sh_off + 16);
                        uint32_t str_size = r.u32(str_sh_off + 20);
                        if (str_offset + str_size <= sz) {
                            strtab = data + str_offset;
                            strtab_sz = str_size;
                        }
                    }
                }

                size_t count = sh_entsize ? sh_size / sh_entsize : 0;
                for (size_t si = 0; si < count; si++) {
                    uint32_t sym_off = sh_offset + si * sh_entsize;
                    if (sym_off + 16 > sz) break;

                    uint32_t st_name_v = r.u32(sym_off);
                    uint32_t st_value = r.u32(sym_off + 4);
                    uint32_t st_size_v = r.u32(sym_off + 8);
                    uint8_t st_info = data[sym_off + 12];

                    uint8_t st_type = st_info & 0xF;
                    if (st_type != 1 && st_type != 2) continue;
                    if (st_value == 0) continue;

                    Symbol s;
                    if (strtab && st_name_v < strtab_sz)
                        s.name = read_cstr_at(strtab, strtab_sz, st_name_v);
                    s.addr = st_value;
                    s.size = st_size_v;
                    s.is_func = (st_type == 2);
                    img.symbols.push_back(std::move(s));
                }
            }
        }
    }

    return true;
}

}
