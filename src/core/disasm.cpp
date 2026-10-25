#include "core/disasm.hpp"
#include <capstone/capstone.h>
#include <cstring>

namespace aida {

static csh g_cs = 0;
static Arch g_arch = Arch::Unknown;

bool init_disassembler(Arch arch) {
    if (g_cs && g_arch == arch) return true;
    if (g_cs) { cs_close(&g_cs); g_cs = 0; }

    cs_arch cs_a;
    cs_mode cs_m;

    switch (arch) {
    case Arch::X86:
        cs_a = CS_ARCH_X86; cs_m = CS_MODE_32; break;
    case Arch::X86_64:
        cs_a = CS_ARCH_X86; cs_m = CS_MODE_64; break;
    case Arch::ARM:
        cs_a = CS_ARCH_ARM; cs_m = CS_MODE_ARM; break;
    case Arch::ARM64:
        cs_a = CS_ARCH_ARM64; cs_m = CS_MODE_ARM; break;
    case Arch::MIPS_LE:
        cs_a = CS_ARCH_MIPS; cs_m = static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN); break;
    case Arch::MIPS_BE:
        cs_a = CS_ARCH_MIPS; cs_m = static_cast<cs_mode>(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN); break;
    case Arch::MIPS64_LE:
        cs_a = CS_ARCH_MIPS; cs_m = static_cast<cs_mode>(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN); break;
    case Arch::MIPS64_BE:
        cs_a = CS_ARCH_MIPS; cs_m = static_cast<cs_mode>(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN); break;
    case Arch::RISCV32:
        cs_a = CS_ARCH_RISCV; cs_m = CS_MODE_RISCV32; break;
    case Arch::RISCV64:
        cs_a = CS_ARCH_RISCV; cs_m = CS_MODE_RISCV64; break;
    case Arch::PPC:
        cs_a = CS_ARCH_PPC; cs_m = static_cast<cs_mode>(CS_MODE_32 | CS_MODE_BIG_ENDIAN); break;
    case Arch::PPC64:
        cs_a = CS_ARCH_PPC; cs_m = static_cast<cs_mode>(CS_MODE_64 | CS_MODE_BIG_ENDIAN); break;
    default:
        fprintf(stderr, "[!] Disassembler: unsupported architecture (%d)\n", static_cast<int>(arch));
        return false;
    }

    cs_err err = cs_open(cs_a, cs_m, &g_cs);
    if (err != CS_ERR_OK) {
        fprintf(stderr, "[!] Disassembler init failed: cs_open error %d\n", err);
        return false;
    }

    cs_option(g_cs, CS_OPT_DETAIL, CS_OPT_ON);
    g_arch = arch;
    return true;
}

void shutdown_disassembler() {
    if (g_cs) { cs_close(&g_cs); g_cs = 0; }
    g_arch = Arch::Unknown;
}

void* cs_handle_raw() { return reinterpret_cast<void*>(g_cs); }

std::vector<Instruction> disassemble(const uint8_t* code, size_t size,
                                      uint64_t addr, size_t max_insns) {
    std::vector<Instruction> result;
    if (!g_cs || !code || !size) return result;

    cs_insn* insns = nullptr;
    size_t count = cs_disasm(g_cs, code, size, addr,
                             max_insns ? max_insns : 0, &insns);
    result.reserve(count);

    for (size_t i = 0; i < count; i++) {
        Instruction inst;
        inst.addr = insns[i].address;
        inst.size = insns[i].size;
        inst.mnemonic = insns[i].mnemonic;
        inst.operands = insns[i].op_str;
        inst.bytes.assign(insns[i].bytes, insns[i].bytes + insns[i].size);
        result.push_back(std::move(inst));
    }

    if (insns) cs_free(insns, count);
    return result;
}

std::vector<Instruction> disassemble_function(const BinaryImage& img, uint64_t func_addr) {
    std::vector<Instruction> result;
    if (!g_cs) return result;

    size_t avail = 0;
    const uint8_t* code = img.bytes_at_va(func_addr, &avail);
    if (!code || !avail) return result;

    size_t max_bytes = std::min<size_t>(avail, 0x10000);
    cs_insn* insns = nullptr;
    size_t count = cs_disasm(g_cs, code, max_bytes, func_addr, 0, &insns);

    bool is_x86 = (g_arch == Arch::X86 || g_arch == Arch::X86_64);

    for (size_t i = 0; i < count; i++) {
        Instruction inst;
        inst.addr = insns[i].address;
        inst.size = insns[i].size;
        inst.mnemonic = insns[i].mnemonic;
        inst.operands = insns[i].op_str;
        inst.bytes.assign(insns[i].bytes, insns[i].bytes + insns[i].size);
        result.push_back(std::move(inst));

        if (is_x86) {
            auto id = insns[i].id;
            if (id == X86_INS_RET || id == X86_INS_RETF || id == X86_INS_RETFQ ||
                id == X86_INS_INT3 || id == X86_INS_HLT || id == X86_INS_UD2) {
                break;
            }
        }

        if (g_arch == Arch::ARM || g_arch == Arch::ARM64) {
            const char* mn = insns[i].mnemonic;
            if (strcmp(mn, "bx") == 0 && strstr(insns[i].op_str, "lr"))
                break;
            if (strcmp(mn, "ret") == 0)
                break;
        }

        if (g_arch == Arch::MIPS_LE || g_arch == Arch::MIPS_BE ||
            g_arch == Arch::MIPS64_LE || g_arch == Arch::MIPS64_BE) {
            const char* mn = insns[i].mnemonic;
            if (strcmp(mn, "jr") == 0 && strstr(insns[i].op_str, "$ra")) {
                if (i + 1 < count) {
                    Instruction delay;
                    delay.addr = insns[i + 1].address;
                    delay.size = insns[i + 1].size;
                    delay.mnemonic = insns[i + 1].mnemonic;
                    delay.operands = insns[i + 1].op_str;
                    delay.bytes.assign(insns[i + 1].bytes, insns[i + 1].bytes + insns[i + 1].size);
                    result.push_back(std::move(delay));
                }
                break;
            }
        }
    }

    if (insns) cs_free(insns, count);
    return result;
}

}
