#pragma once
#include "core/binary.hpp"
#include <vector>

namespace aida {

bool init_disassembler(Arch arch);
void shutdown_disassembler();
void* cs_handle_raw();

std::vector<Instruction> disassemble(const uint8_t* code, size_t size,
                                      uint64_t addr, size_t max_insns = 0);

std::vector<Instruction> disassemble_function(const BinaryImage& img, uint64_t func_addr);

}
