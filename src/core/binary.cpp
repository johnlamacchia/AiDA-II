#include "core/binary.hpp"

namespace aida {

const uint8_t* BinaryImage::bytes_at_va(uint64_t va, size_t* out_len) const {
    for (auto& sec : sections) {
        if (va >= sec.vaddr && va < sec.vaddr + sec.vsize) {
            uint64_t off_in_sec = va - sec.vaddr;
            if (off_in_sec >= sec.file_size) {
                if (out_len) *out_len = 0;
                return nullptr;
            }
            uint64_t file_pos = sec.file_off + off_in_sec;
            if (file_pos >= raw.size()) {
                if (out_len) *out_len = 0;
                return nullptr;
            }
            size_t avail = std::min<size_t>(sec.file_size - off_in_sec, raw.size() - file_pos);
            if (out_len) *out_len = avail;
            return raw.data() + file_pos;
        }
    }
    if (out_len) *out_len = 0;
    return nullptr;
}

std::optional<uint64_t> BinaryImage::va_to_offset(uint64_t va) const {
    for (auto& sec : sections) {
        if (va >= sec.vaddr && va < sec.vaddr + sec.vsize) {
            uint64_t off_in_sec = va - sec.vaddr;
            if (off_in_sec < sec.file_size)
                return sec.file_off + off_in_sec;
        }
    }
    return std::nullopt;
}

std::optional<uint64_t> BinaryImage::offset_to_va(uint64_t off) const {
    for (auto& sec : sections) {
        if (off >= sec.file_off && off < sec.file_off + sec.file_size) {
            return sec.vaddr + (off - sec.file_off);
        }
    }
    return std::nullopt;
}

const Section* BinaryImage::section_for_va(uint64_t va) const {
    for (auto& sec : sections) {
        if (va >= sec.vaddr && va < sec.vaddr + sec.vsize)
            return &sec;
    }
    return nullptr;
}

}
