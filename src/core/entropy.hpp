#pragma once
#include "core/binary.hpp"
#include <vector>
#include <string>

namespace aida {

struct SectionEntropy {
    std::string name;
    uint64_t    vaddr    = 0;
    uint64_t    size     = 0;
    double      entropy  = 0.0;
    bool        packed   = false;
    bool        encrypted = false;
};

struct EntropyWindow {
    uint64_t offset  = 0;
    double   entropy = 0.0;
};

struct EntropyResult {
    std::vector<SectionEntropy> sections;
    double overall_entropy = 0.0;
    bool   likely_packed   = false;
    std::vector<EntropyWindow> high_entropy_regions;
};

double calc_shannon_entropy(const uint8_t* data, size_t len);
EntropyResult analyze_entropy(const BinaryImage& img, size_t window_size = 256);

}
