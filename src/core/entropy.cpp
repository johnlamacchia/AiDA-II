#include "core/entropy.hpp"
#include <cmath>
#include <algorithm>
#include <array>

namespace aida {

double calc_shannon_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;

    std::array<size_t, 256> freq = {};
    for (size_t i = 0; i < len; i++)
        freq[data[i]]++;

    double entropy = 0.0;
    for (size_t i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / static_cast<double>(len);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

EntropyResult analyze_entropy(const BinaryImage& img, size_t window_size) {
    EntropyResult result;

    if (img.raw.empty()) return result;

    result.overall_entropy = calc_shannon_entropy(img.raw.data(), img.raw.size());

    for (auto& sec : img.sections) {
        if (sec.file_off + sec.file_size > img.raw.size()) continue;
        const uint8_t* data = img.raw.data() + sec.file_off;
        size_t len = sec.file_size;

        SectionEntropy se;
        se.name = sec.name;
        se.vaddr = sec.vaddr;
        se.size = sec.file_size;
        se.entropy = calc_shannon_entropy(data, len);
        se.packed = se.entropy > 6.8 && len > 512;
        se.encrypted = se.entropy > 7.5 && len > 1024;
        result.sections.push_back(std::move(se));
    }

    size_t packed_sections = 0;
    size_t total_data_sections = 0;
    for (auto& se : result.sections) {
        if (se.size > 512) {
            total_data_sections++;
            if (se.packed) packed_sections++;
        }
    }
    result.likely_packed = total_data_sections > 0 &&
        packed_sections * 2 >= total_data_sections && result.overall_entropy > 6.5;

    if (window_size > 0 && img.raw.size() > window_size) {
        size_t step = window_size;
        for (size_t off = 0; off + window_size <= img.raw.size(); off += step) {
            double e = calc_shannon_entropy(img.raw.data() + off, window_size);
            if (e > 7.0) {
                EntropyWindow ew;
                ew.offset = off;
                ew.entropy = e;
                result.high_entropy_regions.push_back(ew);
            }
        }
    }

    return result;
}

}
