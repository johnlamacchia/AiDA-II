#pragma once
#include "core/binary.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace aida {

struct CarvedFile {
    uint64_t offset = 0;
    size_t size = 0;
    std::string type;
    std::string output_path;
};

struct YaraMatch {
    std::string rule_name;
    uint64_t offset = 0;
    size_t length = 0;
    std::string matched_data;
};

void scan_signatures(BinaryImage& img);
std::vector<CarvedFile> carve_files(const BinaryImage& img, const std::string& output_dir);
void compute_entropy_heatmap(BinaryImage& img, size_t block_size = 256);
void detect_encoded_strings(BinaryImage& img);
void extract_certificates(BinaryImage& img);
void parse_firmware_headers(BinaryImage& img);
std::vector<YaraMatch> run_yara_scan(const BinaryImage& img, const std::string& rules_text);

}
