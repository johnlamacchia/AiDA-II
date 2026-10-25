#pragma once
#include "core/binary.hpp"
#include <vector>
#include <string>

namespace aida {

struct CryptoHit {
    uint64_t    addr = 0;
    std::string algorithm;
    std::string constant_name;
    size_t      match_len = 0;
};

struct CryptoScanResult {
    std::vector<CryptoHit> hits;
};

CryptoScanResult scan_crypto_constants(const BinaryImage& img);

}
