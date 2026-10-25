#pragma once
#include "core/binary.hpp"
#include <string>
#include <memory>
#include <mutex>

namespace aida {

struct DecompResult {
    bool ok = false;
    std::string code;
    std::string error;
};

class Decompiler {
public:
    explicit Decompiler(std::shared_ptr<BinaryImage> img);
    ~Decompiler();

    bool init();
    DecompResult decompile(uint64_t func_addr);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::shared_ptr<BinaryImage> img_;
    std::mutex mtx_;
    bool initialized_ = false;
};

}
