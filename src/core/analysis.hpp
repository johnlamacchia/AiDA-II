#pragma once
#include "core/binary.hpp"
#include <string>
#include <atomic>
#include <mutex>

namespace aida {

void discover_functions(BinaryImage& img);
void extract_strings(BinaryImage& img, size_t min_len = 4);
void build_xrefs(BinaryImage& img);
void apply_imports_as_functions(BinaryImage& img);
void apply_exports_as_functions(BinaryImage& img);
void apply_symbols_as_functions(BinaryImage& img);
void detect_nullsubs(BinaryImage& img);
void run_crypto_scan(BinaryImage& img);
void run_entropy_analysis(BinaryImage& img);
void run_imphash(BinaryImage& img);
void run_network_scan(BinaryImage& img);
void run_full_analysis(BinaryImage& img);

struct AnalysisProgress {
    std::atomic<int> stage{0};
    std::atomic<bool> done{false};
    std::mutex msg_mtx;
    std::string stage_msg;
    std::atomic<size_t> func_count{0};
    std::atomic<size_t> string_count{0};
    std::atomic<size_t> xref_count{0};

    void set_stage(int s, const std::string& msg) {
        stage.store(s, std::memory_order_release);
        std::lock_guard<std::mutex> lk(msg_mtx);
        stage_msg = msg;
        fprintf(stderr, "[*] %s\n", msg.c_str());
    }
    std::string get_msg() {
        std::lock_guard<std::mutex> lk(msg_mtx);
        return stage_msg;
    }
};

void run_full_analysis(BinaryImage& img, AnalysisProgress* prog);

}
