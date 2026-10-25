#ifdef AIDA_HAS_DECOMP

#include "core/decompiler.hpp"
#include "core/binary.hpp"

#include "libdecomp.hh"
#include "loadimage.hh"
#include "sleigh_arch.hh"
#include "funcdata.hh"
#include "prettyprint.hh"
#include "action.hh"
#include "database.hh"

#include <sstream>
#include <cstring>
#include <filesystem>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef LoadImage
#else
#include <unistd.h>
#endif

#ifndef AIDA_SLEIGH_DIR
#define AIDA_SLEIGH_DIR "."
#endif

namespace aida {

// arch -> sleigh language ID mapping
static std::string arch_to_sleigh_id(Arch arch) {
    switch (arch) {
    case Arch::X86:       return "x86:LE:32:default";
    case Arch::X86_64:    return "x86:LE:64:default";
    case Arch::ARM:       return "ARM:LE:32:v8";
    case Arch::ARM64:     return "AARCH64:LE:64:v8A";
    case Arch::MIPS_LE:   return "MIPS:LE:32:default";
    case Arch::MIPS_BE:   return "MIPS:BE:32:default";
    case Arch::MIPS64_LE: return "MIPS:LE:64:default";
    case Arch::MIPS64_BE: return "MIPS:BE:64:default";
    case Arch::RISCV32:   return "RISCV:LE:32:RV32IC";
    case Arch::RISCV64:   return "RISCV:LE:64:RV64IC";
    case Arch::PPC:       return "PowerPC:BE:32:default";
    case Arch::PPC64:     return "PowerPC:BE:64:default";
    default:              return "";
    }
}

// our LoadImage reads bytes directly from the loaded binary
class AidaLoadImage : public ghidra::LoadImage {
public:
    explicit AidaLoadImage(std::shared_ptr<BinaryImage> img)
        : ghidra::LoadImage("aida_image"), img_(std::move(img)) {}

    void loadFill(ghidra::uint1* ptr, ghidra::int4 size,
                  const ghidra::Address& addr) override {
        uint64_t va = addr.getOffset();
        size_t avail = 0;
        const uint8_t* src = img_->bytes_at_va(va, &avail);
        if (src && avail > 0) {
            size_t to_copy = std::min(static_cast<size_t>(size), avail);
            std::memcpy(ptr, src, to_copy);
            if (to_copy < static_cast<size_t>(size))
                std::memset(ptr + to_copy, 0, size - to_copy);
        } else {
            std::memset(ptr, 0, size);
        }
    }

    std::string getArchType() const override { return "aida"; }
    void adjustVma(long) override {}

private:
    std::shared_ptr<BinaryImage> img_;
};

// custom architecture that wires our loader into Ghidra's engine
class AidaArchitecture : public ghidra::SleighArchitecture {
public:
    AidaArchitecture(const std::string& sleigh_id,
                     std::shared_ptr<BinaryImage> img)
        : ghidra::SleighArchitecture("", sleigh_id, &std::cerr)
        , img_(std::move(img))
    {}

    void buildLoader(ghidra::DocumentStorage&) override {
        loader = new AidaLoadImage(img_);
    }

private:
    std::shared_ptr<BinaryImage> img_;
};

struct Decompiler::Impl {
    std::unique_ptr<AidaArchitecture> arch;
    std::string sleigh_dir;
};

Decompiler::Decompiler(std::shared_ptr<BinaryImage> img)
    : impl_(std::make_unique<Impl>()), img_(std::move(img)) {}

Decompiler::~Decompiler() = default;

bool Decompiler::init() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (initialized_) return true;

    std::string lang_id = arch_to_sleigh_id(img_->arch);
    if (lang_id.empty()) return false;

    std::string sleigh_dir = AIDA_SLEIGH_DIR;
    if (!std::filesystem::exists(sleigh_dir)) {
        // try relative to the executable
#ifdef _WIN32
        char exe_path[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
        sleigh_dir = std::filesystem::path(exe_path).parent_path().append("sleigh").string();
#else
        char exe_path[4096] = {};
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len > 0) {
            exe_path[len] = 0;
            sleigh_dir = std::filesystem::path(exe_path).parent_path().append("sleigh").string();
        }
#endif
    }
    if (!std::filesystem::exists(sleigh_dir)) {
        fprintf(stderr, "[!] SLEIGH directory not found: %s\n", sleigh_dir.c_str());
        return false;
    }

    try {
        std::vector<std::string> paths = { sleigh_dir };
        ghidra::startDecompilerLibrary(paths);
        ghidra::SleighArchitecture::collectSpecFiles(std::cerr);

        impl_->arch = std::make_unique<AidaArchitecture>(lang_id, img_);
        impl_->sleigh_dir = sleigh_dir;

        ghidra::DocumentStorage store;
        impl_->arch->init(store);
        initialized_ = true;
    } catch (ghidra::LowlevelError& e) {
        fprintf(stderr, "[!] Ghidra decompiler init failed: %s\n", e.explain.c_str());
        return false;
    } catch (std::exception& e) {
        fprintf(stderr, "[!] Ghidra decompiler init failed: %s\n", e.what());
        return false;
    }

    return true;
}

DecompResult Decompiler::decompile(uint64_t func_addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    DecompResult result;

    if (!initialized_) {
        result.error = "decompiler not initialized";
        return result;
    }

    try {
        auto* arch = impl_->arch.get();
        ghidra::Address entry_addr(arch->getDefaultCodeSpace(), func_addr);

        // find or create function in ghidra's database
        ghidra::Funcdata* func = arch->symboltab->getGlobalScope()->findFunction(entry_addr);
        if (!func) {
            // create the function if it doesn't exist
            auto it = img_->functions.find(func_addr);
            std::string fname = (it != img_->functions.end()) ? it->second.name : "sub";
            func = arch->symboltab->getGlobalScope()->addFunction(
                entry_addr, fname)->getFunction();
        }

        if (!func) {
            result.error = "failed to create function object at " + std::to_string(func_addr);
            return result;
        }

        arch->clearAnalysis(func);
        auto* action = arch->allacts.getCurrent();
        action->reset(*func);
        ghidra::int4 res = action->perform(*func);
        if (res < 0) {
            result.error = "decompilation failed for function at 0x" +
                           std::to_string(func_addr);
            return result;
        }

        // emit C code
        std::ostringstream ss;
        arch->print->setOutputStream(&ss);
        arch->print->docFunction(func);
        arch->print->setOutputStream(&std::cerr);

        result.code = ss.str();
        result.ok = true;
    } catch (ghidra::LowlevelError& e) {
        result.error = "decompiler error: " + e.explain;
    } catch (std::exception& e) {
        result.error = std::string("decompiler error: ") + e.what();
    }

    return result;
}

}

#endif // AIDA_HAS_DECOMP
