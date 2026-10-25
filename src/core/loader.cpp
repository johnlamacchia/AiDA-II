#include "core/loader.hpp"
#include "core/pe.hpp"
#include "core/elf.hpp"
#include <fstream>
#include <filesystem>

namespace aida {

std::unique_ptr<BinaryImage> load_binary(const std::string& path) {
    auto img = std::make_unique<BinaryImage>();
    img->path = path;

    namespace fs = std::filesystem;
    img->filename = fs::path(path).filename().string();

    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return nullptr;

    auto sz = f.tellg();
    if (sz <= 0) return nullptr;

    img->raw.resize(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(img->raw.data()), sz);

    if (img->raw.size() >= 4) {
        uint16_t mz;
        memcpy(&mz, img->raw.data(), 2);
        if (mz == 0x5A4D) {
            if (parse_pe(*img)) return img;
        }

        if (img->raw[0] == 0x7F && img->raw[1] == 'E' &&
            img->raw[2] == 'L' && img->raw[3] == 'F') {
            if (parse_elf(*img)) return img;
        }

        // TODO: Mach-O (0xFEEDFACE / 0xFEEDFACF)
    }

    img->format = BinaryFormat::Raw;
    img->arch = Arch::Unknown;
    return img;
}

}
