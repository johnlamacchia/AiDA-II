#include "core/firmware.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <cctype>
#include <array>
#include <set>

// memmem polyfill for Windows (must be before namespace)
#ifdef _WIN32
static void* memmem(const void* haystack, size_t hl, const void* needle, size_t nl) {
    if (nl == 0) return const_cast<void*>(haystack);
    if (nl > hl) return nullptr;
    const uint8_t* h = static_cast<const uint8_t*>(haystack);
    const uint8_t* n = static_cast<const uint8_t*>(needle);
    for (size_t i = 0; i <= hl - nl; i++) {
        if (memcmp(h + i, n, nl) == 0) return const_cast<void*>(static_cast<const void*>(h + i));
    }
    return nullptr;
}
#endif

namespace aida {

using SignatureHit   = BinaryImage::SignatureHit;
using EntropyBlock   = BinaryImage::EntropyBlock;
using EncodedString  = BinaryImage::EncodedString;
using CertificateHit = BinaryImage::CertificateHit;
using FirmwareHeader = BinaryImage::FirmwareHeader;

// ---------------------------------------------------------------------------
// Signature database
// ---------------------------------------------------------------------------
struct MagicEntry {
    const char* magic;
    size_t      len;
    size_t      scan_offset;   // where in file the magic sits (0 = file start)
    const char* type;
    const char* desc;
};

// raw bytes encoded as char arrays -- null bytes are valid
#define M(s) s, (sizeof(s) - 1)

static const uint8_t SIG_GZIP[]      = {0x1f, 0x8b, 0x08};
static const uint8_t SIG_LZMA[]      = {0x5d, 0x00, 0x00};
static const uint8_t SIG_XZ[]        = {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00};
static const uint8_t SIG_BZIP2[]     = {0x42, 0x5a, 0x68};
static const uint8_t SIG_ZSTD[]      = {0x28, 0xb5, 0x2f, 0xfd};
static const uint8_t SIG_LZ4[]       = {0x04, 0x22, 0x4d, 0x18};
static const uint8_t SIG_ZIP[]       = {0x50, 0x4b, 0x03, 0x04};
static const uint8_t SIG_RAR[]       = {0x52, 0x61, 0x72, 0x21};
static const uint8_t SIG_7Z[]        = {0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c};
static const uint8_t SIG_CPIO_NEW[]  = {0x30, 0x37, 0x30, 0x37, 0x30, 0x31};
static const uint8_t SIG_CPIO_OLD[]  = {0xc7, 0x71};
static const uint8_t SIG_SQFS_LE[]   = {0x68, 0x73, 0x71, 0x73};  // hsqs
static const uint8_t SIG_SQFS_BE[]   = {0x73, 0x71, 0x73, 0x68};  // sqsh
static const uint8_t SIG_CRAMFS_LE[] = {0x45, 0x3d, 0xcd, 0x28};
static const uint8_t SIG_CRAMFS_BE[] = {0x28, 0xcd, 0x3d, 0x45};
static const uint8_t SIG_JFFS2_LE[]  = {0x85, 0x19};
static const uint8_t SIG_JFFS2_BE[]  = {0x19, 0x85};
static const uint8_t SIG_ROMFS[]     = {0x2d, 0x72, 0x6f, 0x6d, 0x31, 0x66, 0x73, 0x2d};
static const uint8_t SIG_UBIFS[]     = {0x31, 0x18, 0x10, 0x06};
static const uint8_t SIG_UBOOT[]     = {0x27, 0x05, 0x19, 0x56};
static const uint8_t SIG_TRX[]       = {0x48, 0x44, 0x52, 0x30};  // HDR0
static const uint8_t SIG_ELF[]       = {0x7f, 0x45, 0x4c, 0x46};
static const uint8_t SIG_PE[]        = {0x4d, 0x5a};
static const uint8_t SIG_MACHO32_LE[]= {0xce, 0xfa, 0xed, 0xfe};
static const uint8_t SIG_MACHO64_LE[]= {0xcf, 0xfa, 0xed, 0xfe};
static const uint8_t SIG_MACHO32_BE[]= {0xfe, 0xed, 0xfa, 0xce};
static const uint8_t SIG_MACHO64_BE[]= {0xfe, 0xed, 0xfa, 0xcf};
static const uint8_t SIG_MACHO_FAT[] = {0xca, 0xfe, 0xba, 0xbe};
static const uint8_t SIG_DEX[]       = {0x64, 0x65, 0x78, 0x0a};
static const uint8_t SIG_PNG[]       = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};
static const uint8_t SIG_JPEG[]      = {0xff, 0xd8, 0xff};
static const uint8_t SIG_GIF[]       = {0x47, 0x49, 0x46, 0x38};
static const uint8_t SIG_BMP[]       = {0x42, 0x4d};
static const uint8_t SIG_PDF[]       = {0x25, 0x50, 0x44, 0x46};
static const uint8_t SIG_SQLITE[]    = {0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66,
                                        0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00};
static const uint8_t SIG_ANDROID_BOOT[] = {0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21};
static const uint8_t SIG_DTB[]       = {0xd0, 0x0d, 0xfe, 0xed};
static const uint8_t SIG_TAR_USTAR[] = {0x75, 0x73, 0x74, 0x61, 0x72};
static const uint8_t SIG_LZOP[]      = {0x89, 0x4c, 0x5a, 0x4f};
static const uint8_t SIG_AR[]        = {0x21, 0x3c, 0x61, 0x72, 0x63, 0x68, 0x3e};  // !<arch>

struct SigEntry {
    const uint8_t* magic;
    size_t len;
    const char* type;
    const char* desc;
};

static const SigEntry g_signatures[] = {
    {SIG_GZIP,       3,  "gzip",       "gzip compressed data"},
    {SIG_XZ,         6,  "xz",         "XZ compressed data"},
    {SIG_LZMA,       3,  "lzma",       "LZMA compressed data"},
    {SIG_BZIP2,      3,  "bzip2",      "bzip2 compressed data"},
    {SIG_ZSTD,       4,  "zstd",       "Zstandard compressed data"},
    {SIG_LZ4,        4,  "lz4",        "LZ4 compressed data"},
    {SIG_LZOP,       4,  "lzop",       "LZOP compressed data"},
    {SIG_ZIP,        4,  "zip",        "ZIP archive"},
    {SIG_RAR,        4,  "rar",        "RAR archive"},
    {SIG_7Z,         6,  "7z",         "7-Zip archive"},
    {SIG_CPIO_NEW,   6,  "cpio",       "cpio archive (new format)"},
    {SIG_CPIO_OLD,   2,  "cpio",       "cpio archive (old format)"},
    {SIG_AR,         7,  "ar",         "Unix ar archive / .deb package"},
    {SIG_SQFS_LE,    4,  "squashfs",   "SquashFS filesystem (little-endian)"},
    {SIG_SQFS_BE,    4,  "squashfs",   "SquashFS filesystem (big-endian)"},
    {SIG_CRAMFS_LE,  4,  "cramfs",     "CramFS filesystem (little-endian)"},
    {SIG_CRAMFS_BE,  4,  "cramfs",     "CramFS filesystem (big-endian)"},
    {SIG_JFFS2_LE,   2,  "jffs2",      "JFFS2 filesystem (little-endian)"},
    {SIG_JFFS2_BE,   2,  "jffs2",      "JFFS2 filesystem (big-endian)"},
    {SIG_ROMFS,      8,  "romfs",      "RomFS filesystem"},
    {SIG_UBIFS,      4,  "ubifs",      "UBIFS superblock"},
    {SIG_UBOOT,      4,  "uboot",      "U-Boot image header"},
    {SIG_TRX,        4,  "trx",        "Broadcom TRX firmware header"},
    {SIG_ANDROID_BOOT,8, "android",    "Android boot image"},
    {SIG_DTB,        4,  "dtb",        "Device Tree Blob"},
    {SIG_ELF,        4,  "elf",        "ELF executable"},
    {SIG_PE,         2,  "pe",         "PE/MZ executable"},
    {SIG_MACHO32_LE, 4,  "macho",      "Mach-O 32-bit (LE)"},
    {SIG_MACHO64_LE, 4,  "macho",      "Mach-O 64-bit (LE)"},
    {SIG_MACHO32_BE, 4,  "macho",      "Mach-O 32-bit (BE)"},
    {SIG_MACHO64_BE, 4,  "macho",      "Mach-O 64-bit (BE)"},
    {SIG_MACHO_FAT,  4,  "macho_fat",  "Mach-O Universal (fat) binary"},
    {SIG_DEX,        4,  "dex",        "Android DEX bytecode"},
    {SIG_PNG,        8,  "png",        "PNG image"},
    {SIG_JPEG,       3,  "jpeg",       "JPEG image"},
    {SIG_GIF,        4,  "gif",        "GIF image"},
    {SIG_BMP,        2,  "bmp",        "BMP image"},
    {SIG_PDF,        4,  "pdf",        "PDF document"},
    {SIG_SQLITE,     16, "sqlite",     "SQLite 3 database"},
};
static constexpr size_t g_sig_count = sizeof(g_signatures) / sizeof(g_signatures[0]);

// try to estimate embedded object size from its header
static size_t estimate_size(const uint8_t* data, size_t avail, const char* type) {
    if (strcmp(type, "gzip") == 0) {
        // scan for next gzip header or end
        for (size_t i = 10; i + 2 < avail; i++) {
            if (data[i] == 0x1f && data[i+1] == 0x8b && data[i+2] == 0x08)
                return i;
        }
        return avail;
    }
    if (strcmp(type, "zip") == 0 && avail >= 22) {
        // scan backward for end-of-central-directory
        size_t search = std::min(avail, (size_t)65557);
        for (size_t i = 4; i <= search; i++) {
            size_t pos = avail - i;
            if (data[pos] == 0x50 && data[pos+1] == 0x4b &&
                data[pos+2] == 0x05 && data[pos+3] == 0x06)
                return pos + 22; // EOCD minimum size
        }
    }
    if (strcmp(type, "elf") == 0 && avail >= 64) {
        bool is64 = (data[4] == 2);
        if (is64 && avail >= 64) {
            uint64_t shoff = *(uint64_t*)(data + 40);
            uint16_t shentsize = *(uint16_t*)(data + 58);
            uint16_t shnum = *(uint16_t*)(data + 60);
            size_t end = (size_t)(shoff + shentsize * shnum);
            if (end > 0 && end <= avail) return end;
        } else if (avail >= 52) {
            uint32_t shoff = *(uint32_t*)(data + 32);
            uint16_t shentsize = *(uint16_t*)(data + 46);
            uint16_t shnum = *(uint16_t*)(data + 48);
            size_t end = (size_t)(shoff + shentsize * shnum);
            if (end > 0 && end <= avail) return end;
        }
    }
    if (strcmp(type, "pe") == 0 && avail >= 64) {
        uint32_t pe_off = *(uint32_t*)(data + 0x3c);
        if (pe_off + 0x58 < avail && data[pe_off] == 'P' && data[pe_off+1] == 'E') {
            uint32_t size_of_image = *(uint32_t*)(data + pe_off + 0x50);
            if (size_of_image > 0 && size_of_image <= avail) return size_of_image;
        }
    }
    if (strcmp(type, "squashfs") == 0 && avail >= 96) {
        // squashfs superblock: bytes_used at offset 40 (LE) or byte-swapped
        uint64_t bytes_used = *(uint64_t*)(data + 40);
        if (bytes_used > 0 && bytes_used <= avail) return (size_t)bytes_used;
    }
    if (strcmp(type, "uboot") == 0 && avail >= 64) {
        // U-Boot header: data size at offset 12 (big-endian)
        uint32_t dsize = (data[12]<<24) | (data[13]<<16) | (data[14]<<8) | data[15];
        size_t total = 64 + dsize;
        if (total <= avail) return total;
    }
    if (strcmp(type, "png") == 0) {
        // scan for IEND chunk
        for (size_t i = 8; i + 12 < avail; i++) {
            if (data[i+4] == 'I' && data[i+5] == 'E' && data[i+6] == 'N' && data[i+7] == 'D') {
                uint32_t chunk_len = (data[i]<<24) | (data[i+1]<<16) | (data[i+2]<<8) | data[i+3];
                return i + 12 + chunk_len;
            }
        }
    }
    if (strcmp(type, "dtb") == 0 && avail >= 8) {
        uint32_t totalsize = (data[4]<<24) | (data[5]<<16) | (data[6]<<8) | data[7];
        if (totalsize > 0 && totalsize <= avail) return totalsize;
    }
    return 0;
}

void scan_signatures(BinaryImage& img) {
    img.signature_hits.clear();
    const uint8_t* raw = img.raw.data();
    size_t raw_sz = img.raw.size();

    // track what offsets we already matched to avoid jffs2 flooding (2-byte sigs)
    std::set<uint64_t> seen_offsets;

    for (size_t i = 0; i < raw_sz; i++) {
        for (size_t s = 0; s < g_sig_count; s++) {
            auto& sig = g_signatures[s];
            if (i + sig.len > raw_sz) continue;
            if (memcmp(raw + i, sig.magic, sig.len) != 0) continue;

            // PE: verify it's not just random MZ bytes -- check PE offset
            if (strcmp(sig.type, "pe") == 0) {
                if (i + 0x40 > raw_sz) continue;
                uint32_t pe_off = *(uint32_t*)(raw + i + 0x3c);
                if (i + pe_off + 4 > raw_sz) continue;
                if (raw[i + pe_off] != 'P' || raw[i + pe_off + 1] != 'E') continue;
            }
            // BMP: check file size field is reasonable
            if (strcmp(sig.type, "bmp") == 0 && i + 6 <= raw_sz) {
                uint32_t bmp_sz = *(uint32_t*)(raw + i + 2);
                if (bmp_sz < 26 || i + bmp_sz > raw_sz) continue;
            }
            // JFFS2: only report first occurrence to avoid flooding
            if (strcmp(sig.type, "jffs2") == 0) {
                if (!img.signature_hits.empty()) {
                    bool already = false;
                    for (auto& h : img.signature_hits) {
                        if (h.type == "jffs2") { already = true; break; }
                    }
                    if (already) continue;
                }
            }

            if (seen_offsets.count(i)) continue;
            seen_offsets.insert(i);

            SignatureHit hit;
            hit.offset = i;
            hit.va = img.offset_to_va(i).value_or(0);
            hit.type = sig.type;
            hit.description = sig.desc;
            hit.estimated_size = estimate_size(raw + i, raw_sz - i, sig.type);
            img.signature_hits.push_back(std::move(hit));
            break; // one match per offset
        }
    }

    // also scan for tar at offset 257
    for (size_t i = 0; i + 262 < raw_sz; i += 512) {
        if (memcmp(raw + i + 257, SIG_TAR_USTAR, 5) == 0) {
            if (seen_offsets.count(i)) continue;
            SignatureHit hit;
            hit.offset = i;
            hit.va = img.offset_to_va(i).value_or(0);
            hit.type = "tar";
            hit.description = "tar archive (ustar)";
            img.signature_hits.push_back(std::move(hit));
            break; // just report first tar block
        }
    }

    std::sort(img.signature_hits.begin(), img.signature_hits.end(),
              [](const SignatureHit& a, const SignatureHit& b) { return a.offset < b.offset; });

    fprintf(stderr, "[+] Signature scan: %zu hits\n", img.signature_hits.size());
}

// ---------------------------------------------------------------------------
// File carving
// ---------------------------------------------------------------------------
std::vector<CarvedFile> carve_files(const BinaryImage& img, const std::string& output_dir) {
    std::vector<CarvedFile> carved;
    std::filesystem::create_directories(output_dir);

    for (size_t i = 0; i < img.signature_hits.size(); i++) {
        auto& hit = img.signature_hits[i];
        size_t size = hit.estimated_size;
        if (size == 0) {
            // estimate to next signature or end of file
            if (i + 1 < img.signature_hits.size())
                size = (size_t)(img.signature_hits[i+1].offset - hit.offset);
            else
                size = img.raw.size() - (size_t)hit.offset;
        }
        if (size == 0 || hit.offset + size > img.raw.size()) continue;

        // determine extension
        std::string ext = hit.type;
        if (ext == "pe") ext = "exe";
        else if (ext == "macho" || ext == "macho_fat") ext = "macho";
        else if (ext == "uboot") ext = "uimage";
        else if (ext == "android") ext = "img";

        char fname[128];
        snprintf(fname, sizeof(fname), "%06llX.%s", (unsigned long long)hit.offset, ext.c_str());
        std::string path = (std::filesystem::path(output_dir) / fname).string();

        std::ofstream out(path, std::ios::binary);
        if (out) {
            out.write(reinterpret_cast<const char*>(img.raw.data() + hit.offset), size);
            CarvedFile cf;
            cf.offset = hit.offset;
            cf.size = size;
            cf.type = hit.type;
            cf.output_path = path;
            carved.push_back(std::move(cf));
        }
    }

    fprintf(stderr, "[+] Carved %zu files to %s\n", carved.size(), output_dir.c_str());
    return carved;
}

// ---------------------------------------------------------------------------
// Entropy heatmap
// ---------------------------------------------------------------------------
static float shannon_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0f;
    std::array<size_t, 256> freq = {};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    float ent = 0.0f;
    float inv = 1.0f / static_cast<float>(len);
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        float p = static_cast<float>(freq[i]) * inv;
        ent -= p * std::log2(p);
    }
    return ent;
}

void compute_entropy_heatmap(BinaryImage& img, size_t block_size) {
    img.entropy_heatmap.clear();
    if (img.raw.empty() || block_size == 0) return;

    size_t blocks = (img.raw.size() + block_size - 1) / block_size;
    img.entropy_heatmap.reserve(blocks);

    for (size_t i = 0; i < img.raw.size(); i += block_size) {
        size_t len = std::min(block_size, img.raw.size() - i);
        EntropyBlock eb;
        eb.offset = i;
        eb.entropy = shannon_entropy(img.raw.data() + i, len);
        img.entropy_heatmap.push_back(eb);
    }
    fprintf(stderr, "[+] Entropy heatmap: %zu blocks (block size %zu)\n",
        img.entropy_heatmap.size(), block_size);
}

// ---------------------------------------------------------------------------
// Base64 / hex encoded string detection
// ---------------------------------------------------------------------------
static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static bool is_b64_char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

static std::string decode_base64(const std::string& in) {
    static uint8_t table[256] = {};
    static bool init = false;
    if (!init) {
        memset(table, 0xff, 256);
        for (int i = 0; i < 64; i++) table[(uint8_t)b64_chars[i]] = i;
        table['='] = 0;
        init = true;
    }

    std::string out;
    out.reserve(in.size() * 3 / 4);
    uint32_t accum = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        uint8_t v = table[(uint8_t)c];
        if (v == 0xff) return {};
        accum = (accum << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((accum >> bits) & 0xff));
        }
    }
    return out;
}

static bool is_hex_char(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static std::string decode_hex(const std::string& in) {
    if (in.size() % 2 != 0) return {};
    std::string out;
    out.reserve(in.size() / 2);
    for (size_t i = 0; i < in.size(); i += 2) {
        char buf[3] = {in[i], in[i+1], 0};
        out.push_back(static_cast<char>(strtol(buf, nullptr, 16)));
    }
    return out;
}

static bool has_printable_content(const std::string& s) {
    if (s.empty()) return false;
    int printable = 0;
    for (uint8_t c : s) {
        if (c >= 0x20 && c < 0x7f) printable++;
    }
    return (printable * 100 / s.size()) > 60;
}

void detect_encoded_strings(BinaryImage& img) {
    img.encoded_strings.clear();
    const uint8_t* raw = img.raw.data();
    size_t sz = img.raw.size();

    // scan for base64 runs (min 20 chars, must be divisible by 4)
    size_t i = 0;
    while (i < sz) {
        if (!is_b64_char(raw[i]) || raw[i] == '=') { i++; continue; }

        size_t start = i;
        while (i < sz && is_b64_char(raw[i])) i++;
        size_t run_len = i - start;

        if (run_len >= 20) {
            std::string encoded(reinterpret_cast<const char*>(raw + start), run_len);
            // trim to valid base64 length
            size_t trim = encoded.size() % 4;
            if (trim) encoded.resize(encoded.size() - trim);
            if (encoded.size() < 20) continue;

            std::string decoded = decode_base64(encoded);
            if (decoded.size() >= 8 && has_printable_content(decoded)) {
                EncodedString es;
                es.offset = start;
                es.va = img.offset_to_va(start).value_or(0);
                es.encoded = encoded.substr(0, 120);
                if (encoded.size() > 120) es.encoded += "...";
                es.decoded = decoded.substr(0, 120);
                if (decoded.size() > 120) es.decoded += "...";
                es.encoding = "base64";
                img.encoded_strings.push_back(std::move(es));
            }
        }
    }

    // scan for hex runs (min 32 hex chars = 16 bytes)
    i = 0;
    while (i < sz) {
        if (!is_hex_char(raw[i])) { i++; continue; }

        size_t start = i;
        while (i < sz && is_hex_char(raw[i])) i++;
        size_t run_len = i - start;

        if (run_len >= 32 && run_len % 2 == 0 && run_len <= 4096) {
            // make sure it's not just digits or letters
            bool has_digit = false, has_alpha = false;
            for (size_t j = start; j < i; j++) {
                if (raw[j] >= '0' && raw[j] <= '9') has_digit = true;
                else has_alpha = true;
            }
            if (!has_digit || !has_alpha) continue;

            std::string encoded(reinterpret_cast<const char*>(raw + start), run_len);
            std::string decoded = decode_hex(encoded);
            if (!decoded.empty() && has_printable_content(decoded)) {
                EncodedString es;
                es.offset = start;
                es.va = img.offset_to_va(start).value_or(0);
                es.encoded = encoded.substr(0, 120);
                if (encoded.size() > 120) es.encoded += "...";
                es.decoded = decoded.substr(0, 120);
                if (decoded.size() > 120) es.decoded += "...";
                es.encoding = "hex";
                img.encoded_strings.push_back(std::move(es));
            }
        }
    }

    std::sort(img.encoded_strings.begin(), img.encoded_strings.end(),
              [](const EncodedString& a, const EncodedString& b) { return a.offset < b.offset; });
    fprintf(stderr, "[+] Encoded strings: %zu found\n", img.encoded_strings.size());
}

// ---------------------------------------------------------------------------
// Certificate / key extraction
// ---------------------------------------------------------------------------
struct PemMarker {
    const char* begin;
    const char* end;
    const char* type;
};

static const PemMarker g_pem_markers[] = {
    {"-----BEGIN CERTIFICATE-----",     "-----END CERTIFICATE-----",     "PEM Certificate"},
    {"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "PEM RSA Private Key"},
    {"-----BEGIN EC PRIVATE KEY-----",  "-----END EC PRIVATE KEY-----",  "PEM EC Private Key"},
    {"-----BEGIN PRIVATE KEY-----",     "-----END PRIVATE KEY-----",     "PEM Private Key (PKCS#8)"},
    {"-----BEGIN PUBLIC KEY-----",      "-----END PUBLIC KEY-----",      "PEM Public Key"},
    {"-----BEGIN DSA PRIVATE KEY-----", "-----END DSA PRIVATE KEY-----", "PEM DSA Private Key"},
    {"-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----", "PEM Encrypted Private Key"},
    {"-----BEGIN X509 CRL-----",        "-----END X509 CRL-----",       "PEM X.509 CRL"},
    {"-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----", "PEM CSR"},
};
void extract_certificates(BinaryImage& img) {
    img.certificate_hits.clear();
    const char* raw = reinterpret_cast<const char*>(img.raw.data());
    size_t sz = img.raw.size();

    // PEM markers
    for (auto& marker : g_pem_markers) {
        size_t begin_len = strlen(marker.begin);
        size_t end_len = strlen(marker.end);

        const char* p = raw;
        const char* end = raw + sz;
        while (p + begin_len < end) {
            const char* found = static_cast<const char*>(
                memmem(p, end - p, marker.begin, begin_len));
            if (!found) break;

            size_t off = found - raw;
            const char* end_found = static_cast<const char*>(
                memmem(found + begin_len, end - (found + begin_len), marker.end, end_len));

            CertificateHit ch;
            ch.offset = off;
            ch.va = img.offset_to_va(off).value_or(0);
            ch.type = marker.type;
            if (end_found) {
                ch.size = (end_found + end_len) - found;
                ch.details = std::string(found, std::min(ch.size, (size_t)256));
                if (ch.size > 256) ch.details += "...";
            } else {
                ch.size = std::min((size_t)256, (size_t)(end - found));
                ch.details = std::string(found, ch.size);
            }
            img.certificate_hits.push_back(std::move(ch));
            p = found + begin_len;
        }
    }

    // SSH public key markers
    static const char* ssh_markers[] = {"ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-"};
    for (auto& ssh : ssh_markers) {
        size_t ssh_len = strlen(ssh);
        const char* p = raw;
        const char* end_ptr = raw + sz;
        while (p + ssh_len < end_ptr) {
            const char* found = static_cast<const char*>(
                memmem(p, end_ptr - p, ssh, ssh_len));
            if (!found) break;
            size_t off = found - raw;
            // read until newline or non-printable
            size_t key_len = 0;
            while (found + key_len < end_ptr && found[key_len] >= 0x20 && found[key_len] < 0x7f)
                key_len++;

            if (key_len > 20) {
                CertificateHit ch;
                ch.offset = off;
                ch.va = img.offset_to_va(off).value_or(0);
                ch.type = "SSH Public Key";
                ch.size = key_len;
                ch.details = std::string(found, std::min(key_len, (size_t)200));
                if (key_len > 200) ch.details += "...";
                img.certificate_hits.push_back(std::move(ch));
            }
            p = found + ssh_len;
        }
    }

    // DER certificate detection (ASN.1 SEQUENCE with reasonable length)
    for (size_t i = 0; i + 4 < sz; i++) {
        if (img.raw[i] != 0x30 || img.raw[i+1] != 0x82) continue;
        uint16_t der_len = (img.raw[i+2] << 8) | img.raw[i+3];
        if (der_len < 128 || i + 4 + der_len > sz) continue;
        // check for certificate OID (2.5.4 = 55 04)
        bool has_cert_oid = false;
        for (size_t j = i + 4; j + 4 < i + 4 + der_len && j + 4 < sz; j++) {
            if (img.raw[j] == 0x55 && img.raw[j+1] == 0x04) {
                has_cert_oid = true;
                break;
            }
        }
        if (!has_cert_oid) continue;

        CertificateHit ch;
        ch.offset = i;
        ch.va = img.offset_to_va(i).value_or(0);
        ch.type = "DER Certificate";
        ch.size = 4 + der_len;
        char buf[64];
        snprintf(buf, sizeof(buf), "DER encoded, %u bytes", (unsigned)(4 + der_len));
        ch.details = buf;
        img.certificate_hits.push_back(std::move(ch));
        i += 3 + der_len; // skip past
    }

    std::sort(img.certificate_hits.begin(), img.certificate_hits.end(),
              [](const CertificateHit& a, const CertificateHit& b) { return a.offset < b.offset; });
    fprintf(stderr, "[+] Certificate/key scan: %zu hits\n", img.certificate_hits.size());
}

// ---------------------------------------------------------------------------
// Firmware header parsing
// ---------------------------------------------------------------------------
void parse_firmware_headers(BinaryImage& img) {
    img.firmware_headers.clear();
    const uint8_t* raw = img.raw.data();
    size_t sz = img.raw.size();

    for (auto& hit : img.signature_hits) {
        size_t off = (size_t)hit.offset;
        size_t avail = sz - off;
        const uint8_t* p = raw + off;

        if (hit.type == "uboot" && avail >= 64) {
            FirmwareHeader fh;
            fh.offset = off;
            fh.type = "U-Boot Image";
            uint32_t ih_size  = (p[12]<<24)|(p[13]<<16)|(p[14]<<8)|p[15];
            uint32_t ih_load  = (p[16]<<24)|(p[17]<<16)|(p[18]<<8)|p[19];
            uint32_t ih_ep    = (p[20]<<24)|(p[21]<<16)|(p[22]<<8)|p[23];
            uint8_t  ih_os    = p[28];
            uint8_t  ih_arch  = p[29];
            uint8_t  ih_comp  = p[31];
            char name[33] = {};
            memcpy(name, p + 32, 32);

            static const char* os_names[] = {"Invalid","OpenBSD","NetBSD","FreeBSD","4.4BSD","Linux",
                "SVR4","Esix","Solaris","Irix","SCO","Dell","NCR","LynxOS","VxWorks","pSOS",
                "QNX","U-Boot","RTEMS","ARTOS","Unity","INTEGRITY"};
            static const char* arch_names[] = {"Invalid","Alpha","ARM","x86","IA64","MIPS","MIPS64",
                "PPC","S390","SH","SPARC","SPARC64","M68K","Nios","MicroBlaze","Nios2",
                "Blackfin","AVR32","ST200","Sandbox","NDS32","OpenRISC","ARM64","ARC","x86_64","Xtensa","RISCV"};
            static const char* comp_names[] = {"none","gzip","bzip2","lzma","lzo","lz4","zstd"};

            std::ostringstream ss;
            ss << "Name: " << name;
            ss << " | Size: " << ih_size;
            ss << " | Load: 0x" << std::hex << ih_load;
            ss << " | Entry: 0x" << ih_ep << std::dec;
            if (ih_os < sizeof(os_names)/sizeof(os_names[0]))
                ss << " | OS: " << os_names[ih_os];
            if (ih_arch < sizeof(arch_names)/sizeof(arch_names[0]))
                ss << " | Arch: " << arch_names[ih_arch];
            if (ih_comp < sizeof(comp_names)/sizeof(comp_names[0]))
                ss << " | Compression: " << comp_names[ih_comp];
            fh.details = ss.str();
            img.firmware_headers.push_back(std::move(fh));
        }

        if (hit.type == "trx" && avail >= 28) {
            FirmwareHeader fh;
            fh.offset = off;
            fh.type = "Broadcom TRX";
            uint32_t trx_len = p[4]|(p[5]<<8)|(p[6]<<16)|(p[7]<<24);
            uint32_t trx_crc = p[8]|(p[9]<<8)|(p[10]<<16)|(p[11]<<24);
            uint32_t off1 = p[16]|(p[17]<<8)|(p[18]<<16)|(p[19]<<24);
            uint32_t off2 = p[20]|(p[21]<<8)|(p[22]<<16)|(p[23]<<24);
            uint32_t off3 = p[24]|(p[25]<<8)|(p[26]<<16)|(p[27]<<24);

            std::ostringstream ss;
            ss << "Length: " << trx_len << " | CRC: 0x" << std::hex << trx_crc << std::dec;
            ss << " | Partitions: 0x" << std::hex << off1 << ", 0x" << off2 << ", 0x" << off3;
            fh.details = ss.str();
            img.firmware_headers.push_back(std::move(fh));
        }

        if (hit.type == "squashfs" && avail >= 96) {
            FirmwareHeader fh;
            fh.offset = off;
            fh.type = "SquashFS";
            bool le = (p[0] == 'h'); // hsqs = LE
            uint32_t inodes, block_size, frags;
            uint16_t comp;
            if (le) {
                inodes = p[4]|(p[5]<<8)|(p[6]<<16)|(p[7]<<24);
                block_size = p[12]|(p[13]<<8)|(p[14]<<16)|(p[15]<<24);
                frags = p[16]|(p[17]<<8)|(p[18]<<16)|(p[19]<<24);
                comp = p[20]|(p[21]<<8);
            } else {
                inodes = (p[4]<<24)|(p[5]<<16)|(p[6]<<8)|p[7];
                block_size = (p[12]<<24)|(p[13]<<16)|(p[14]<<8)|p[15];
                frags = (p[16]<<24)|(p[17]<<16)|(p[18]<<8)|p[19];
                comp = (p[20]<<8)|p[21];
            }
            static const char* comp_names[] = {"gzip","lzma","lzo","xz","lz4","zstd"};
            std::ostringstream ss;
            ss << "Inodes: " << inodes << " | Block: " << block_size << " | Frags: " << frags;
            if (comp >= 1 && comp <= 6) ss << " | Comp: " << comp_names[comp-1];
            ss << " | Endian: " << (le ? "LE" : "BE");
            fh.details = ss.str();
            img.firmware_headers.push_back(std::move(fh));
        }

        if (hit.type == "dtb" && avail >= 40) {
            FirmwareHeader fh;
            fh.offset = off;
            fh.type = "Device Tree Blob";
            uint32_t totalsize = (p[4]<<24)|(p[5]<<16)|(p[6]<<8)|p[7];
            uint32_t version = (p[20]<<24)|(p[21]<<16)|(p[22]<<8)|p[23];
            std::ostringstream ss;
            ss << "Size: " << totalsize << " | Version: " << version;
            fh.details = ss.str();
            img.firmware_headers.push_back(std::move(fh));
        }

        if (hit.type == "android" && avail >= 48) {
            FirmwareHeader fh;
            fh.offset = off;
            fh.type = "Android Boot Image";
            uint32_t kernel_sz = p[8]|(p[9]<<8)|(p[10]<<16)|(p[11]<<24);
            uint32_t kernel_addr = p[12]|(p[13]<<8)|(p[14]<<16)|(p[15]<<24);
            uint32_t ramdisk_sz = p[16]|(p[17]<<8)|(p[18]<<16)|(p[19]<<24);
            uint32_t ramdisk_addr = p[20]|(p[21]<<8)|(p[22]<<16)|(p[23]<<24);
            std::ostringstream ss;
            ss << "Kernel: " << kernel_sz << " bytes @ 0x" << std::hex << kernel_addr;
            ss << " | Ramdisk: " << std::dec << ramdisk_sz << " bytes @ 0x" << std::hex << ramdisk_addr;
            fh.details = ss.str();
            img.firmware_headers.push_back(std::move(fh));
        }
    }
    fprintf(stderr, "[+] Firmware headers: %zu parsed\n", img.firmware_headers.size());
}

// ---------------------------------------------------------------------------
// Yara-like scanner (simplified)
// ---------------------------------------------------------------------------
struct YaraRule {
    std::string name;
    struct Pattern {
        std::string id;
        std::vector<uint8_t> bytes;
        std::vector<bool> mask;  // true = match this byte, false = wildcard
        bool text = false;
        bool nocase = false;
    };
    std::vector<Pattern> patterns;
    std::string condition; // "any of them" or "all of them" or "$name"
};

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    return s.substr(a, b - a + 1);
}

static std::vector<YaraRule> parse_yara_rules(const std::string& text) {
    std::vector<YaraRule> rules;
    std::istringstream iss(text);
    std::string line;

    YaraRule current;
    bool in_rule = false;
    bool in_strings = false;
    bool in_condition = false;

    while (std::getline(iss, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '/' || t.substr(0, 2) == "//") continue;

        if (!in_rule) {
            if (t.substr(0, 5) == "rule " || t.substr(0, 5) == "rule\t") {
                current = {};
                size_t name_start = 5;
                while (name_start < t.size() && (t[name_start] == ' ' || t[name_start] == '\t'))
                    name_start++;
                size_t name_end = t.find_first_of(" \t{", name_start);
                current.name = t.substr(name_start, name_end - name_start);
                in_rule = true;
            }
            continue;
        }

        if (t == "strings:" || t == "strings :") { in_strings = true; in_condition = false; continue; }
        if (t == "condition:" || t == "condition :") { in_condition = true; in_strings = false; continue; }

        if (t == "}") {
            if (current.condition.empty()) current.condition = "any of them";
            rules.push_back(std::move(current));
            current = {};
            in_rule = false; in_strings = false; in_condition = false;
            continue;
        }

        if (in_strings) {
            // parse: $name = { hex bytes } or $name = "text"
            size_t eq = t.find('=');
            if (eq == std::string::npos) continue;
            YaraRule::Pattern pat;
            pat.id = trim(t.substr(0, eq));

            std::string val = trim(t.substr(eq + 1));
            if (val.front() == '{' && val.back() == '}') {
                // hex pattern
                std::string hex_str = val.substr(1, val.size() - 2);
                std::istringstream hs(hex_str);
                std::string token;
                while (hs >> token) {
                    if (token == "??" || token == "?") {
                        pat.bytes.push_back(0);
                        pat.mask.push_back(false);
                    } else {
                        pat.bytes.push_back(static_cast<uint8_t>(strtol(token.c_str(), nullptr, 16)));
                        pat.mask.push_back(true);
                    }
                }
            } else if (val.size() >= 2 && val.front() == '"') {
                // text pattern
                size_t end_q = val.find('"', 1);
                if (end_q != std::string::npos) {
                    std::string text_val = val.substr(1, end_q - 1);
                    pat.text = true;
                    if (val.find("nocase") != std::string::npos) pat.nocase = true;
                    for (char c : text_val) {
                        pat.bytes.push_back(static_cast<uint8_t>(c));
                        pat.mask.push_back(true);
                    }
                }
            }
            if (!pat.bytes.empty()) current.patterns.push_back(std::move(pat));
        }

        if (in_condition) {
            current.condition += " " + t;
        }
    }

    return rules;
}

std::vector<YaraMatch> run_yara_scan(const BinaryImage& img, const std::string& rules_text) {
    std::vector<YaraMatch> matches;
    auto rules = parse_yara_rules(rules_text);

    for (auto& rule : rules) {
        std::string cond = trim(rule.condition);
        bool need_all = (cond.find("all of them") != std::string::npos);

        int matched_patterns = 0;

        for (auto& pat : rule.patterns) {
            if (pat.bytes.empty()) continue;
            size_t pat_len = pat.bytes.size();

            for (size_t i = 0; i + pat_len <= img.raw.size(); i++) {
                bool match = true;
                for (size_t j = 0; j < pat_len; j++) {
                    if (!pat.mask[j]) continue;
                    uint8_t file_byte = img.raw[i + j];
                    uint8_t pat_byte = pat.bytes[j];
                    if (pat.nocase) {
                        if (tolower(file_byte) != tolower(pat_byte)) { match = false; break; }
                    } else {
                        if (file_byte != pat_byte) { match = false; break; }
                    }
                }
                if (match) {
                    YaraMatch m;
                    m.rule_name = rule.name;
                    m.offset = i;
                    m.length = pat_len;
                    m.matched_data = pat.id;
                    matches.push_back(std::move(m));
                    matched_patterns++;
                    break; // one match per pattern per rule is enough
                }
            }
        }

        if (need_all && matched_patterns < (int)rule.patterns.size()) {
            // remove matches for this rule since condition not met
            matches.erase(
                std::remove_if(matches.begin(), matches.end(),
                    [&](const YaraMatch& m) { return m.rule_name == rule.name; }),
                matches.end());
        }
    }

    fprintf(stderr, "[+] Yara scan: %zu matches\n", matches.size());
    return matches;
}

}
