#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <optional>
#include <memory>

namespace aida {

enum class Arch : uint8_t {
    Unknown,
    X86,
    X86_64,
    ARM,
    ARM64,
    MIPS_LE,
    MIPS_BE,
    MIPS64_LE,
    MIPS64_BE,
    RISCV32,
    RISCV64,
    PPC,
    PPC64,
};

enum class BinaryFormat : uint8_t {
    Unknown,
    PE,
    ELF,
    MachO,
    Raw,
};

enum class Endian : uint8_t { Little, Big };

inline Endian arch_endian(Arch a) {
    switch (a) {
    case Arch::MIPS_BE: case Arch::MIPS64_BE:
    case Arch::PPC: case Arch::PPC64:
        return Endian::Big;
    default:
        return Endian::Little;
    }
}

inline int arch_bits(Arch a) {
    switch (a) {
    case Arch::X86: case Arch::ARM: case Arch::MIPS_LE: case Arch::MIPS_BE:
    case Arch::RISCV32: case Arch::PPC:
        return 32;
    case Arch::X86_64: case Arch::ARM64: case Arch::MIPS64_LE: case Arch::MIPS64_BE:
    case Arch::RISCV64: case Arch::PPC64:
        return 64;
    default:
        return 0;
    }
}

struct Section {
    std::string name;
    uint64_t    vaddr      = 0;
    uint64_t    vsize      = 0;
    uint64_t    file_off   = 0;
    uint64_t    file_size  = 0;
    bool        executable = false;
    bool        writable   = false;
    bool        readable   = true;
};

struct ImportEntry {
    std::string module;
    std::string name;
    uint16_t    ordinal = 0;
    uint64_t    iat_rva = 0;
};

struct ExportEntry {
    std::string name;
    uint64_t    rva     = 0;
    uint16_t    ordinal = 0;
    bool        forwarded = false;
    std::string forward_name;
};

struct Symbol {
    std::string name;
    uint64_t    addr = 0;
    uint64_t    size = 0;
    bool        is_func = false;
};

struct Instruction {
    uint64_t    addr = 0;
    uint16_t    size = 0;
    std::string mnemonic;
    std::string operands;
    std::vector<uint8_t> bytes;
};

enum class XrefType : uint8_t {
    Call,
    Jump,
    Data,
    String,
};

struct Xref {
    uint64_t from = 0;
    uint64_t to   = 0;
    XrefType type = XrefType::Data;
};

struct FoundString {
    uint64_t    addr = 0;
    std::string value;
    bool        wide = false;
};

struct Function {
    uint64_t    addr = 0;
    uint64_t    end_addr = 0;
    std::string name;
    bool        user_named = false;
    bool        is_import  = false;
    bool        is_export  = false;
    bool        is_nullsub = false;
    std::vector<Instruction> instructions;
};

struct BinaryImage {
    std::string             path;
    std::string             filename;
    BinaryFormat            format   = BinaryFormat::Unknown;
    Arch                    arch     = Arch::Unknown;
    uint64_t                base     = 0;
    uint64_t                entry    = 0;
    std::vector<uint8_t>    raw;

    std::vector<Section>     sections;
    std::vector<ImportEntry> imports;
    std::vector<ExportEntry> exports;
    std::vector<Symbol>      symbols;

    std::map<uint64_t, Function>     functions;
    std::vector<Xref>                xrefs;
    std::unordered_map<uint64_t, std::vector<uint32_t>> xref_to_idx;
    std::vector<FoundString>         strings;

    std::unordered_map<uint64_t, std::string> user_comments;
    std::unordered_map<uint64_t, std::string> user_names;

    struct CryptoHitRef {
        uint64_t    addr = 0;
        std::string algorithm;
        std::string constant_name;
        size_t      match_len = 0;
    };
    std::vector<CryptoHitRef> crypto_hits;

    struct SectionEntropyRef {
        std::string name;
        double      entropy = 0.0;
        bool        packed = false;
    };
    std::vector<SectionEntropyRef> section_entropy;
    double overall_entropy = 0.0;
    bool   likely_packed = false;

    std::string imphash;

    struct NetworkRef {
        uint64_t    addr = 0;
        std::string value;
        std::string type;  // url, ipv4, ipv6, domain, email, mac, port
    };
    std::vector<NetworkRef> network_refs;

    std::vector<uint64_t> bookmarks;

    // firmware analysis results (structs defined here to avoid circular deps)
    struct SignatureHit {
        uint64_t offset = 0; uint64_t va = 0;
        std::string type, description;
        size_t estimated_size = 0;
    };
    std::vector<SignatureHit> signature_hits;

    struct EntropyBlock { uint64_t offset = 0; float entropy = 0.0f; };
    std::vector<EntropyBlock> entropy_heatmap;

    struct EncodedString {
        uint64_t offset = 0; uint64_t va = 0;
        std::string encoded, decoded, encoding;
    };
    std::vector<EncodedString> encoded_strings;

    struct CertificateHit {
        uint64_t offset = 0; uint64_t va = 0;
        std::string type, details;
        size_t size = 0;
    };
    std::vector<CertificateHit> certificate_hits;

    struct FirmwareHeader {
        uint64_t offset = 0;
        std::string type, details;
    };
    std::vector<FirmwareHeader> firmware_headers;

    const uint8_t* bytes_at_va(uint64_t va, size_t* out_len = nullptr) const;
    std::optional<uint64_t> va_to_offset(uint64_t va) const;
    std::optional<uint64_t> offset_to_va(uint64_t off) const;
    const Section* section_for_va(uint64_t va) const;
};

}
