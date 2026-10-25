#include "core/imphash.hpp"
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace aida {

// Minimal MD5 implementation (RFC 1321) -- just for imphash, not general use
namespace {

struct MD5Ctx {
    uint32_t state[4];
    uint64_t count;
    uint8_t  buffer[64];
};

static const uint32_t MD5_T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const uint8_t MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
};

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);

    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16)      { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d;          g = (3*i + 5) % 16; }
        else              { f = c ^ (b | ~d);       g = (7*i) % 16; }

        uint32_t tmp = d;
        d = c; c = b;
        b = b + rotl32(a + f + MD5_T[i] + M[g], MD5_S[i]);
        a = tmp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5_init(MD5Ctx& ctx) {
    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xefcdab89;
    ctx.state[2] = 0x98badcfe;
    ctx.state[3] = 0x10325476;
    ctx.count = 0;
    memset(ctx.buffer, 0, 64);
}

static void md5_update(MD5Ctx& ctx, const uint8_t* data, size_t len) {
    size_t buf_used = (size_t)(ctx.count & 63);
    ctx.count += len;

    if (buf_used) {
        size_t fill = 64 - buf_used;
        if (len < fill) {
            memcpy(ctx.buffer + buf_used, data, len);
            return;
        }
        memcpy(ctx.buffer + buf_used, data, fill);
        md5_transform(ctx.state, ctx.buffer);
        data += fill;
        len -= fill;
    }

    while (len >= 64) {
        md5_transform(ctx.state, data);
        data += 64;
        len -= 64;
    }

    if (len > 0)
        memcpy(ctx.buffer, data, len);
}

static void md5_final(MD5Ctx& ctx, uint8_t digest[16]) {
    size_t buf_used = (size_t)(ctx.count & 63);
    ctx.buffer[buf_used++] = 0x80;

    if (buf_used > 56) {
        memset(ctx.buffer + buf_used, 0, 64 - buf_used);
        md5_transform(ctx.state, ctx.buffer);
        buf_used = 0;
    }
    memset(ctx.buffer + buf_used, 0, 56 - buf_used);

    uint64_t bits = ctx.count * 8;
    for (int i = 0; i < 8; i++)
        ctx.buffer[56 + i] = (uint8_t)(bits >> (i * 8));

    md5_transform(ctx.state, ctx.buffer);

    for (int i = 0; i < 4; i++) {
        digest[i*4]   = (uint8_t)(ctx.state[i]);
        digest[i*4+1] = (uint8_t)(ctx.state[i] >> 8);
        digest[i*4+2] = (uint8_t)(ctx.state[i] >> 16);
        digest[i*4+3] = (uint8_t)(ctx.state[i] >> 24);
    }
}

static std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return out;
}

static std::string strip_extension(const std::string& dll) {
    std::string d = to_lower(dll);
    if (d.size() > 4) {
        std::string ext = d.substr(d.size() - 4);
        if (ext == ".dll" || ext == ".sys" || ext == ".ocx" || ext == ".drv")
            d = d.substr(0, d.size() - 4);
    }
    return d;
}

} // anon

std::string compute_imphash(const BinaryImage& img) {
    if (img.format != BinaryFormat::PE || img.imports.empty())
        return "";

    std::vector<std::string> entries;
    entries.reserve(img.imports.size());

    for (auto& imp : img.imports) {
        if (imp.name.empty()) continue;
        std::string entry = strip_extension(imp.module) + "." + to_lower(imp.name);
        entries.push_back(std::move(entry));
    }

    if (entries.empty()) return "";

    std::string combined;
    for (size_t i = 0; i < entries.size(); i++) {
        if (i > 0) combined += ",";
        combined += entries[i];
    }

    MD5Ctx ctx;
    md5_init(ctx);
    md5_update(ctx, reinterpret_cast<const uint8_t*>(combined.data()), combined.size());
    uint8_t digest[16];
    md5_final(ctx, digest);

    std::ostringstream ss;
    for (int i = 0; i < 16; i++)
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)digest[i];

    return ss.str();
}

}
