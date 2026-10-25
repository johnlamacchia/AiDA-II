#include "core/decrypt.hpp"
#include <cstring>
#include <algorithm>
#include <cmath>
#include <array>

namespace aida {

static double quick_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    std::array<size_t, 256> freq = {};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        e -= p * std::log2(p);
    }
    return e;
}

static double printable_ratio(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    size_t printable = 0;
    for (size_t i = 0; i < len; i++)
        if (data[i] >= 0x20 && data[i] < 0x7F) printable++;
    return (double)printable / (double)len;
}

// -------------------------------------------------------------------------
// XOR single byte
// -------------------------------------------------------------------------
DecryptResult xor_decrypt(const uint8_t* data, size_t len, uint8_t key) {
    DecryptResult r;
    r.algorithm = "xor_single";
    r.output.resize(len);
    for (size_t i = 0; i < len; i++) r.output[i] = data[i] ^ key;
    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = quick_entropy(r.output.data(), r.output.size());
    r.success = true;
    r.note = "key=0x" + std::string(2, '0');
    char hex[8]; snprintf(hex, sizeof(hex), "0x%02X", key);
    r.note = std::string("key=") + hex;
    return r;
}

// -------------------------------------------------------------------------
// XOR multi-byte
// -------------------------------------------------------------------------
DecryptResult xor_decrypt(const uint8_t* data, size_t len, const uint8_t* key, size_t key_len) {
    DecryptResult r;
    r.algorithm = "xor_multi";
    if (key_len == 0) { r.success = false; r.note = "empty key"; return r; }
    r.output.resize(len);
    for (size_t i = 0; i < len; i++) r.output[i] = data[i] ^ key[i % key_len];
    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = quick_entropy(r.output.data(), r.output.size());
    r.success = true;
    std::string key_hex;
    for (size_t i = 0; i < key_len && i < 32; i++) {
        char h[4]; snprintf(h, sizeof(h), "%02X", key[i]);
        key_hex += h;
    }
    r.note = "key=" + key_hex + (key_len > 32 ? "..." : "");
    return r;
}

// -------------------------------------------------------------------------
// XOR bruteforce
// -------------------------------------------------------------------------
DecryptResult xor_bruteforce(const uint8_t* data, size_t len) {
    DecryptResult best;
    best.algorithm = "xor_bruteforce";
    best.success = false;
    double best_score = -1.0;

    size_t sample_len = std::min(len, (size_t)4096);
    std::vector<uint8_t> tmp(sample_len);

    for (int key = 1; key < 256; key++) {
        for (size_t i = 0; i < sample_len; i++) tmp[i] = data[i] ^ (uint8_t)key;
        double pr = printable_ratio(tmp.data(), sample_len);
        double ent = quick_entropy(tmp.data(), sample_len);
        // score: high printable ratio + lower entropy = likely plaintext
        double score = pr * 3.0 + (8.0 - ent);
        if (score > best_score) {
            best_score = score;
            best.output.resize(len);
            for (size_t i = 0; i < len; i++) best.output[i] = data[i] ^ (uint8_t)key;
            best.entropy_before = quick_entropy(data, len);
            best.entropy_after = quick_entropy(best.output.data(), best.output.size());
            best.success = true;
            char hex[8]; snprintf(hex, sizeof(hex), "0x%02X", key);
            best.note = std::string("best_key=") + hex +
                " printable=" + std::to_string((int)(pr * 100)) + "%"
                " entropy=" + std::to_string(ent).substr(0, 4);
        }
    }
    return best;
}

// -------------------------------------------------------------------------
// RC4
// -------------------------------------------------------------------------
DecryptResult rc4_decrypt(const uint8_t* data, size_t len, const uint8_t* key, size_t key_len) {
    DecryptResult r;
    r.algorithm = "rc4";
    if (key_len == 0) { r.success = false; r.note = "empty key"; return r; }

    // KSA
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = j + S[i] + key[i % key_len];
        std::swap(S[i], S[(int)j]);
    }

    // PRGA
    r.output.resize(len);
    uint8_t si = 0; j = 0;
    for (size_t n = 0; n < len; n++) {
        si++;
        j = j + S[si];
        std::swap(S[si], S[j]);
        r.output[n] = data[n] ^ S[(uint8_t)(S[si] + S[j])];
    }

    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = quick_entropy(r.output.data(), r.output.size());
    r.success = true;

    std::string key_hex;
    for (size_t i = 0; i < key_len && i < 32; i++) {
        char h[4]; snprintf(h, sizeof(h), "%02X", key[i]);
        key_hex += h;
    }
    r.note = "key=" + key_hex;
    return r;
}

// -------------------------------------------------------------------------
// ROT-N
// -------------------------------------------------------------------------
DecryptResult rot_decrypt(const uint8_t* data, size_t len, int n) {
    DecryptResult r;
    r.algorithm = "rot" + std::to_string(n);
    r.output.resize(len);
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        if (c >= 'A' && c <= 'Z') c = 'A' + (c - 'A' + n) % 26;
        else if (c >= 'a' && c <= 'z') c = 'a' + (c - 'a' + n) % 26;
        r.output[i] = c;
    }
    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = quick_entropy(r.output.data(), r.output.size());
    r.success = true;
    r.note = "shift=" + std::to_string(n);
    return r;
}

// -------------------------------------------------------------------------
// Base64 decode
// -------------------------------------------------------------------------
static const int8_t b64_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

DecryptResult base64_decode(const uint8_t* data, size_t len) {
    DecryptResult r;
    r.algorithm = "base64";

    // strip whitespace
    std::vector<uint8_t> clean;
    clean.reserve(len);
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '=' || b64_table[data[i]] >= 0) clean.push_back(data[i]);
        else if (data[i] == '\r' || data[i] == '\n' || data[i] == ' ' || data[i] == '\t') continue;
        else { r.success = false; r.note = "invalid base64 character"; return r; }
    }

    r.output.reserve(clean.size() * 3 / 4);
    for (size_t i = 0; i < clean.size(); ) {
        uint32_t accum = 0;
        int bits = 0;
        for (int j = 0; j < 4 && i < clean.size(); j++, i++) {
            if (clean[i] == '=') { bits += 6; continue; }
            int val = b64_table[clean[i]];
            if (val < 0) break;
            accum = (accum << 6) | val;
            bits += 6;
        }
        if (bits >= 8) { r.output.push_back((accum >> (bits - 8)) & 0xFF); bits -= 8; }
        if (bits >= 8) { r.output.push_back((accum >> (bits - 8)) & 0xFF); bits -= 8; }
        if (bits >= 8) { r.output.push_back((accum >> (bits - 8)) & 0xFF); }
    }

    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = quick_entropy(r.output.data(), r.output.size());
    r.success = true;
    r.note = "decoded " + std::to_string(len) + " -> " + std::to_string(r.output.size()) + " bytes";
    return r;
}

// -------------------------------------------------------------------------
// Reverse bytes
// -------------------------------------------------------------------------
DecryptResult reverse_bytes(const uint8_t* data, size_t len) {
    DecryptResult r;
    r.algorithm = "reverse";
    r.output.assign(data, data + len);
    std::reverse(r.output.begin(), r.output.end());
    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = r.entropy_before; // same entropy
    r.success = true;
    return r;
}

// -------------------------------------------------------------------------
// NOT (bitwise complement)
// -------------------------------------------------------------------------
DecryptResult not_decrypt(const uint8_t* data, size_t len) {
    DecryptResult r;
    r.algorithm = "not";
    r.output.resize(len);
    for (size_t i = 0; i < len; i++) r.output[i] = ~data[i];
    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = r.entropy_before;
    r.success = true;
    return r;
}

// -------------------------------------------------------------------------
// ADD/SUB constant byte
// -------------------------------------------------------------------------
DecryptResult add_decrypt(const uint8_t* data, size_t len, uint8_t key) {
    DecryptResult r;
    r.algorithm = "add";
    r.output.resize(len);
    for (size_t i = 0; i < len; i++) r.output[i] = data[i] + key;
    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = r.entropy_before;
    r.success = true;
    char hex[8]; snprintf(hex, sizeof(hex), "0x%02X", key);
    r.note = std::string("key=") + hex;
    return r;
}

DecryptResult sub_decrypt(const uint8_t* data, size_t len, uint8_t key) {
    DecryptResult r;
    r.algorithm = "sub";
    r.output.resize(len);
    for (size_t i = 0; i < len; i++) r.output[i] = data[i] - key;
    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = r.entropy_before;
    r.success = true;
    char hex[8]; snprintf(hex, sizeof(hex), "0x%02X", key);
    r.note = std::string("key=") + hex;
    return r;
}

// -------------------------------------------------------------------------
// Rolling XOR
// -------------------------------------------------------------------------
DecryptResult rolling_xor_decrypt(const uint8_t* data, size_t len, uint8_t seed) {
    DecryptResult r;
    r.algorithm = "rolling_xor";
    r.output.resize(len);
    uint8_t prev = seed;
    for (size_t i = 0; i < len; i++) {
        r.output[i] = data[i] ^ prev;
        prev = data[i];
    }
    r.entropy_before = quick_entropy(data, len);
    r.entropy_after = quick_entropy(r.output.data(), r.output.size());
    r.success = true;
    char hex[8]; snprintf(hex, sizeof(hex), "0x%02X", seed);
    r.note = std::string("seed=") + hex;
    return r;
}

// -------------------------------------------------------------------------
// Auto-detect
// -------------------------------------------------------------------------
static double score_result(const DecryptResult& r) {
    if (r.output.empty()) return -1.0;
    size_t sample = std::min(r.output.size(), (size_t)4096);
    double pr = printable_ratio(r.output.data(), sample);
    return pr * 3.0 + (8.0 - r.entropy_after);
}

DecryptResult auto_decrypt(const uint8_t* data, size_t len) {
    struct Candidate {
        DecryptResult result;
        double score;
    };

    double orig_entropy = quick_entropy(data, len);
    double orig_printable = printable_ratio(data, len);

    if (orig_entropy < 4.0 && orig_printable > 0.7) {
        DecryptResult r;
        r.algorithm = "none";
        r.success = false;
        r.note = "data already looks like plaintext (entropy=" +
            std::to_string(orig_entropy).substr(0, 4) +
            " printable=" + std::to_string((int)(orig_printable * 100)) + "%)";
        r.entropy_before = orig_entropy;
        return r;
    }

    std::vector<Candidate> candidates;

    auto xbf = xor_bruteforce(data, len);
    candidates.push_back({std::move(xbf), 0.0});
    candidates.back().score = score_result(candidates.back().result);

    auto nr = not_decrypt(data, len);
    candidates.push_back({std::move(nr), 0.0});
    candidates.back().score = score_result(candidates.back().result);

    if (orig_printable > 0.9) {
        auto b64 = base64_decode(data, len);
        if (b64.success && !b64.output.empty()) {
            candidates.push_back({std::move(b64), 0.0});
            candidates.back().score = score_result(candidates.back().result) + 2.0;
        }
    }

    auto rxor = rolling_xor_decrypt(data, len, 0);
    candidates.push_back({std::move(rxor), 0.0});
    candidates.back().score = score_result(candidates.back().result);

    if (candidates.empty()) {
        DecryptResult r;
        r.algorithm = "auto";
        r.success = false;
        r.note = "no candidate produced useful output";
        return r;
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const Candidate& a, const Candidate& b) { return a.score > b.score; });

    auto best = std::move(candidates[0].result);
    best.algorithm = "auto(" + best.algorithm + ")";
    return best;
}

}
