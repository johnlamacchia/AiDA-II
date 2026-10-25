#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace aida {

struct DecryptResult {
    std::vector<uint8_t> output;
    std::string          algorithm;
    std::string          note;
    bool                 success = false;
    double               entropy_before = 0.0;
    double               entropy_after  = 0.0;
};

// XOR with single-byte key
DecryptResult xor_decrypt(const uint8_t* data, size_t len, uint8_t key);

// XOR with multi-byte key
DecryptResult xor_decrypt(const uint8_t* data, size_t len, const uint8_t* key, size_t key_len);

// XOR key bruteforce: try all single-byte keys, return the one that produces lowest entropy / most printable ASCII
DecryptResult xor_bruteforce(const uint8_t* data, size_t len);

// RC4 decrypt/encrypt (symmetric)
DecryptResult rc4_decrypt(const uint8_t* data, size_t len, const uint8_t* key, size_t key_len);

// ROT-N for ASCII data (default ROT13)
DecryptResult rot_decrypt(const uint8_t* data, size_t len, int n = 13);

// Base64 decode
DecryptResult base64_decode(const uint8_t* data, size_t len);

// Simple substitution: reverse bytes
DecryptResult reverse_bytes(const uint8_t* data, size_t len);

// NOT (bitwise complement)
DecryptResult not_decrypt(const uint8_t* data, size_t len);

// ADD/SUB constant byte
DecryptResult add_decrypt(const uint8_t* data, size_t len, uint8_t key);
DecryptResult sub_decrypt(const uint8_t* data, size_t len, uint8_t key);

// Rolling XOR: each byte XORed with the previous ciphertext byte
DecryptResult rolling_xor_decrypt(const uint8_t* data, size_t len, uint8_t seed);

// Auto-detect: try common algorithms and return the best result
DecryptResult auto_decrypt(const uint8_t* data, size_t len);

}
