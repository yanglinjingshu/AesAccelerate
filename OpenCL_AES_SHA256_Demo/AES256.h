#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "OpenCLManager.h"

class AES256
{
public:
    // GPU-accelerated AES-256 ECB encryption. Returns timing in milliseconds.
    static double GpuEncrypt(const std::vector<uint8_t>& plaintext,
                             const std::vector<uint8_t>& key,
                             std::vector<uint8_t>& ciphertext,
                             OpenCLManager& opencl);

    // GPU-accelerated AES-256 ECB decryption. Returns timing in milliseconds.
    static double GpuDecrypt(const std::vector<uint8_t>& ciphertext,
                             const std::vector<uint8_t>& key,
                             std::vector<uint8_t>& plaintext,
                             OpenCLManager& opencl);

    // CPU AES-256 ECB encryption for comparison. Returns timing in milliseconds.
    static double CpuEncrypt(const std::vector<uint8_t>& plaintext,
                             const std::vector<uint8_t>& key,
                             std::vector<uint8_t>& ciphertext);

    // CPU AES-256 ECB decryption for comparison. Returns timing in milliseconds.
    static double CpuDecrypt(const std::vector<uint8_t>& ciphertext,
                             const std::vector<uint8_t>& key,
                             std::vector<uint8_t>& plaintext);

    // Generate demo data by repeating input to reach targetSize bytes
    static std::vector<uint8_t> GenerateDemoData(const std::vector<uint8_t>& input, size_t targetSize);

private:
    static const int BLOCK_SIZE = 16;
    static const int KEY_SIZE = 32;
    static const int ROUNDS = 14;
    static const int EXPANDED_KEY_SIZE = 240; // 15 round keys * 16 bytes

    // Expand 256-bit key to 15 round keys (240 bytes)
    static void KeyExpansion(const uint8_t key[KEY_SIZE], uint8_t roundKeys[EXPANDED_KEY_SIZE]);

    // Encrypt a single 16-byte block
    static void EncryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE],
                             const uint8_t roundKeys[EXPANDED_KEY_SIZE]);

    // Decrypt a single 16-byte block
    static void DecryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE],
                             const uint8_t roundKeys[EXPANDED_KEY_SIZE]);

    // PKCS#7 padding
    static std::vector<uint8_t> PadPKCS7(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> UnpadPKCS7(const std::vector<uint8_t>& data);

    static void SubBytes(uint8_t state[BLOCK_SIZE]);
    static void InvSubBytes(uint8_t state[BLOCK_SIZE]);
    static void ShiftRows(uint8_t state[BLOCK_SIZE]);
    static void InvShiftRows(uint8_t state[BLOCK_SIZE]);
    static void MixColumns(uint8_t state[BLOCK_SIZE]);
    static void InvMixColumns(uint8_t state[BLOCK_SIZE]);
    static void AddRoundKey(uint8_t state[BLOCK_SIZE], const uint8_t* roundKey);
    static uint8_t GfMul(uint8_t a, uint8_t b);
};
