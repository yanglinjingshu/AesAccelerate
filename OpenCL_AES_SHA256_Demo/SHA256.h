#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "OpenCLManager.h"

class SHA256
{
public:
    // GPU-accelerated SHA256 hash. Returns timing in milliseconds for processing numHashes independent hashes.
    static double GpuHash(const std::string& input,
                          std::string& hashHex,
                          OpenCLManager& opencl,
                          unsigned int numHashes = 262144);

    // CPU SHA256 hash for comparison. Returns timing in milliseconds for processing numHashes independent hashes.
    static double CpuHash(const std::string& input,
                          std::string& hashHex,
                          unsigned int numHashes = 262144);

    // Simple single hash on CPU (returns hex string)
    static std::string Hash(const std::string& input);

private:
    static const int HASH_SIZE = 32; // 256 bits = 32 bytes
    static const int BLOCK_SIZE = 64; // 512 bits = 64 bytes
    static const int DIGEST_WORDS = 8;

    // Hash a single message and output 32-byte digest
    static void HashMessage(const uint8_t* message, size_t messageLen, uint8_t digest[HASH_SIZE]);

    // SHA256 compression function on a 64-byte block
    static void Transform(uint32_t state[DIGEST_WORDS], const uint8_t block[BLOCK_SIZE]);

    static uint32_t RotateRight(uint32_t x, uint32_t n);
    static uint32_t Choose(uint32_t e, uint32_t f, uint32_t g);
    static uint32_t Majority(uint32_t a, uint32_t b, uint32_t c);
    static uint32_t Sigma0(uint32_t x);
    static uint32_t Sigma1(uint32_t x);
    static uint32_t Sigma0Small(uint32_t x);
    static uint32_t Sigma1Small(uint32_t x);
};
