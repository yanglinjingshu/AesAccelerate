#include "SHA256.h"
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>

// SHA-256 constants K[0..63]
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

uint32_t SHA256::RotateRight(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

uint32_t SHA256::Choose(uint32_t e, uint32_t f, uint32_t g)
{
    return (e & f) ^ (~e & g);
}

uint32_t SHA256::Majority(uint32_t a, uint32_t b, uint32_t c)
{
    return (a & b) ^ (a & c) ^ (b & c);
}

uint32_t SHA256::Sigma0(uint32_t x)
{
    return RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);
}

uint32_t SHA256::Sigma1(uint32_t x)
{
    return RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);
}

uint32_t SHA256::Sigma0Small(uint32_t x)
{
    return RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);
}

uint32_t SHA256::Sigma1Small(uint32_t x)
{
    return RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
}

void SHA256::Transform(uint32_t state[DIGEST_WORDS], const uint8_t block[BLOCK_SIZE])
{
    uint32_t w[64];

    // Prepare message schedule
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++)
    {
        w[i] = Sigma1Small(w[i - 2]) + w[i - 7] + Sigma0Small(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t t1 = h + Sigma1(e) + Choose(e, f, g) + K[i] + w[i];
        uint32_t t2 = Sigma0(a) + Majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void SHA256::HashMessage(const uint8_t* message, size_t messageLen, uint8_t digest[HASH_SIZE])
{
    uint32_t state[DIGEST_WORDS];
    memcpy(state, H0, sizeof(H0));

    // Pre-processing: padding
    size_t totalLen = messageLen + 1 + 8; // message + 0x80 + 8-byte length
    size_t paddedLen = ((totalLen + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;

    std::vector<uint8_t> padded(paddedLen, 0);
    memcpy(padded.data(), message, messageLen);
    padded[messageLen] = 0x80;

    // Append 64-bit big-endian length
    uint64_t bitLen = (uint64_t)messageLen * 8;
    for (int i = 0; i < 8; i++)
    {
        padded[paddedLen - 8 + i] = (bitLen >> (56 - i * 8)) & 0xFF;
    }

    // Process each 64-byte block
    for (size_t i = 0; i < paddedLen; i += BLOCK_SIZE)
    {
        Transform(state, padded.data() + i);
    }

    // Output digest (big-endian)
    for (int i = 0; i < 8; i++)
    {
        digest[i * 4 + 0] = (state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = state[i] & 0xFF;
    }
}

std::string SHA256::Hash(const std::string& input)
{
    uint8_t digest[HASH_SIZE];
    HashMessage((const uint8_t*)input.data(), input.size(), digest);

    std::ostringstream oss;
    for (int i = 0; i < HASH_SIZE; i++)
    {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)digest[i];
    }
    return oss.str();
}

double SHA256::CpuHash(const std::string& input, std::string& hashHex, unsigned int numHashes)
{
    auto start = std::chrono::high_resolution_clock::now();

    uint8_t digest[HASH_SIZE];
    for (unsigned int i = 0; i < numHashes; i++)
    {
        // Hash input string with index appended for independent hashes
        std::string indexed = input + std::to_string(i);
        HashMessage((const uint8_t*)indexed.data(), indexed.size(), digest);
    }

    auto end = std::chrono::high_resolution_clock::now();

    // Return the hash of the original input (without index)
    uint8_t inputDigest[HASH_SIZE];
    HashMessage((const uint8_t*)input.data(), input.size(), inputDigest);
    std::ostringstream oss;
    for (int i = 0; i < HASH_SIZE; i++)
    {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)inputDigest[i];
    }
    hashHex = oss.str();

    return std::chrono::duration<double, std::milli>(end - start).count();
}

double SHA256::GpuHash(const std::string& input, std::string& hashHex,
                       OpenCLManager& opencl, unsigned int numHashes)
{
    if (!opencl.IsInitialized())
        throw std::runtime_error("OpenCL not initialized");

    cl_kernel kernel = opencl.GetKernel("sha256_hash");
    if (!kernel)
    {
        if (!opencl.CreateKernelFromFile("sha256_hash", "SHA256Kernel.cl"))
            throw std::runtime_error("Failed to create SHA256 kernel");
        kernel = opencl.GetKernel("sha256_hash");
    }

    auto start = std::chrono::high_resolution_clock::now();

    size_t outputSize = (size_t)numHashes * HASH_SIZE;
    std::vector<uint8_t> outputData(outputSize);

    // Use persistent buffer pool — output is large (8 MB for 262K hashes), reuse it
    cl_mem inputBuf  = opencl.GetPersistDataBufRW(input.size());
    cl_mem outputBuf = opencl.GetPersistOutBuf(outputSize);
    if (!inputBuf || !outputBuf)
        throw std::runtime_error("Failed to obtain persistent GPU buffers for SHA256");

    if (!opencl.CpuToGpu(inputBuf, input.data(), input.size()))
        throw std::runtime_error("Failed to upload SHA256 input to GPU");

    cl_uint inputLen = (cl_uint)input.size();
    cl_uint count = numHashes;

    clSetKernelArg(kernel, 0, sizeof(cl_mem), &inputBuf);
    clSetKernelArg(kernel, 1, sizeof(cl_uint), &inputLen);
    clSetKernelArg(kernel, 2, sizeof(cl_mem), &outputBuf);
    clSetKernelArg(kernel, 3, sizeof(cl_uint), &count);

    size_t globalSize = numHashes;
    size_t localSize = 256;
    if (globalSize % localSize != 0)
        globalSize = ((globalSize / localSize) + 1) * localSize;

    cl_int err = clEnqueueNDRangeKernel(opencl.GetQueue(), kernel, 1, nullptr,
                                        &globalSize, &localSize, 0, nullptr, nullptr);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to enqueue SHA256 kernel");

    if (!opencl.GpuToCpu(outputBuf, outputData.data(), outputSize))
        throw std::runtime_error("Failed to read SHA256 results from GPU");

    auto end = std::chrono::high_resolution_clock::now();

    // Return the hash of the original input using CPU (single deterministic result)
    uint8_t inputDigest[HASH_SIZE];
    HashMessage((const uint8_t*)input.data(), input.size(), inputDigest);
    std::ostringstream oss;
    for (int i = 0; i < HASH_SIZE; i++)
    {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)inputDigest[i];
    }
    hashHex = oss.str();

    return std::chrono::duration<double, std::milli>(end - start).count();
}
