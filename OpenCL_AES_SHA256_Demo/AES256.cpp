#include "AES256.h"
#include <chrono>
#include <cstring>
#include <stdexcept>

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES Inverse S-box
static const uint8_t invSbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon values for key expansion
static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

uint8_t AES256::GfMul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
            p ^= a;
        uint8_t hiBit = a & 0x80;
        a <<= 1;
        if (hiBit)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void AES256::SubBytes(uint8_t state[BLOCK_SIZE])
{
    for (int i = 0; i < BLOCK_SIZE; i++)
        state[i] = sbox[state[i]];
}

void AES256::InvSubBytes(uint8_t state[BLOCK_SIZE])
{
    for (int i = 0; i < BLOCK_SIZE; i++)
        state[i] = invSbox[state[i]];
}

void AES256::ShiftRows(uint8_t state[BLOCK_SIZE])
{
    uint8_t temp[BLOCK_SIZE];
    // Row 0 (bytes 0,4,8,12): no shift
    temp[0] = state[0];  temp[4] = state[4];  temp[8] = state[8];   temp[12] = state[12];
    // Row 1 (bytes 1,5,9,13): shift left by 1
    temp[1] = state[5];  temp[5] = state[9];  temp[9] = state[13];  temp[13] = state[1];
    // Row 2 (bytes 2,6,10,14): shift left by 2
    temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2];  temp[14] = state[6];
    // Row 3 (bytes 3,7,11,15): shift left by 3
    temp[3] = state[15]; temp[7] = state[3];  temp[11] = state[7];  temp[15] = state[11];
    memcpy(state, temp, BLOCK_SIZE);
}

void AES256::InvShiftRows(uint8_t state[BLOCK_SIZE])
{
    uint8_t temp[BLOCK_SIZE];
    // Row 0: no shift
    temp[0] = state[0];  temp[4] = state[4];  temp[8] = state[8];   temp[12] = state[12];
    // Row 1: shift right by 1 (same as left by 3)
    temp[1] = state[13]; temp[5] = state[1];  temp[9] = state[5];   temp[13] = state[9];
    // Row 2: shift right by 2
    temp[2] = state[10]; temp[6] = state[14]; temp[10] = state[2];  temp[14] = state[6];
    // Row 3: shift right by 3 (same as left by 1)
    temp[3] = state[7];  temp[7] = state[11]; temp[11] = state[15]; temp[15] = state[3];
    memcpy(state, temp, BLOCK_SIZE);
}

void AES256::MixColumns(uint8_t state[BLOCK_SIZE])
{
    for (int c = 0; c < 4; c++)
    {
        int i = c * 4;
        uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        state[i]   = GfMul(0x02, a0) ^ GfMul(0x03, a1) ^ a2 ^ a3;
        state[i+1] = a0 ^ GfMul(0x02, a1) ^ GfMul(0x03, a2) ^ a3;
        state[i+2] = a0 ^ a1 ^ GfMul(0x02, a2) ^ GfMul(0x03, a3);
        state[i+3] = GfMul(0x03, a0) ^ a1 ^ a2 ^ GfMul(0x02, a3);
    }
}

void AES256::InvMixColumns(uint8_t state[BLOCK_SIZE])
{
    for (int c = 0; c < 4; c++)
    {
        int i = c * 4;
        uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        state[i]   = GfMul(0x0e, a0) ^ GfMul(0x0b, a1) ^ GfMul(0x0d, a2) ^ GfMul(0x09, a3);
        state[i+1] = GfMul(0x09, a0) ^ GfMul(0x0e, a1) ^ GfMul(0x0b, a2) ^ GfMul(0x0d, a3);
        state[i+2] = GfMul(0x0d, a0) ^ GfMul(0x09, a1) ^ GfMul(0x0e, a2) ^ GfMul(0x0b, a3);
        state[i+3] = GfMul(0x0b, a0) ^ GfMul(0x0d, a1) ^ GfMul(0x09, a2) ^ GfMul(0x0e, a3);
    }
}

void AES256::AddRoundKey(uint8_t state[BLOCK_SIZE], const uint8_t* roundKey)
{
    for (int i = 0; i < BLOCK_SIZE; i++)
        state[i] ^= roundKey[i];
}

void AES256::KeyExpansion(const uint8_t key[KEY_SIZE], uint8_t roundKeys[EXPANDED_KEY_SIZE])
{
    uint32_t w[60]; // AES-256 produces 60 32-bit words

    // Copy key into first 8 words
    for (int i = 0; i < 8; i++)
        w[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
               ((uint32_t)key[4*i+2] << 8) | (uint32_t)key[4*i+3];

    // Expand
    for (int i = 8; i < 60; i++)
    {
        uint32_t temp = w[i - 1];
        if (i % 8 == 0)
        {
            // RotWord + SubWord + Rcon
            temp = ((uint32_t)sbox[(temp >> 16) & 0xFF] << 24) |
                   ((uint32_t)sbox[(temp >> 8) & 0xFF] << 16) |
                   ((uint32_t)sbox[temp & 0xFF] << 8) |
                   ((uint32_t)sbox[(temp >> 24) & 0xFF]);
            temp ^= ((uint32_t)Rcon[i / 8] << 24);
        }
        else if (i % 8 == 4)
        {
            // SubWord only
            temp = ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24) |
                   ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                   ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                   ((uint32_t)sbox[temp & 0xFF]);
        }
        w[i] = w[i - 8] ^ temp;
    }

    // Pack into round keys byte array
    for (int round = 0; round <= ROUNDS; round++)
    {
        for (int j = 0; j < 4; j++)
        {
            uint32_t word = w[round * 4 + j];
            roundKeys[round * 16 + j * 4 + 0] = (word >> 24) & 0xFF;
            roundKeys[round * 16 + j * 4 + 1] = (word >> 16) & 0xFF;
            roundKeys[round * 16 + j * 4 + 2] = (word >> 8) & 0xFF;
            roundKeys[round * 16 + j * 4 + 3] = word & 0xFF;
        }
    }
}

void AES256::EncryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE],
                          const uint8_t roundKeys[EXPANDED_KEY_SIZE])
{
    memcpy(out, in, BLOCK_SIZE);

    // Initial AddRoundKey
    AddRoundKey(out, roundKeys);

    // Rounds 1-13 with MixColumns
    for (int round = 1; round < ROUNDS; round++)
    {
        SubBytes(out);
        ShiftRows(out);
        MixColumns(out);
        AddRoundKey(out, roundKeys + round * BLOCK_SIZE);
    }

    // Final round (no MixColumns)
    SubBytes(out);
    ShiftRows(out);
    AddRoundKey(out, roundKeys + ROUNDS * BLOCK_SIZE);
}

void AES256::DecryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE],
                          const uint8_t roundKeys[EXPANDED_KEY_SIZE])
{
    memcpy(out, in, BLOCK_SIZE);

    // Initial AddRoundKey (with last round key)
    AddRoundKey(out, roundKeys + ROUNDS * BLOCK_SIZE);

    // Rounds 13-1 with InvMixColumns
    for (int round = ROUNDS - 1; round >= 1; round--)
    {
        InvShiftRows(out);
        InvSubBytes(out);
        AddRoundKey(out, roundKeys + round * BLOCK_SIZE);
        InvMixColumns(out);
    }

    // Final round (no InvMixColumns)
    InvShiftRows(out);
    InvSubBytes(out);
    AddRoundKey(out, roundKeys);
}

std::vector<uint8_t> AES256::PadPKCS7(const std::vector<uint8_t>& data)
{
    size_t padLen = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
    std::vector<uint8_t> padded = data;
    padded.insert(padded.end(), padLen, (uint8_t)padLen);
    return padded;
}

std::vector<uint8_t> AES256::UnpadPKCS7(const std::vector<uint8_t>& data)
{
    if (data.empty())
        return data;
    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > BLOCK_SIZE)
        return data;
    for (size_t i = data.size() - padLen; i < data.size(); i++)
    {
        if (data[i] != padLen)
            return data;
    }
    return std::vector<uint8_t>(data.begin(), data.end() - padLen);
}

std::vector<uint8_t> AES256::GenerateDemoData(const std::vector<uint8_t>& input, size_t targetSize)
{
    if (input.empty())
        return std::vector<uint8_t>(targetSize, 0x41); // fill with 'A'

    if (input.size() >= targetSize)
        return std::vector<uint8_t>(input.begin(), input.begin() + targetSize);

    std::vector<uint8_t> result;
    result.reserve(targetSize);
    while (result.size() < targetSize)
    {
        size_t remaining = targetSize - result.size();
        size_t copySize = (input.size() < remaining) ? input.size() : remaining;
        result.insert(result.end(), input.begin(), input.begin() + copySize);
    }
    return result;
}

double AES256::CpuEncrypt(const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& key,
                          std::vector<uint8_t>& ciphertext)
{
    if (key.size() < KEY_SIZE)
        throw std::runtime_error("AES key must be at least 32 bytes");

    uint8_t roundKeys[EXPANDED_KEY_SIZE];
    KeyExpansion(key.data(), roundKeys);

    std::vector<uint8_t> padded = PadPKCS7(plaintext);
    size_t numBlocks = padded.size() / BLOCK_SIZE;
    ciphertext.resize(padded.size());

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < numBlocks; i++)
    {
        EncryptBlock(padded.data() + i * BLOCK_SIZE,
                     ciphertext.data() + i * BLOCK_SIZE,
                     roundKeys);
    }

    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

double AES256::CpuDecrypt(const std::vector<uint8_t>& ciphertext,
                          const std::vector<uint8_t>& key,
                          std::vector<uint8_t>& plaintext)
{
    if (key.size() < KEY_SIZE)
        throw std::runtime_error("AES key must be at least 32 bytes");
    if (ciphertext.size() % BLOCK_SIZE != 0)
        throw std::runtime_error("Ciphertext length must be multiple of 16 bytes");

    uint8_t roundKeys[EXPANDED_KEY_SIZE];
    KeyExpansion(key.data(), roundKeys);

    size_t numBlocks = ciphertext.size() / BLOCK_SIZE;
    plaintext.resize(ciphertext.size());

    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < numBlocks; i++)
    {
        DecryptBlock(ciphertext.data() + i * BLOCK_SIZE,
                     plaintext.data() + i * BLOCK_SIZE,
                     roundKeys);
    }

    auto end = std::chrono::high_resolution_clock::now();

    plaintext = UnpadPKCS7(plaintext);
    return std::chrono::duration<double, std::milli>(end - start).count();
}

double AES256::GpuEncrypt(const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& key,
                          std::vector<uint8_t>& ciphertext,
                          OpenCLManager& opencl)
{
    if (!opencl.IsInitialized())
        throw std::runtime_error("OpenCL not initialized");
    if (key.size() < KEY_SIZE)
        throw std::runtime_error("AES key must be at least 32 bytes");

    uint8_t roundKeys[EXPANDED_KEY_SIZE];
    KeyExpansion(key.data(), roundKeys);

    std::vector<uint8_t> padded = PadPKCS7(plaintext);
    size_t numBlocks = padded.size() / BLOCK_SIZE;
    size_t dataSize = padded.size();
    ciphertext.resize(dataSize);

    cl_kernel kernel = opencl.GetKernel("aes256_encrypt");
    if (!kernel)
    {
        if (!opencl.CreateKernelFromFile("aes256_encrypt", "AES256Kernel.cl"))
            throw std::runtime_error("Failed to create AES256 encrypt kernel");
        kernel = opencl.GetKernel("aes256_encrypt");
    }

    auto start = std::chrono::high_resolution_clock::now();

    // Use persistent buffer pool — skip alloc/free on repeated calls
    cl_mem inputBuf  = opencl.GetPersistDataBufRW(dataSize);
    cl_mem outputBuf = opencl.GetPersistOutBuf(dataSize);
    cl_mem keyBuf    = opencl.GetPersistKeyBuf();
    if (!inputBuf || !outputBuf || !keyBuf)
        throw std::runtime_error("Failed to obtain persistent GPU buffers");

    // Upload data and round keys
    if (!opencl.CpuToGpu(inputBuf, padded.data(), dataSize))
        throw std::runtime_error("Failed to upload AES input to GPU");
    if (!opencl.CpuToGpu(keyBuf, roundKeys, EXPANDED_KEY_SIZE))
        throw std::runtime_error("Failed to upload AES round keys to GPU");

    clSetKernelArg(kernel, 0, sizeof(cl_mem), &inputBuf);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &outputBuf);
    clSetKernelArg(kernel, 2, sizeof(cl_mem), &keyBuf);
    clSetKernelArg(kernel, 3, sizeof(cl_uint), &numBlocks);

    size_t globalSize = numBlocks;
    size_t localSize = 256;
    if (globalSize % localSize != 0)
        globalSize = ((globalSize / localSize) + 1) * localSize;

    cl_int err = clEnqueueNDRangeKernel(opencl.GetQueue(), kernel, 1, nullptr,
                                        &globalSize, &localSize, 0, nullptr, nullptr);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to enqueue AES encrypt kernel");

    if (!opencl.GpuToCpu(outputBuf, ciphertext.data(), dataSize))
        throw std::runtime_error("Failed to read AES encrypt result from GPU");

    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

double AES256::GpuDecrypt(const std::vector<uint8_t>& ciphertext,
                          const std::vector<uint8_t>& key,
                          std::vector<uint8_t>& plaintext,
                          OpenCLManager& opencl)
{
    if (!opencl.IsInitialized())
        throw std::runtime_error("OpenCL not initialized");
    if (key.size() < KEY_SIZE)
        throw std::runtime_error("AES key must be at least 32 bytes");
    if (ciphertext.size() % BLOCK_SIZE != 0)
        throw std::runtime_error("Ciphertext length must be multiple of 16 bytes");

    uint8_t roundKeys[EXPANDED_KEY_SIZE];
    KeyExpansion(key.data(), roundKeys);

    size_t numBlocks = ciphertext.size() / BLOCK_SIZE;
    size_t dataSize = ciphertext.size();
    plaintext.resize(dataSize);

    cl_kernel kernel = opencl.GetKernel("aes256_decrypt");
    if (!kernel)
    {
        if (!opencl.CreateKernelFromFile("aes256_decrypt", "AES256Kernel.cl"))
            throw std::runtime_error("Failed to create AES256 decrypt kernel");
        kernel = opencl.GetKernel("aes256_decrypt");
    }

    auto start = std::chrono::high_resolution_clock::now();

    // Use persistent buffer pool — skip alloc/free on repeated calls
    cl_mem inputBuf  = opencl.GetPersistDataBufRW(dataSize);
    cl_mem outputBuf = opencl.GetPersistOutBuf(dataSize);
    cl_mem keyBuf    = opencl.GetPersistKeyBuf();
    if (!inputBuf || !outputBuf || !keyBuf)
        throw std::runtime_error("Failed to obtain persistent GPU buffers");

    if (!opencl.CpuToGpu(inputBuf, ciphertext.data(), dataSize))
        throw std::runtime_error("Failed to upload AES ciphertext to GPU");
    if (!opencl.CpuToGpu(keyBuf, roundKeys, EXPANDED_KEY_SIZE))
        throw std::runtime_error("Failed to upload AES round keys to GPU");

    clSetKernelArg(kernel, 0, sizeof(cl_mem), &inputBuf);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &outputBuf);
    clSetKernelArg(kernel, 2, sizeof(cl_mem), &keyBuf);
    clSetKernelArg(kernel, 3, sizeof(cl_uint), &numBlocks);

    size_t globalSize = numBlocks;
    size_t localSize = 256;
    if (globalSize % localSize != 0)
        globalSize = ((globalSize / localSize) + 1) * localSize;

    cl_int err = clEnqueueNDRangeKernel(opencl.GetQueue(), kernel, 1, nullptr,
                                        &globalSize, &localSize, 0, nullptr, nullptr);
    if (err != CL_SUCCESS)
        throw std::runtime_error("Failed to enqueue AES decrypt kernel");

    if (!opencl.GpuToCpu(outputBuf, plaintext.data(), dataSize))
        throw std::runtime_error("Failed to read AES decrypt result from GPU");

    auto end = std::chrono::high_resolution_clock::now();

    plaintext = UnpadPKCS7(plaintext);
    return std::chrono::duration<double, std::milli>(end - start).count();
}
