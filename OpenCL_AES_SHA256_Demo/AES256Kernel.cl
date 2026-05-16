// AES-256 Encryption/Decryption OpenCL Kernel (ECB Mode)
// S-box lookup table
__constant uchar sbox[256] = {
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
__constant uchar invSbox[256] = {
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

// Galois field multiplication by 2
uchar xtime(uchar x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

// Galois field multiplication
uchar gmul(uchar a, uchar b) {
    uchar p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            p ^= a;
        uchar hi = a & 0x80;
        a <<= 1;
        if (hi)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// MixColumns for a 4-byte column (stored as uint)
uint mixColumn(uint col) {
    uchar a0 = (col >> 24) & 0xFF;
    uchar a1 = (col >> 16) & 0xFF;
    uchar a2 = (col >> 8) & 0xFF;
    uchar a3 = col & 0xFF;

    return ((uint)(gmul(2, a0) ^ gmul(3, a1) ^ a2 ^ a3) << 24) |
           ((uint)(a0 ^ gmul(2, a1) ^ gmul(3, a2) ^ a3) << 16) |
           ((uint)(a0 ^ a1 ^ gmul(2, a2) ^ gmul(3, a3)) << 8) |
           ((uint)(gmul(3, a0) ^ a1 ^ a2 ^ gmul(2, a3)));
}

// InvMixColumns for a 4-byte column
uint invMixColumn(uint col) {
    uchar a0 = (col >> 24) & 0xFF;
    uchar a1 = (col >> 16) & 0xFF;
    uchar a2 = (col >> 8) & 0xFF;
    uchar a3 = col & 0xFF;

    return ((uint)(gmul(0x0e, a0) ^ gmul(0x0b, a1) ^ gmul(0x0d, a2) ^ gmul(0x09, a3)) << 24) |
           ((uint)(gmul(0x09, a0) ^ gmul(0x0e, a1) ^ gmul(0x0b, a2) ^ gmul(0x0d, a3)) << 16) |
           ((uint)(gmul(0x0d, a0) ^ gmul(0x09, a1) ^ gmul(0x0e, a2) ^ gmul(0x0b, a3)) << 8) |
           ((uint)(gmul(0x0b, a0) ^ gmul(0x0d, a1) ^ gmul(0x09, a2) ^ gmul(0x0e, a3)));
}

// Load round key as 4 uint values (column-major: key[0..3]=col0, key[4..7]=col1, etc.)
void loadRoundKey(__constant uchar* rk, int offset, uint* k) {
    for (int i = 0; i < 4; i++) {
        k[i] = ((uint)rk[offset + i * 4 + 0] << 24) |
               ((uint)rk[offset + i * 4 + 1] << 16) |
               ((uint)rk[offset + i * 4 + 2] << 8) |
               ((uint)rk[offset + i * 4 + 3]);
    }
}

// Store state to output buffer
void storeBlock(__global uchar* output, uint idx, uint* state) {
    for (int i = 0; i < 4; i++) {
        output[idx + i * 4 + 0] = (state[i] >> 24) & 0xFF;
        output[idx + i * 4 + 1] = (state[i] >> 16) & 0xFF;
        output[idx + i * 4 + 2] = (state[i] >> 8) & 0xFF;
        output[idx + i * 4 + 3] = state[i] & 0xFF;
    }
}

// Load block from input buffer
void loadBlock(__global const uchar* input, uint idx, uint* state) {
    for (int i = 0; i < 4; i++) {
        state[i] = ((uint)input[idx + i * 4 + 0] << 24) |
                   ((uint)input[idx + i * 4 + 1] << 16) |
                   ((uint)input[idx + i * 4 + 2] << 8) |
                   ((uint)input[idx + i * 4 + 3]);
    }
}

// ============================================================================
// AES-256 Encryption Kernel (ECB mode)
// Each work-item processes one 16-byte block independently.
// input:  plaintext blocks (numBlocks * 16 bytes)
// output: ciphertext blocks (numBlocks * 16 bytes)
// roundKeys: expanded round keys (15 * 16 = 240 bytes)
// numBlocks: total number of 16-byte blocks
// ============================================================================
__kernel void aes256_encrypt(
    __global const uchar* input,
    __global uchar* output,
    __constant uchar* roundKeys,
    uint numBlocks)
{
    uint idx = get_global_id(0);
    if (idx >= numBlocks) return;

    uint state[4];
    loadBlock(input, idx * 16, state);

    // Initial AddRoundKey (round key 0)
    uint rk[4];
    loadRoundKey(roundKeys, 0, rk);
    for (int i = 0; i < 4; i++)
        state[i] ^= rk[i];

    // Rounds 1 to 13 (with MixColumns)
    for (int round = 1; round < 14; round++) {
        // SubBytes + ShiftRows combined
        uint temp[4];
        temp[0] = ((uint)sbox[(state[0] >> 24) & 0xFF] << 24) |
                  ((uint)sbox[(state[1] >> 16) & 0xFF] << 16) |
                  ((uint)sbox[(state[2] >> 8) & 0xFF] << 8) |
                  ((uint)sbox[state[3] & 0xFF]);

        temp[1] = ((uint)sbox[(state[1] >> 24) & 0xFF] << 24) |
                  ((uint)sbox[(state[2] >> 16) & 0xFF] << 16) |
                  ((uint)sbox[(state[3] >> 8) & 0xFF] << 8) |
                  ((uint)sbox[state[0] & 0xFF]);

        temp[2] = ((uint)sbox[(state[2] >> 24) & 0xFF] << 24) |
                  ((uint)sbox[(state[3] >> 16) & 0xFF] << 16) |
                  ((uint)sbox[(state[0] >> 8) & 0xFF] << 8) |
                  ((uint)sbox[state[1] & 0xFF]);

        temp[3] = ((uint)sbox[(state[3] >> 24) & 0xFF] << 24) |
                  ((uint)sbox[(state[0] >> 16) & 0xFF] << 16) |
                  ((uint)sbox[(state[1] >> 8) & 0xFF] << 8) |
                  ((uint)sbox[state[2] & 0xFF]);

        // MixColumns
        for (int i = 0; i < 4; i++)
            state[i] = mixColumn(temp[i]);

        // AddRoundKey
        loadRoundKey(roundKeys, round * 16, rk);
        for (int i = 0; i < 4; i++)
            state[i] ^= rk[i];
    }

    // Final round (round 14): no MixColumns
    uint finalState[4];
    finalState[0] = ((uint)sbox[(state[0] >> 24) & 0xFF] << 24) |
                    ((uint)sbox[(state[1] >> 16) & 0xFF] << 16) |
                    ((uint)sbox[(state[2] >> 8) & 0xFF] << 8) |
                    ((uint)sbox[state[3] & 0xFF]);

    finalState[1] = ((uint)sbox[(state[1] >> 24) & 0xFF] << 24) |
                    ((uint)sbox[(state[2] >> 16) & 0xFF] << 16) |
                    ((uint)sbox[(state[3] >> 8) & 0xFF] << 8) |
                    ((uint)sbox[state[0] & 0xFF]);

    finalState[2] = ((uint)sbox[(state[2] >> 24) & 0xFF] << 24) |
                    ((uint)sbox[(state[3] >> 16) & 0xFF] << 16) |
                    ((uint)sbox[(state[0] >> 8) & 0xFF] << 8) |
                    ((uint)sbox[state[1] & 0xFF]);

    finalState[3] = ((uint)sbox[(state[3] >> 24) & 0xFF] << 24) |
                    ((uint)sbox[(state[0] >> 16) & 0xFF] << 16) |
                    ((uint)sbox[(state[1] >> 8) & 0xFF] << 8) |
                    ((uint)sbox[state[2] & 0xFF]);

    // AddRoundKey (final round)
    loadRoundKey(roundKeys, 14 * 16, rk);
    for (int i = 0; i < 4; i++)
        finalState[i] ^= rk[i];

    storeBlock(output, idx * 16, finalState);
}

// ============================================================================
// AES-256 Decryption Kernel (ECB mode)
// ============================================================================
__kernel void aes256_decrypt(
    __global const uchar* input,
    __global uchar* output,
    __constant uchar* roundKeys,
    uint numBlocks)
{
    uint idx = get_global_id(0);
    if (idx >= numBlocks) return;

    uint state[4];
    loadBlock(input, idx * 16, state);

    // Initial AddRoundKey with last round key (round 14)
    uint rk[4];
    loadRoundKey(roundKeys, 14 * 16, rk);
    for (int i = 0; i < 4; i++)
        state[i] ^= rk[i];

    // Rounds 13 down to 1 (with InvMixColumns)
    for (int round = 13; round >= 1; round--) {
        // InvShiftRows + InvSubBytes combined
        uint temp[4];
        temp[0] = ((uint)invSbox[(state[0] >> 24) & 0xFF] << 24) |
                  ((uint)invSbox[(state[3] >> 16) & 0xFF] << 16) |
                  ((uint)invSbox[(state[2] >> 8) & 0xFF] << 8) |
                  ((uint)invSbox[state[1] & 0xFF]);

        temp[1] = ((uint)invSbox[(state[1] >> 24) & 0xFF] << 24) |
                  ((uint)invSbox[(state[0] >> 16) & 0xFF] << 16) |
                  ((uint)invSbox[(state[3] >> 8) & 0xFF] << 8) |
                  ((uint)invSbox[state[2] & 0xFF]);

        temp[2] = ((uint)invSbox[(state[2] >> 24) & 0xFF] << 24) |
                  ((uint)invSbox[(state[1] >> 16) & 0xFF] << 16) |
                  ((uint)invSbox[(state[0] >> 8) & 0xFF] << 8) |
                  ((uint)invSbox[state[3] & 0xFF]);

        temp[3] = ((uint)invSbox[(state[3] >> 24) & 0xFF] << 24) |
                  ((uint)invSbox[(state[2] >> 16) & 0xFF] << 16) |
                  ((uint)invSbox[(state[1] >> 8) & 0xFF] << 8) |
                  ((uint)invSbox[state[0] & 0xFF]);

        // AddRoundKey
        loadRoundKey(roundKeys, round * 16, rk);
        for (int i = 0; i < 4; i++)
            temp[i] ^= rk[i];

        // InvMixColumns
        for (int i = 0; i < 4; i++)
            state[i] = invMixColumn(temp[i]);
    }

    // Final round (round 0): InvShiftRows + InvSubBytes + AddRoundKey (no InvMixColumns)
    uint finalState[4];
    finalState[0] = ((uint)invSbox[(state[0] >> 24) & 0xFF] << 24) |
                    ((uint)invSbox[(state[3] >> 16) & 0xFF] << 16) |
                    ((uint)invSbox[(state[2] >> 8) & 0xFF] << 8) |
                    ((uint)invSbox[state[1] & 0xFF]);

    finalState[1] = ((uint)invSbox[(state[1] >> 24) & 0xFF] << 24) |
                    ((uint)invSbox[(state[0] >> 16) & 0xFF] << 16) |
                    ((uint)invSbox[(state[3] >> 8) & 0xFF] << 8) |
                    ((uint)invSbox[state[2] & 0xFF]);

    finalState[2] = ((uint)invSbox[(state[2] >> 24) & 0xFF] << 24) |
                    ((uint)invSbox[(state[1] >> 16) & 0xFF] << 16) |
                    ((uint)invSbox[(state[0] >> 8) & 0xFF] << 8) |
                    ((uint)invSbox[state[3] & 0xFF]);

    finalState[3] = ((uint)invSbox[(state[3] >> 24) & 0xFF] << 24) |
                    ((uint)invSbox[(state[2] >> 16) & 0xFF] << 16) |
                    ((uint)invSbox[(state[1] >> 8) & 0xFF] << 8) |
                    ((uint)invSbox[state[0] & 0xFF]);

    // AddRoundKey with round key 0
    loadRoundKey(roundKeys, 0, rk);
    for (int i = 0; i < 4; i++)
        finalState[i] ^= rk[i];

    storeBlock(output, idx * 16, finalState);
}
