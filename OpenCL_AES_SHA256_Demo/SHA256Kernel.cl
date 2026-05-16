// SHA-256 Hash OpenCL Kernel
// Each work-item computes an independent SHA-256 hash.
// Input: base_input + work-item index appended

// SHA-256 constants K[0..63]
__constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values H0[0..7]
__constant uint H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Right rotation helper
inline uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 logical functions
inline uint Ch(uint e, uint f, uint g) {
    return (e & f) ^ (~e & g);
}

inline uint Maj(uint a, uint b, uint c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

inline uint SIG0(uint x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint SIG1(uint x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint sig0(uint x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint sig1(uint x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA-256 compression function on a 64-byte block (private memory pointer)
static void sha256_transform(uint* state, const uchar* block) {
    uint w[64];

    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint)block[i * 4] << 24) |
               ((uint)block[i * 4 + 1] << 16) |
               ((uint)block[i * 4 + 2] << 8) |
               ((uint)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16];
    }

    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];

    // 64 rounds
    for (int i = 0; i < 64; i++) {
        uint t1 = h + SIG1(e) + Ch(e, f, g) + K[i] + w[i];
        uint t2 = SIG0(a) + Maj(a, b, c);
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

// Convert uint to decimal string (in-place, returns length)
static int uintToStr(uint num, uchar* buf) {
    if (num == 0) {
        buf[0] = '0';
        return 1;
    }
    int len = 0;
    uchar temp[12];
    uint n = num;
    while (n > 0) {
        temp[len++] = '0' + (n % 10);
        n /= 10;
    }
    // Reverse into buf
    for (int i = 0; i < len; i++) {
        buf[i] = temp[len - 1 - i];
    }
    return len;
}

// ============================================================================
// SHA-256 Hash Kernel
// Each work-item hashes: base_input (from global memory) + work-item index
// baseInput: base input string bytes
// baseLen: length of base input in bytes
// output: hash results (32 bytes per hash, concatenated)
// count: total number of hashes to compute
// ============================================================================
__kernel void sha256_hash(
    __global const uchar* baseInput,
    uint baseLen,
    __global uchar* output,
    uint count)
{
    uint idx = get_global_id(0);
    if (idx >= count) return;

    // Build the message: baseInput_bytes + index_as_decimal_string
    // Max message size: baseLen + 12 (max 10 digits for uint) + padding room
    uchar msg[128]; // supports up to (128 - 9) = 119 byte messages (incl. padding)

    // Copy base input
    uint msgLen = 0;
    for (uint i = 0; i < baseLen && i < 55; i++) {
        msg[msgLen++] = baseInput[i];
    }

    // Append index as decimal string
    uchar idxStr[12];
    int idxLen = uintToStr(idx, idxStr);
    for (int i = 0; i < idxLen && msgLen < 55; i++) {
        msg[msgLen++] = idxStr[i];
    }

    // SHA-256 padding: append 0x80
    uint padStart = msgLen;
    msg[msgLen++] = 0x80;

    // Pad with zeros until length % 64 == 56
    while (msgLen % 64 != 56) {
        msg[msgLen++] = 0;
    }

    // Append 64-bit big-endian length in bits
    ulong bitLen = (ulong)padStart * 8;
    for (int i = 7; i >= 0; i--) {
        msg[msgLen++] = (bitLen >> (i * 8)) & 0xFF;
    }

    // Initialize hash state
    uint state[8];
    for (int i = 0; i < 8; i++) {
        state[i] = H0[i];
    }

    // Process each 64-byte block
    uint numBlocks = msgLen / 64;
    for (uint i = 0; i < numBlocks; i++) {
        sha256_transform(state, msg + i * 64);
    }

    // Write result (32 bytes, big-endian)
    uint outOffset = idx * 32;
    for (int i = 0; i < 8; i++) {
        output[outOffset + i * 4 + 0] = (state[i] >> 24) & 0xFF;
        output[outOffset + i * 4 + 1] = (state[i] >> 16) & 0xFF;
        output[outOffset + i * 4 + 2] = (state[i] >> 8) & 0xFF;
        output[outOffset + i * 4 + 3] = state[i] & 0xFF;
    }
}
