// Vesper -- self-contained crypto used by the offset table container.
//
// Implements exactly what the table format needs and nothing more:
//   * SHA-256
//   * HMAC-SHA256
//   * AES-256 (FIPS-197) with CBC mode decryption
//
// No external dependency, no OpenSSL, no BCrypt. This code must be safe to run
// inside a game process, so it allocates nothing on the heap and never throws.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace vesper::crypto {

// ---------------------------------------------------------------- SHA-256 --

struct Sha256 {
    std::uint32_t state[8];
    std::uint64_t bitlen;
    unsigned char buffer[64];
    std::size_t buflen;

    void init() {
        static constexpr std::uint32_t k[8] = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
        };
        for (int i = 0; i < 8; ++i) state[i] = k[i];
        bitlen = 0;
        buflen = 0;
    }

    static std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void transform(const unsigned char* block) {
        static constexpr std::uint32_t K[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
            0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
            0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
            0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
            0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
            0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
        };

        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                   (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<std::uint32_t>(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i) {
            const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
            const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void update(const void* data, std::size_t len) {
        const auto* p = static_cast<const unsigned char*>(data);
        bitlen += static_cast<std::uint64_t>(len) * 8;
        while (len > 0) {
            const std::size_t take = (len < 64 - buflen) ? len : 64 - buflen;
            std::memcpy(buffer + buflen, p, take);
            buflen += take;
            p += take;
            len -= take;
            if (buflen == 64) {
                transform(buffer);
                buflen = 0;
            }
        }
    }

    void final(unsigned char out[32]) {
        const std::uint64_t bits = bitlen;
        unsigned char pad = 0x80;
        update(&pad, 1);
        const unsigned char zero = 0;
        while (buflen != 56) update(&zero, 1);
        unsigned char lenBytes[8];
        for (int i = 0; i < 8; ++i) lenBytes[i] = static_cast<unsigned char>(bits >> (56 - i * 8));
        update(lenBytes, 8);
        for (int i = 0; i < 8; ++i) {
            out[i * 4] = static_cast<unsigned char>(state[i] >> 24);
            out[i * 4 + 1] = static_cast<unsigned char>(state[i] >> 16);
            out[i * 4 + 2] = static_cast<unsigned char>(state[i] >> 8);
            out[i * 4 + 3] = static_cast<unsigned char>(state[i]);
        }
    }
};

inline std::array<unsigned char, 32> sha256(const void* data, std::size_t len) {
    Sha256 h;
    h.init();
    h.update(data, len);
    std::array<unsigned char, 32> out{};
    h.final(out.data());
    return out;
}

inline std::array<unsigned char, 32> sha256_concat(const void* a, std::size_t alen,
                                                   const void* b, std::size_t blen,
                                                   const void* c = nullptr, std::size_t clen = 0) {
    Sha256 h;
    h.init();
    h.update(a, alen);
    h.update(b, blen);
    if (c) h.update(c, clen);
    std::array<unsigned char, 32> out{};
    h.final(out.data());
    return out;
}

// --------------------------------------------------------------- HMAC-256 --

inline std::array<unsigned char, 32> hmac_sha256(const void* key, std::size_t keyLen,
                                                 const void* msg, std::size_t msgLen) {
    unsigned char k[64];
    std::memset(k, 0, sizeof(k));
    if (keyLen > 64) {
        const auto digest = sha256(key, keyLen);
        std::memcpy(k, digest.data(), 32);
    } else {
        std::memcpy(k, key, keyLen);
    }

    unsigned char ipad[64];
    unsigned char opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<unsigned char>(k[i] ^ 0x36);
        opad[i] = static_cast<unsigned char>(k[i] ^ 0x5c);
    }

    Sha256 inner;
    inner.init();
    inner.update(ipad, 64);
    inner.update(msg, msgLen);
    unsigned char innerDigest[32];
    inner.final(innerDigest);

    Sha256 outer;
    outer.init();
    outer.update(opad, 64);
    outer.update(innerDigest, 32);
    std::array<unsigned char, 32> out{};
    outer.final(out.data());
    return out;
}

inline bool constant_time_equal(const void* a, const void* b, std::size_t len) {
    const auto* x = static_cast<const unsigned char*>(a);
    const auto* y = static_cast<const unsigned char*>(b);
    unsigned char diff = 0;
    for (std::size_t i = 0; i < len; ++i) diff = static_cast<unsigned char>(diff | (x[i] ^ y[i]));
    return diff == 0;
}

// -------------------------------------------------------------------- AES --

class Aes256 {
public:
    // Tables are built once from the algebraic definition of the S-box, which
    // keeps the source free of 512 bytes of magic constants.
    static const std::array<unsigned char, 256>& sbox() {
        static const std::array<unsigned char, 256> table = build_sbox(false);
        return table;
    }
    static const std::array<unsigned char, 256>& inv_sbox() {
        static const std::array<unsigned char, 256> table = build_sbox(true);
        return table;
    }

    void set_key(const unsigned char key[32]) {
        static constexpr int Nk = 8;
        static constexpr int Nr = 14;
        static constexpr int Nb = 4;

        std::uint32_t w[(Nr + 1) * Nb];
        for (int i = 0; i < Nk; ++i) {
            w[i] = (static_cast<std::uint32_t>(key[4 * i]) << 24) |
                   (static_cast<std::uint32_t>(key[4 * i + 1]) << 16) |
                   (static_cast<std::uint32_t>(key[4 * i + 2]) << 8) |
                   static_cast<std::uint32_t>(key[4 * i + 3]);
        }

        std::uint32_t rcon = 1;
        for (int i = Nk; i < (Nr + 1) * Nb; ++i) {
            std::uint32_t temp = w[i - 1];
            if (i % Nk == 0) {
                temp = (temp << 8) | (temp >> 24);  // RotWord
                temp = (static_cast<std::uint32_t>(sbox()[(temp >> 24) & 0xff]) << 24) |
                       (static_cast<std::uint32_t>(sbox()[(temp >> 16) & 0xff]) << 16) |
                       (static_cast<std::uint32_t>(sbox()[(temp >> 8) & 0xff]) << 8) |
                       static_cast<std::uint32_t>(sbox()[temp & 0xff]);
                temp ^= (rcon << 24);
                rcon = gf_mul(static_cast<unsigned char>(rcon), 2);
            } else if (Nk > 6 && i % Nk == 4) {
                temp = (static_cast<std::uint32_t>(sbox()[(temp >> 24) & 0xff]) << 24) |
                       (static_cast<std::uint32_t>(sbox()[(temp >> 16) & 0xff]) << 16) |
                       (static_cast<std::uint32_t>(sbox()[(temp >> 8) & 0xff]) << 8) |
                       static_cast<std::uint32_t>(sbox()[temp & 0xff]);
            }
            w[i] = w[i - Nk] ^ temp;
        }

        for (int round = 0; round <= Nr; ++round) {
            for (int c = 0; c < Nb; ++c) {
                const std::uint32_t word = w[round * Nb + c];
                round_key_[round * 16 + 4 * c] = static_cast<unsigned char>(word >> 24);
                round_key_[round * 16 + 4 * c + 1] = static_cast<unsigned char>(word >> 16);
                round_key_[round * 16 + 4 * c + 2] = static_cast<unsigned char>(word >> 8);
                round_key_[round * 16 + 4 * c + 3] = static_cast<unsigned char>(word);
            }
        }
    }

    void decrypt_block(const unsigned char in[16], unsigned char out[16]) const {
        static constexpr int Nr = 14;
        unsigned char s[16];
        std::memcpy(s, in, 16);

        add_round_key(s, Nr);
        for (int round = Nr - 1; round >= 1; --round) {
            inv_shift_rows(s);
            inv_sub_bytes(s);
            add_round_key(s, round);
            inv_mix_columns(s);
        }
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, 0);
        std::memcpy(out, s, 16);
    }

    void encrypt_block(const unsigned char in[16], unsigned char out[16]) const {
        static constexpr int Nr = 14;
        unsigned char s[16];
        std::memcpy(s, in, 16);

        add_round_key(s, 0);
        for (int round = 1; round < Nr; ++round) {
            sub_bytes(s);
            shift_rows(s);
            mix_columns(s);
            add_round_key(s, round);
        }
        sub_bytes(s);
        shift_rows(s);
        add_round_key(s, Nr);
        std::memcpy(out, s, 16);
    }

private:
    unsigned char round_key_[15 * 16]{};

    static unsigned char gf_mul(unsigned char a, unsigned char b) {
        unsigned char p = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) p = static_cast<unsigned char>(p ^ a);
            const unsigned char hi = static_cast<unsigned char>(a & 0x80);
            a = static_cast<unsigned char>(a << 1);
            if (hi) a = static_cast<unsigned char>(a ^ 0x1b);
            b = static_cast<unsigned char>(b >> 1);
        }
        return p;
    }

    static unsigned char gf_pow(unsigned char a, int n) {
        unsigned char r = 1;
        for (int i = 0; i < n; ++i) r = gf_mul(r, a);
        return r;
    }

    static unsigned char gf_inv(unsigned char a) {
        if (a == 0) return 0;
        // a^254 == a^-1 in GF(2^8)
        unsigned char r = 1;
        for (int i = 0; i < 254; ++i) r = gf_mul(r, a);
        return r;
    }

    static std::array<unsigned char, 256> build_sbox(bool inverse) {
        std::array<unsigned char, 256> table{};
        for (int i = 0; i < 256; ++i) {
            const unsigned char inv = gf_inv(static_cast<unsigned char>(i));
            unsigned char x = inv;
            unsigned char value = static_cast<unsigned char>(x ^ rotl8(x, 1) ^ rotl8(x, 2) ^
                                                             rotl8(x, 3) ^ rotl8(x, 4) ^ 0x63);
            table[i] = value;
        }
        if (inverse) {
            std::array<unsigned char, 256> inv_table{};
            for (int i = 0; i < 256; ++i) inv_table[table[i]] = static_cast<unsigned char>(i);
            return inv_table;
        }
        return table;
    }

    static unsigned char rotl8(unsigned char x, int n) {
        return static_cast<unsigned char>((x << n) | (x >> (8 - n)));
    }

    void add_round_key(unsigned char s[16], int round) const {
        for (int i = 0; i < 16; ++i) s[i] = static_cast<unsigned char>(s[i] ^ round_key_[round * 16 + i]);
    }

    static void sub_bytes(unsigned char s[16]) {
        for (int i = 0; i < 16; ++i) s[i] = sbox()[s[i]];
    }

    static void inv_sub_bytes(unsigned char s[16]) {
        for (int i = 0; i < 16; ++i) s[i] = inv_sbox()[s[i]];
    }

    static void shift_rows(unsigned char s[16]) {
        unsigned char t[16];
        // row r occupies indices r, r+4, r+8, r+12 and rotates left by r
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) t[r + 4 * c] = s[r + 4 * ((c + r) & 3)];
        }
        std::memcpy(s, t, 16);
    }

    static void inv_shift_rows(unsigned char s[16]) {
        unsigned char t[16];
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) t[r + 4 * c] = s[r + 4 * ((c - r + 4) & 3)];
        }
        std::memcpy(s, t, 16);
    }

    static void mix_columns(unsigned char s[16]) {
        for (int c = 0; c < 4; ++c) {
            unsigned char* col = s + 4 * c;
            const unsigned char a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
            col[0] = static_cast<unsigned char>(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
            col[1] = static_cast<unsigned char>(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
            col[2] = static_cast<unsigned char>(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
            col[3] = static_cast<unsigned char>(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
        }
    }

    static void inv_mix_columns(unsigned char s[16]) {
        for (int c = 0; c < 4; ++c) {
            unsigned char* col = s + 4 * c;
            const unsigned char a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
            col[0] = static_cast<unsigned char>(gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9));
            col[1] = static_cast<unsigned char>(gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13));
            col[2] = static_cast<unsigned char>(gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11));
            col[3] = static_cast<unsigned char>(gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14));
        }
    }
};

// AES-256-CBC decryption with PKCS#7 unpadding.
//
// `out` must have room for `len` bytes. Returns the unpadded plaintext length,
// or 0 when the input is malformed (length not block aligned, bad padding).
inline std::size_t aes256_cbc_decrypt(const unsigned char key[32],
                                      const unsigned char iv[16],
                                      const unsigned char* in, std::size_t len,
                                      unsigned char* out) {
    if (len == 0 || (len % 16) != 0) return 0;

    Aes256 aes;
    aes.set_key(key);

    unsigned char prev[16];
    std::memcpy(prev, iv, 16);

    std::size_t produced = 0;
    for (std::size_t offset = 0; offset < len; offset += 16) {
        unsigned char block[16];
        aes.decrypt_block(in + offset, block);
        for (int i = 0; i < 16; ++i) out[offset + i] = static_cast<unsigned char>(block[i] ^ prev[i]);
        std::memcpy(prev, in + offset, 16);
        produced = offset + 16;
    }

    if (produced == 0) return 0;
    const unsigned char pad = out[produced - 1];
    if (pad == 0 || pad > 16 || pad > produced) return 0;
    for (std::size_t i = 0; i < pad; ++i) {
        if (out[produced - 1 - i] != pad) return 0;
    }
    return produced - pad;
}

}  // namespace vesper::crypto
