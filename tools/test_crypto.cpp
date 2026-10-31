// Standalone proof that the AES-256 implementation matches FIPS-197, and that
// the table container round-trips against the Python compiler.
//
//   g++ -std=c++20 -Iengine/include tools/test_crypto.cpp -o out/test_crypto
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <vesper/crypto.hpp>

static int failures = 0;

static void check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

static std::vector<unsigned char> unhex(const char* text) {
    std::vector<unsigned char> out;
    for (const char* p = text; p[0] && p[1]; p += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out.push_back(static_cast<unsigned char>((nib(p[0]) << 4) | nib(p[1])));
    }
    return out;
}

static bool matches(const unsigned char* data, const std::vector<unsigned char>& expected) {
    return std::memcmp(data, expected.data(), expected.size()) == 0;
}

int main(int argc, char** argv) {
    std::printf("AES-256 block (FIPS-197 C.3)\n");
    {
        const auto key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const auto plain = unhex("00112233445566778899aabbccddeeff");
        const auto expect = unhex("8ea2b7ca516745bfeafc49904b496089");

        vesper::crypto::Aes256 aes;
        aes.set_key(key.data());
        unsigned char block[16];
        aes.encrypt_block(plain.data(), block);
        check(matches(block, expect), "encrypt_block");

        unsigned char back[16];
        aes.decrypt_block(expect.data(), back);
        check(std::memcmp(back, plain.data(), 16) == 0, "decrypt_block");
    }

    std::printf("SHA-256 'abc'\n");
    {
        const auto digest = vesper::crypto::sha256("abc", 3);
        const auto expect = unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        check(matches(digest.data(), expect), "sha256");
    }

    std::printf("HMAC-SHA256 RFC 4231 case 2\n");
    {
        const auto mac = vesper::crypto::hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28);
        const auto expect = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        check(matches(mac.data(), expect), "hmac");
    }

    if (argc > 1) {
        std::printf("container round-trip\n");
        std::FILE* f = std::fopen(argv[1], "rb");
        if (!f) {
            std::printf("  [FAIL] cannot open %s\n", argv[1]);
            ++failures;
        } else {
            std::vector<unsigned char> blob;
            unsigned char buf[4096];
            std::size_t got;
            while ((got = std::fread(buf, 1, sizeof(buf), f)) > 0) blob.insert(blob.end(), buf, buf + got);
            std::fclose(f);

            check(blob.size() > 64 && std::memcmp(blob.data(), "VSPR", 4) == 0, "magic");

            const unsigned char buildLen = blob[8];
            const std::string build(reinterpret_cast<const char*>(blob.data() + 9), buildLen);

            std::size_t off = 9 + buildLen;
            std::uint32_t bodyLen = 0;
            std::memcpy(&bodyLen, blob.data() + off, 4);
            off += 4;
            const unsigned char* iv = blob.data() + off;
            off += 16;
            const unsigned char* body = blob.data() + off;
            off += bodyLen;
            const unsigned char* mac = blob.data() + off;

            std::printf("  build=%s body=%u\n", build.c_str(), bodyLen);

            static const char kSecret[] = "vesper::table::k1::7b1f0a5c9e3d2648";
            std::vector<unsigned char> keyMaterial;
            keyMaterial.insert(keyMaterial.end(), kSecret, kSecret + sizeof(kSecret) - 1);
            keyMaterial.push_back(0);
            keyMaterial.insert(keyMaterial.end(), build.begin(), build.end());
            const auto key = vesper::crypto::sha256(keyMaterial.data(), keyMaterial.size());

            std::vector<unsigned char> macInput;
            macInput.insert(macInput.end(), blob.data() + 8, blob.data() + 9 + buildLen + 4 + 16);
            macInput.insert(macInput.end(), body, body + bodyLen);
            const auto expectMac = vesper::crypto::hmac_sha256(key.data(), 32, macInput.data(), macInput.size());
            check(vesper::crypto::constant_time_equal(mac, expectMac.data(), 32), "hmac over container");

            std::vector<unsigned char> plain(bodyLen);
            const std::size_t plainLen =
                vesper::crypto::aes256_cbc_decrypt(key.data(), iv, body, bodyLen, plain.data());
            check(plainLen > 8, "cbc decrypt + unpad");

            if (plainLen > 8) {
                std::uint32_t count = 0;
                std::memcpy(&count, plain.data(), 4);
                std::printf("  entries=%u\n", count);
                check(count > 100, "entry count plausible");

                std::size_t cursor = 4;
                int shown = 0;
                for (std::uint32_t i = 0; i < count && cursor + 2 <= plainLen; ++i) {
                    std::uint16_t nameLen = 0;
                    std::memcpy(&nameLen, plain.data() + cursor, 2);
                    cursor += 2;
                    const std::string name(reinterpret_cast<const char*>(plain.data() + cursor), nameLen);
                    cursor += nameLen;
                    std::uint64_t value = 0;
                    std::memcpy(&value, plain.data() + cursor, 8);
                    cursor += 8;
                    if (shown++ < 3) std::printf("    %s = 0x%llx\n", name.c_str(),
                                                 static_cast<unsigned long long>(value));
                }
                check(cursor == plainLen, "entry table consumed exactly");
            }
        }
    }

    std::printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "OK", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
