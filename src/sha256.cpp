#include "pkcs11cpp/sha256.h"

#include <cstring>

namespace pkcs11cpp {

namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

}  // namespace

Sha256::Sha256()
    : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}

void Sha256::processBlock(const CK_BYTE* block) {
    std::array<std::uint32_t, 64> w{};
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (int i = 0; i < 64; ++i) {
        std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        std::uint32_t ch = (e & f) ^ (~e & g);
        std::uint32_t temp1 = h + s1 + ch + kRoundConstants[i] + w[i];
        std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        std::uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const CK_BYTE* data, std::size_t length) {
    totalLength_ += length;

    while (length > 0) {
        std::size_t take = std::min(length, buffer_.size() - bufferLength_);
        std::memcpy(buffer_.data() + bufferLength_, data, take);
        bufferLength_ += take;
        data += take;
        length -= take;

        if (bufferLength_ == buffer_.size()) {
            processBlock(buffer_.data());
            bufferLength_ = 0;
        }
    }
}

void Sha256::update(const std::vector<CK_BYTE>& data) {
    update(data.data(), data.size());
}

Sha256::Digest Sha256::finish() {
    std::uint64_t bitLength = totalLength_ * 8;

    // Append the mandatory 0x80 padding byte, then zero-pad up to 56 bytes
    // (mod 64), leaving the last 8 bytes for the big-endian bit length.
    CK_BYTE pad = 0x80;
    update(&pad, 1);

    static constexpr CK_BYTE kZero = 0x00;
    while (bufferLength_ != 56) {
        update(&kZero, 1);
    }

    std::array<CK_BYTE, 8> lengthBytes{};
    for (int i = 0; i < 8; ++i) {
        lengthBytes[7 - i] = static_cast<CK_BYTE>(bitLength >> (i * 8));
    }
    // Bypass update() here since it would recurse into padding logic again;
    // this is the final 8-byte block tail, appended directly.
    std::memcpy(buffer_.data() + bufferLength_, lengthBytes.data(), 8);
    processBlock(buffer_.data());

    Digest digest{};
    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = static_cast<CK_BYTE>(state_[i] >> 24);
        digest[i * 4 + 1] = static_cast<CK_BYTE>(state_[i] >> 16);
        digest[i * 4 + 2] = static_cast<CK_BYTE>(state_[i] >> 8);
        digest[i * 4 + 3] = static_cast<CK_BYTE>(state_[i]);
    }
    return digest;
}

Sha256::Digest Sha256::hash(const std::vector<CK_BYTE>& data) {
    Sha256 sha;
    sha.update(data);
    return sha.finish();
}

std::string Sha256::toHex(const Digest& digest) {
    static constexpr char kHexChars[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(digest.size() * 2);
    for (CK_BYTE b : digest) {
        hex.push_back(kHexChars[b >> 4]);
        hex.push_back(kHexChars[b & 0x0F]);
    }
    return hex;
}

Sha256::Digest hmacSha256(const std::vector<CK_BYTE>& key, const std::vector<CK_BYTE>& message) {
    constexpr std::size_t kBlockSize = 64;

    std::vector<CK_BYTE> keyBlock(kBlockSize, 0x00);
    if (key.size() > kBlockSize) {
        auto digest = Sha256::hash(key);
        std::copy(digest.begin(), digest.end(), keyBlock.begin());
    } else {
        std::copy(key.begin(), key.end(), keyBlock.begin());
    }

    std::vector<CK_BYTE> innerPad(kBlockSize), outerPad(kBlockSize);
    for (std::size_t i = 0; i < kBlockSize; ++i) {
        innerPad[i] = keyBlock[i] ^ 0x36;
        outerPad[i] = keyBlock[i] ^ 0x5c;
    }

    Sha256 inner;
    inner.update(innerPad);
    inner.update(message);
    auto innerDigest = inner.finish();

    Sha256 outer;
    outer.update(outerPad);
    outer.update(std::vector<CK_BYTE>(innerDigest.begin(), innerDigest.end()));
    return outer.finish();
}

}  // namespace pkcs11cpp
