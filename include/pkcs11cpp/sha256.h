#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Self-contained SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104).
//
// This project intentionally has zero third-party dependencies, so instead
// of linking OpenSSL it vendors a small, from-scratch implementation of the
// one primitive the mock PKCS#11 backend and a couple of key-derivation
// helpers need. It is written for clarity and correctness against small
// inputs (test/demo data), not for constant-time resistance to timing
// side-channels -- production code signing real secrets should link a
// vetted library (OpenSSL, BoringSSL, ...) instead.
class Sha256 {
public:
    static constexpr std::size_t kDigestSize = 32;
    using Digest = std::array<CK_BYTE, kDigestSize>;

    Sha256();

    void Update(const CK_BYTE* data, std::size_t length);
    void Update(const std::vector<CK_BYTE>& data);

    // Finalizes and returns the digest. The object must not be reused
    // after calling this (matches the one-shot usage pattern in this repo).
    Digest Finish();

    static Digest Hash(const std::vector<CK_BYTE>& data);
    static std::string ToHex(const Digest& digest);

private:
    void ProcessBlock(const CK_BYTE* block);

    std::array<std::uint32_t, 8> state_;
    std::array<CK_BYTE, 64> buffer_{};
    std::size_t buffer_length_ = 0;
    std::uint64_t total_length_ = 0;
};

// HMAC-SHA256(key, message) per RFC 2104. Used by the mock PKCS#11 module
// to simulate C_Sign / C_Verify without a real asymmetric-crypto provider.
Sha256::Digest HmacSha256(const std::vector<CK_BYTE>& key, const std::vector<CK_BYTE>& message);

}  // namespace pkcs11cpp
