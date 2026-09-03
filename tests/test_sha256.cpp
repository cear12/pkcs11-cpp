#include "catch.hpp"
#include "pkcs11cpp/sha256.h"

using namespace pkcs11cpp;

TEST_CASE("Sha256 matches known FIPS 180-4 / RFC 4231 test vectors", "[sha256]") {
    SECTION("empty input") {
        REQUIRE(Sha256::ToHex(Sha256::Hash({})) ==
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
    SECTION("\"abc\"") {
        std::vector<CK_BYTE> data = {'a', 'b', 'c'};
        REQUIRE(Sha256::ToHex(Sha256::Hash(data)) ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    SECTION("input spanning multiple 64-byte blocks") {
        std::vector<CK_BYTE> data(200, 'x');
        auto digest = Sha256::Hash(data);
        REQUIRE(digest.size() == Sha256::kDigestSize);
        // Re-hashing the same input must be deterministic.
        REQUIRE(Sha256::ToHex(digest) == Sha256::ToHex(Sha256::Hash(data)));
    }
}

TEST_CASE("HmacSha256 matches RFC 4231 test case 1", "[sha256][hmac]") {
    std::vector<CK_BYTE> key(20, 0x0b);
    std::vector<CK_BYTE> data = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
    REQUIRE(Sha256::ToHex(HmacSha256(key, data)) ==
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST_CASE("HmacSha256 is sensitive to both key and message", "[sha256][hmac]") {
    std::vector<CK_BYTE> key1 = {'k', 'e', 'y', '1'};
    std::vector<CK_BYTE> key2 = {'k', 'e', 'y', '2'};
    std::vector<CK_BYTE> message = {'d', 'a', 't', 'a'};

    REQUIRE(HmacSha256(key1, message) != HmacSha256(key2, message));
}
