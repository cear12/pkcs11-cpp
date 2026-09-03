#include "catch.hpp"
#include "pkcs11cpp/attribute_manager.h"

using namespace pkcs11cpp;

TEST_CASE("AttributeSet builds a correct RSA private key template", "[attribute_manager]") {
    auto attrs = AttributeManager::createRSAPrivateKeyTemplate("my-key", {0x01, 0x02});

    REQUIRE(attrs.hasAttribute(CKA_CLASS));
    REQUIRE(attrs.hasAttribute(CKA_LABEL));
    REQUIRE(attrs.getAttribute(CKA_LABEL).has_value());

    auto label = *attrs.getAttribute(CKA_LABEL);
    REQUIRE(std::string(label.begin(), label.end()) == "my-key");
}

TEST_CASE("AttributeSet::addAttribute overwrites an existing entry in place", "[attribute_manager]") {
    AttributeManager::AttributeSet attrs;
    attrs.addString(CKA_LABEL, "first");
    REQUIRE(attrs.size() == 1);

    attrs.addString(CKA_LABEL, "second");
    REQUIRE(attrs.size() == 1);  // same type again, not appended
    auto label = *attrs.getAttribute(CKA_LABEL);
    REQUIRE(std::string(label.begin(), label.end()) == "second");
}

TEST_CASE("AttributeSet rejects malformed boolean/ULONG attribute sizes", "[attribute_manager]") {
    AttributeManager::AttributeSet attrs;
    REQUIRE_THROWS_AS(attrs.addAttribute(CKA_TOKEN, std::vector<CK_BYTE>{1, 2, 3}), std::invalid_argument);
    REQUIRE_THROWS_AS(attrs.addAttribute(CKA_CLASS, std::vector<CK_BYTE>{1}), std::invalid_argument);
}

TEST_CASE("AttributeSet::addMetadata is retrievable via a vendor-defined type", "[attribute_manager]") {
    AttributeManager::AttributeSet attrs;
    attrs.addMetadata("purpose", "testing");
    // The exact vendor type is a hash of the key, but *something* in
    // vendor-defined space must now be present.
    bool foundVendorAttr = false;
    for (size_t i = 0; i < attrs.size(); ++i) {
        if (attrs.data()[i].type >= CKA_VENDOR_DEFINED) foundVendorAttr = true;
    }
    REQUIRE(foundVendorAttr);
}

TEST_CASE("describeAttribute names well-known attributes and falls back gracefully", "[attribute_manager]") {
    REQUIRE(AttributeManager::describeAttribute(CKA_LABEL) == "CKA_LABEL");
    REQUIRE(AttributeManager::describeAttribute(CKA_VENDOR_DEFINED + 7) == "CKA_VENDOR_DEFINED+7");
}
