#include "catch.hpp"
#include "pkcs11cpp/attribute_manager.h"

using namespace pkcs11cpp;

TEST_CASE("AttributeSet builds a correct RSA private key template",
          "[attribute_manager]") {
  auto attrs =
      AttributeManager::CreateRsaPrivateKeyTemplate("my-key", {0x01, 0x02});

  REQUIRE(attrs.HasAttribute(CKA_CLASS));
  REQUIRE(attrs.HasAttribute(CKA_LABEL));
  REQUIRE(attrs.GetAttribute(CKA_LABEL).has_value());

  auto label = *attrs.GetAttribute(CKA_LABEL);
  REQUIRE(std::string(label.begin(), label.end()) == "my-key");
}

TEST_CASE("AttributeSet::AddAttribute overwrites an existing entry in place",
          "[attribute_manager]") {
  AttributeManager::AttributeSet attrs;
  attrs.AddString(CKA_LABEL, "first");
  REQUIRE(attrs.Size() == 1);

  attrs.AddString(CKA_LABEL, "second");
  REQUIRE(attrs.Size() == 1);  // same type again, not appended
  auto label = *attrs.GetAttribute(CKA_LABEL);
  REQUIRE(std::string(label.begin(), label.end()) == "second");
}

TEST_CASE("AttributeSet rejects malformed boolean/ULONG attribute sizes",
          "[attribute_manager]") {
  AttributeManager::AttributeSet attrs;
  REQUIRE_THROWS_AS(
      attrs.AddAttribute(CKA_TOKEN, std::vector<CK_BYTE>{1, 2, 3}),
      std::invalid_argument);
  REQUIRE_THROWS_AS(attrs.AddAttribute(CKA_CLASS, std::vector<CK_BYTE>{1}),
                    std::invalid_argument);
}

TEST_CASE("AttributeSet::AddMetadata is retrievable via a vendor-defined type",
          "[attribute_manager]") {
  AttributeManager::AttributeSet attrs;
  attrs.AddMetadata("purpose", "testing");
  // The exact vendor type is a hash of the key, but *something* in
  // vendor-defined space must now be present.
  bool found_vendor_attr = false;
  for (size_t i = 0; i < attrs.Size(); ++i) {
    if (attrs.Data()[i].type >= CKA_VENDOR_DEFINED) found_vendor_attr = true;
  }
  REQUIRE(found_vendor_attr);
}

TEST_CASE(
    "DescribeAttribute names well-known attributes and falls back gracefully",
    "[attribute_manager]") {
  REQUIRE(AttributeManager::DescribeAttribute(CKA_LABEL) == "CKA_LABEL");
  REQUIRE(AttributeManager::DescribeAttribute(CKA_VENDOR_DEFINED + 7) ==
          "CKA_VENDOR_DEFINED+7");
}
