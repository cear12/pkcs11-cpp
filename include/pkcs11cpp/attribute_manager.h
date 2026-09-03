#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Builds and validates PKCS#11 CK_ATTRIBUTE templates without the
// caller having to hand-manage the raw byte buffers each CK_ATTRIBUTE
// points into (a classic source of dangling-pointer bugs: CK_ATTRIBUTE
// only stores a pointer + length, so whatever owns the bytes must outlive
// every C_* call that uses the template).
class AttributeManager {
public:
    class AttributeSet {
    public:
        AttributeSet& addAttribute(CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value, bool validate = true);
        AttributeSet& addBoolean(CK_ATTRIBUTE_TYPE type, bool value);
        AttributeSet& addULong(CK_ATTRIBUTE_TYPE type, CK_ULONG value);
        AttributeSet& addString(CK_ATTRIBUTE_TYPE type, const std::string& value);
        AttributeSet& addBytes(CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value);

        // Vendor-defined attributes (CKA_VENDOR_DEFINED + hash(key) % 1000)
        // used to smuggle simple "created"/"purpose"-style metadata onto an
        // object. Real deployments should prefer a proper application
        // profile / attribute registry instead of hashing into vendor
        // space, but this mirrors what many PKCS#11 wrapper libraries do
        // in practice for lightweight tagging.
        AttributeSet& addMetadata(const std::string& key, const std::string& value);

        CK_ATTRIBUTE* data() { return attributes_.data(); }
        const CK_ATTRIBUTE* data() const { return attributes_.data(); }
        size_t size() const { return attributes_.size(); }
        bool hasAttribute(CK_ATTRIBUTE_TYPE type) const;
        std::optional<std::vector<CK_BYTE>> getAttribute(CK_ATTRIBUTE_TYPE type) const;

    private:
        std::vector<CK_ATTRIBUTE> attributes_;
        std::vector<std::vector<CK_BYTE>> attributeData_;
        std::unordered_map<CK_ATTRIBUTE_TYPE, size_t> attributeIndex_;
    };

    // Fetches every attribute in the "common" set (class, key type, token
    // flags, sign/verify/encrypt/decrypt/wrap/unwrap capability flags,
    // label, id) for an object via the standard two-pass
    // C_GetAttributeValue protocol: first call sizes each attribute,
    // second call fills the caller-allocated buffers.
    AttributeSet readObjectAttributes(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                       CK_OBJECT_HANDLE object) const;

    void modifyObjectAttributes(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions, CK_OBJECT_HANDLE object,
                                 const AttributeSet& newAttributes) const;

    static AttributeSet createRSAPrivateKeyTemplate(const std::string& label, const std::vector<CK_BYTE>& id,
                                                      bool extractable = false, bool sensitive = true);
    static AttributeSet createAESKeyTemplate(const std::string& label, const std::vector<CK_BYTE>& id,
                                              CK_ULONG keySizeBits = 256);

    // Human-readable name for a well-known CKA_* attribute type, used for
    // logging/demo output ("CKA_LABEL" instead of a raw integer).
    static std::string describeAttribute(CK_ATTRIBUTE_TYPE type);

private:
    static bool isAttributeModifiable(CK_ATTRIBUTE_TYPE type);
    static void validateAttribute(CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value);
    static std::string currentTimestampUtc();
};

}  // namespace pkcs11cpp
