#include "pkcs11cpp/attribute_manager.h"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "pkcs11cpp/logging.h"

namespace pkcs11cpp {

// --- AttributeSet ------------------------------------------------------------

AttributeManager::AttributeSet& AttributeManager::AttributeSet::addAttribute(
    CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value, bool validate) {
    if (validate) {
        AttributeManager::validateAttribute(type, value);
    }

    auto it = attributeIndex_.find(type);
    if (it != attributeIndex_.end()) {
        size_t index = it->second;
        attributeData_[index] = value;
        attributes_[index].pValue = attributeData_[index].data();
        attributes_[index].ulValueLen = static_cast<CK_ULONG>(attributeData_[index].size());
    } else {
        size_t index = attributes_.size();
        attributeIndex_[type] = index;
        attributeData_.push_back(value);
        attributes_.push_back({type, attributeData_.back().data(),
                                static_cast<CK_ULONG>(attributeData_.back().size())});
    }
    return *this;
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::addBoolean(CK_ATTRIBUTE_TYPE type, bool value) {
    CK_BBOOL boolValue = value ? CK_TRUE : CK_FALSE;
    return addAttribute(type, std::vector<CK_BYTE>(reinterpret_cast<CK_BYTE*>(&boolValue),
                                                     reinterpret_cast<CK_BYTE*>(&boolValue) + sizeof(boolValue)));
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::addULong(CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
    return addAttribute(type, std::vector<CK_BYTE>(reinterpret_cast<CK_BYTE*>(&value),
                                                     reinterpret_cast<CK_BYTE*>(&value) + sizeof(value)));
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::addString(CK_ATTRIBUTE_TYPE type,
                                                                            const std::string& value) {
    return addAttribute(type, std::vector<CK_BYTE>(value.begin(), value.end()));
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::addBytes(CK_ATTRIBUTE_TYPE type,
                                                                           const std::vector<CK_BYTE>& value) {
    return addAttribute(type, value);
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::addMetadata(const std::string& key,
                                                                              const std::string& value) {
    CK_ATTRIBUTE_TYPE vendorType = CKA_VENDOR_DEFINED + static_cast<CK_ATTRIBUTE_TYPE>(std::hash<std::string>{}(key) % 1000);
    return addString(vendorType, key + "=" + value);
}

bool AttributeManager::AttributeSet::hasAttribute(CK_ATTRIBUTE_TYPE type) const {
    return attributeIndex_.count(type) > 0;
}

std::optional<std::vector<CK_BYTE>> AttributeManager::AttributeSet::getAttribute(CK_ATTRIBUTE_TYPE type) const {
    auto it = attributeIndex_.find(type);
    if (it != attributeIndex_.end()) {
        return attributeData_[it->second];
    }
    return std::nullopt;
}

// --- AttributeManager ---------------------------------------------------------

namespace {
// The "common" attribute set readObjectAttributes probes for. PKCS#11 has
// no "list all attributes" call, so a wrapper has to name what it wants;
// this list covers what the rest of this repo (and most applications)
// care about when introspecting a key or certificate object.
const std::vector<CK_ATTRIBUTE_TYPE>& commonAttributeTypes() {
    static const std::vector<CK_ATTRIBUTE_TYPE> types = {
        CKA_CLASS,   CKA_KEY_TYPE, CKA_TOKEN,   CKA_PRIVATE, CKA_SENSITIVE, CKA_EXTRACTABLE,
        CKA_SIGN,    CKA_VERIFY,   CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP,      CKA_UNWRAP,
        CKA_LABEL,   CKA_ID,
    };
    return types;
}
}  // namespace

AttributeManager::AttributeSet AttributeManager::readObjectAttributes(CK_SESSION_HANDLE session,
                                                                        CK_FUNCTION_LIST_PTR functions,
                                                                        CK_OBJECT_HANDLE object) const {
    const auto& types = commonAttributeTypes();
    std::vector<CK_ATTRIBUTE> probe;
    probe.reserve(types.size());
    for (auto type : types) probe.push_back({type, nullptr, 0});

    // Pass 1: size each attribute (and discover which ones this object
    // simply doesn't have -- CKR_ATTRIBUTE_TYPE_INVALID sets ulValueLen to
    // CK_UNAVAILABLE_INFORMATION rather than failing the whole call).
    functions->C_GetAttributeValue(session, object, probe.data(), static_cast<CK_ULONG>(probe.size()));

    std::vector<std::vector<CK_BYTE>> buffers(probe.size());
    for (size_t i = 0; i < probe.size(); ++i) {
        if (probe[i].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
            buffers[i].resize(probe[i].ulValueLen);
            probe[i].pValue = buffers[i].data();
        }
    }

    CK_RV rv = functions->C_GetAttributeValue(session, object, probe.data(), static_cast<CK_ULONG>(probe.size()));
    if (rv != CKR_OK) {
        log::warn("C_GetAttributeValue returned rv=" + std::to_string(rv) + " while reading object " +
                  std::to_string(object) + "; returning the attributes that were readable");
    }

    AttributeSet result;
    for (size_t i = 0; i < probe.size(); ++i) {
        if (probe[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) continue;
        result.addAttribute(probe[i].type, buffers[i], /*validate=*/false);
    }
    return result;
}

void AttributeManager::modifyObjectAttributes(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                               CK_OBJECT_HANDLE object, const AttributeSet& newAttributes) const {
    std::vector<CK_ATTRIBUTE> modifiable;
    for (size_t i = 0; i < newAttributes.size(); ++i) {
        CK_ATTRIBUTE_TYPE type = newAttributes.data()[i].type;
        if (isAttributeModifiable(type)) {
            modifiable.push_back(newAttributes.data()[i]);
        } else {
            log::warn("Attempt to modify read-only attribute: " + describeAttribute(type));
        }
    }

    if (!modifiable.empty()) {
        CK_RV rv = functions->C_SetAttributeValue(session, object, modifiable.data(),
                                                    static_cast<CK_ULONG>(modifiable.size()));
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to modify attributes: " + std::to_string(rv));
        }
    }
}

AttributeManager::AttributeSet AttributeManager::createRSAPrivateKeyTemplate(const std::string& label,
                                                                               const std::vector<CK_BYTE>& id,
                                                                               bool extractable, bool sensitive) {
    AttributeSet attrs;
    attrs.addULong(CKA_CLASS, CKO_PRIVATE_KEY)
        .addULong(CKA_KEY_TYPE, CKK_RSA)
        .addBoolean(CKA_TOKEN, true)
        .addBoolean(CKA_PRIVATE, true)
        .addBoolean(CKA_SENSITIVE, sensitive)
        .addBoolean(CKA_EXTRACTABLE, extractable)
        .addBoolean(CKA_SIGN, true)
        .addBoolean(CKA_DECRYPT, true)
        .addString(CKA_LABEL, label)
        .addBytes(CKA_ID, id)
        .addMetadata("created", currentTimestampUtc())
        .addMetadata("purpose", "signing_and_decryption");
    return attrs;
}

AttributeManager::AttributeSet AttributeManager::createAESKeyTemplate(const std::string& label,
                                                                        const std::vector<CK_BYTE>& id,
                                                                        CK_ULONG keySizeBits) {
    AttributeSet attrs;
    attrs.addULong(CKA_CLASS, CKO_SECRET_KEY)
        .addULong(CKA_KEY_TYPE, CKK_AES)
        .addULong(CKA_VALUE_LEN, keySizeBits / 8)
        .addBoolean(CKA_TOKEN, true)
        .addBoolean(CKA_SENSITIVE, true)
        .addBoolean(CKA_EXTRACTABLE, false)
        .addBoolean(CKA_ENCRYPT, true)
        .addBoolean(CKA_DECRYPT, true)
        .addBoolean(CKA_WRAP, true)
        .addBoolean(CKA_UNWRAP, true)
        .addString(CKA_LABEL, label)
        .addBytes(CKA_ID, id)
        .addMetadata("created", currentTimestampUtc())
        .addMetadata("algorithm", "AES-" + std::to_string(keySizeBits));
    return attrs;
}

std::string AttributeManager::describeAttribute(CK_ATTRIBUTE_TYPE type) {
    static const std::unordered_map<CK_ATTRIBUTE_TYPE, std::string> names = {
        {CKA_CLASS, "CKA_CLASS"},         {CKA_TOKEN, "CKA_TOKEN"},         {CKA_PRIVATE, "CKA_PRIVATE"},
        {CKA_LABEL, "CKA_LABEL"},         {CKA_VALUE_LEN, "CKA_VALUE_LEN"}, {CKA_EXTRACTABLE, "CKA_EXTRACTABLE"},
        {CKA_SENSITIVE, "CKA_SENSITIVE"}, {CKA_ID, "CKA_ID"},               {CKA_KEY_TYPE, "CKA_KEY_TYPE"},
        {CKA_DERIVE, "CKA_DERIVE"},       {CKA_ENCRYPT, "CKA_ENCRYPT"},     {CKA_DECRYPT, "CKA_DECRYPT"},
        {CKA_WRAP, "CKA_WRAP"},           {CKA_UNWRAP, "CKA_UNWRAP"},       {CKA_SIGN, "CKA_SIGN"},
        {CKA_VERIFY, "CKA_VERIFY"},
    };
    auto it = names.find(type);
    if (it != names.end()) return it->second;
    if (type >= CKA_VENDOR_DEFINED) return "CKA_VENDOR_DEFINED+" + std::to_string(type - CKA_VENDOR_DEFINED);
    return "CKA_0x" + std::to_string(type);
}

bool AttributeManager::isAttributeModifiable(CK_ATTRIBUTE_TYPE type) {
    static const std::set<CK_ATTRIBUTE_TYPE> modifiableAttrs = {
        CKA_LABEL, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN,  CKA_VERIFY,
        CKA_WRAP,  CKA_UNWRAP,  CKA_DERIVE,  CKA_SENSITIVE, CKA_EXTRACTABLE,
    };
    return modifiableAttrs.count(type) > 0 || type >= CKA_VENDOR_DEFINED;
}

void AttributeManager::validateAttribute(CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value) {
    switch (type) {
        case CKA_CLASS:
        case CKA_KEY_TYPE:
            if (value.size() != sizeof(CK_ULONG)) {
                throw std::invalid_argument("Invalid size for ULONG attribute");
            }
            break;
        case CKA_TOKEN:
        case CKA_PRIVATE:
        case CKA_SENSITIVE:
        case CKA_EXTRACTABLE:
        case CKA_SIGN:
        case CKA_VERIFY:
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
        case CKA_WRAP:
        case CKA_UNWRAP:
            if (value.size() != sizeof(CK_BBOOL)) {
                throw std::invalid_argument("Invalid size for BOOLEAN attribute");
            }
            break;
        default:
            break;
    }
}

std::string AttributeManager::currentTimestampUtc() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tmUtc{};
    gmtime_r(&time, &tmUtc);
    std::stringstream ss;
    ss << std::put_time(&tmUtc, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

}  // namespace pkcs11cpp
