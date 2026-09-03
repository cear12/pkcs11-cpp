#include "pkcs11cpp/attribute_manager.h"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "pkcs11cpp/logging.h"

namespace pkcs11cpp {

// --- AttributeSet ------------------------------------------------------------

AttributeManager::AttributeSet& AttributeManager::AttributeSet::AddAttribute(
    CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value, bool validate) {
    if (validate) {
        AttributeManager::ValidateAttribute(type, value);
    }

    auto it = attribute_index_.find(type);
    if (it != attribute_index_.end()) {
        size_t index = it->second;
        attribute_data_[index] = value;
        attributes_[index].pValue = attribute_data_[index].data();
        attributes_[index].ulValueLen = static_cast<CK_ULONG>(attribute_data_[index].size());
    } else {
        size_t index = attributes_.size();
        attribute_index_[type] = index;
        attribute_data_.push_back(value);
        attributes_.push_back({type, attribute_data_.back().data(),
                                static_cast<CK_ULONG>(attribute_data_.back().size())});
    }
    return *this;
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::AddBoolean(CK_ATTRIBUTE_TYPE type, bool value) {
    CK_BBOOL bool_value = value ? CK_TRUE : CK_FALSE;
    return AddAttribute(type, std::vector<CK_BYTE>(reinterpret_cast<CK_BYTE*>(&bool_value),
                                                     reinterpret_cast<CK_BYTE*>(&bool_value) + sizeof(bool_value)));
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::AddULong(CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
    return AddAttribute(type, std::vector<CK_BYTE>(reinterpret_cast<CK_BYTE*>(&value),
                                                     reinterpret_cast<CK_BYTE*>(&value) + sizeof(value)));
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::AddString(CK_ATTRIBUTE_TYPE type,
                                                                            const std::string& value) {
    return AddAttribute(type, std::vector<CK_BYTE>(value.begin(), value.end()));
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::AddBytes(CK_ATTRIBUTE_TYPE type,
                                                                           const std::vector<CK_BYTE>& value) {
    return AddAttribute(type, value);
}

AttributeManager::AttributeSet& AttributeManager::AttributeSet::AddMetadata(const std::string& key,
                                                                              const std::string& value) {
    CK_ATTRIBUTE_TYPE vendor_type = CKA_VENDOR_DEFINED + static_cast<CK_ATTRIBUTE_TYPE>(std::hash<std::string>{}(key) % 1000);
    return AddString(vendor_type, key + "=" + value);
}

bool AttributeManager::AttributeSet::HasAttribute(CK_ATTRIBUTE_TYPE type) const {
    return attribute_index_.count(type) > 0;
}

std::optional<std::vector<CK_BYTE>> AttributeManager::AttributeSet::GetAttribute(CK_ATTRIBUTE_TYPE type) const {
    auto it = attribute_index_.find(type);
    if (it != attribute_index_.end()) {
        return attribute_data_[it->second];
    }
    return std::nullopt;
}

// --- AttributeManager ---------------------------------------------------------

namespace {
// The "common" attribute set ReadObjectAttributes probes for. PKCS#11 has
// no "list all attributes" call, so a wrapper has to name what it wants;
// this list covers what the rest of this repo (and most applications)
// care about when introspecting a key or certificate object.
const std::vector<CK_ATTRIBUTE_TYPE>& CommonAttributeTypes() {
    static const std::vector<CK_ATTRIBUTE_TYPE> kTypes = {
        CKA_CLASS,   CKA_KEY_TYPE, CKA_TOKEN,   CKA_PRIVATE, CKA_SENSITIVE, CKA_EXTRACTABLE,
        CKA_SIGN,    CKA_VERIFY,   CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP,      CKA_UNWRAP,
        CKA_LABEL,   CKA_ID,
    };
    return kTypes;
}
}  // namespace

AttributeManager::AttributeSet AttributeManager::ReadObjectAttributes(CK_SESSION_HANDLE session,
                                                                        CK_FUNCTION_LIST_PTR functions,
                                                                        CK_OBJECT_HANDLE object) const {
    const auto& types = CommonAttributeTypes();
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
        log::Warn("C_GetAttributeValue returned rv=" + std::to_string(rv) + " while reading object " +
                  std::to_string(object) + "; returning the attributes that were readable");
    }

    AttributeSet result;
    for (size_t i = 0; i < probe.size(); ++i) {
        if (probe[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) continue;
        result.AddAttribute(probe[i].type, buffers[i], /*validate=*/false);
    }
    return result;
}

void AttributeManager::ModifyObjectAttributes(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                               CK_OBJECT_HANDLE object, const AttributeSet& new_attributes) const {
    std::vector<CK_ATTRIBUTE> modifiable;
    for (size_t i = 0; i < new_attributes.Size(); ++i) {
        CK_ATTRIBUTE_TYPE type = new_attributes.Data()[i].type;
        if (IsAttributeModifiable(type)) {
            modifiable.push_back(new_attributes.Data()[i]);
        } else {
            log::Warn("Attempt to modify read-only attribute: " + DescribeAttribute(type));
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

AttributeManager::AttributeSet AttributeManager::CreateRsaPrivateKeyTemplate(const std::string& label,
                                                                               const std::vector<CK_BYTE>& id,
                                                                               bool extractable, bool sensitive) {
    AttributeSet attrs;
    attrs.AddULong(CKA_CLASS, CKO_PRIVATE_KEY)
        .AddULong(CKA_KEY_TYPE, CKK_RSA)
        .AddBoolean(CKA_TOKEN, true)
        .AddBoolean(CKA_PRIVATE, true)
        .AddBoolean(CKA_SENSITIVE, sensitive)
        .AddBoolean(CKA_EXTRACTABLE, extractable)
        .AddBoolean(CKA_SIGN, true)
        .AddBoolean(CKA_DECRYPT, true)
        .AddString(CKA_LABEL, label)
        .AddBytes(CKA_ID, id)
        .AddMetadata("created", CurrentTimestampUtc())
        .AddMetadata("purpose", "signing_and_decryption");
    return attrs;
}

AttributeManager::AttributeSet AttributeManager::CreateAesKeyTemplate(const std::string& label,
                                                                        const std::vector<CK_BYTE>& id,
                                                                        CK_ULONG key_size_bits) {
    AttributeSet attrs;
    attrs.AddULong(CKA_CLASS, CKO_SECRET_KEY)
        .AddULong(CKA_KEY_TYPE, CKK_AES)
        .AddULong(CKA_VALUE_LEN, key_size_bits / 8)
        .AddBoolean(CKA_TOKEN, true)
        .AddBoolean(CKA_SENSITIVE, true)
        .AddBoolean(CKA_EXTRACTABLE, false)
        .AddBoolean(CKA_ENCRYPT, true)
        .AddBoolean(CKA_DECRYPT, true)
        .AddBoolean(CKA_WRAP, true)
        .AddBoolean(CKA_UNWRAP, true)
        .AddString(CKA_LABEL, label)
        .AddBytes(CKA_ID, id)
        .AddMetadata("created", CurrentTimestampUtc())
        .AddMetadata("algorithm", "AES-" + std::to_string(key_size_bits));
    return attrs;
}

std::string AttributeManager::DescribeAttribute(CK_ATTRIBUTE_TYPE type) {
    static const std::unordered_map<CK_ATTRIBUTE_TYPE, std::string> kNames = {
        {CKA_CLASS, "CKA_CLASS"},         {CKA_TOKEN, "CKA_TOKEN"},         {CKA_PRIVATE, "CKA_PRIVATE"},
        {CKA_LABEL, "CKA_LABEL"},         {CKA_VALUE_LEN, "CKA_VALUE_LEN"}, {CKA_EXTRACTABLE, "CKA_EXTRACTABLE"},
        {CKA_SENSITIVE, "CKA_SENSITIVE"}, {CKA_ID, "CKA_ID"},               {CKA_KEY_TYPE, "CKA_KEY_TYPE"},
        {CKA_DERIVE, "CKA_DERIVE"},       {CKA_ENCRYPT, "CKA_ENCRYPT"},     {CKA_DECRYPT, "CKA_DECRYPT"},
        {CKA_WRAP, "CKA_WRAP"},           {CKA_UNWRAP, "CKA_UNWRAP"},       {CKA_SIGN, "CKA_SIGN"},
        {CKA_VERIFY, "CKA_VERIFY"},
    };
    auto it = kNames.find(type);
    if (it != kNames.end()) return it->second;
    if (type >= CKA_VENDOR_DEFINED) return "CKA_VENDOR_DEFINED+" + std::to_string(type - CKA_VENDOR_DEFINED);
    return "CKA_0x" + std::to_string(type);
}

bool AttributeManager::IsAttributeModifiable(CK_ATTRIBUTE_TYPE type) {
    static const std::set<CK_ATTRIBUTE_TYPE> kModifiableAttrs = {
        CKA_LABEL, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN,  CKA_VERIFY,
        CKA_WRAP,  CKA_UNWRAP,  CKA_DERIVE,  CKA_SENSITIVE, CKA_EXTRACTABLE,
    };
    return kModifiableAttrs.count(type) > 0 || type >= CKA_VENDOR_DEFINED;
}

void AttributeManager::ValidateAttribute(CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value) {
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

std::string AttributeManager::CurrentTimestampUtc() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc{};
    gmtime_r(&time, &tm_utc);
    std::stringstream ss;
    ss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

}  // namespace pkcs11cpp
