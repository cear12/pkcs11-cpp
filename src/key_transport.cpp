#include "pkcs11cpp/key_transport.h"

#include <stdexcept>
#include <array>

namespace pkcs11cpp {

namespace {
constexpr std::array<CK_ATTRIBUTE_TYPE, 12> kTransportAttributeTypes = {
    CKA_CLASS,   CKA_KEY_TYPE, CKA_TOKEN,   CKA_PRIVATE, CKA_SENSITIVE, CKA_EXTRACTABLE,
    CKA_SIGN,    CKA_VERIFY,   CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP,      CKA_UNWRAP,
};
}  // namespace

std::vector<CK_BYTE> KeyTransport::generateRandomBytes(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                         std::size_t length) {
    std::vector<CK_BYTE> data(length);
    CK_RV rv = functions->C_GenerateRandom(session, data.data(), static_cast<CK_ULONG>(length));
    if (rv != CKR_OK) {
        throw std::runtime_error("C_GenerateRandom failed: " + std::to_string(rv));
    }
    return data;
}

KeyTransport::WrapResult KeyTransport::extractKeyTemplate(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                            CK_OBJECT_HANDLE keyHandle) {
    std::vector<CK_ATTRIBUTE> probe;
    probe.reserve(kTransportAttributeTypes.size());
    for (auto type : kTransportAttributeTypes) probe.push_back({type, nullptr, 0});

    functions->C_GetAttributeValue(session, keyHandle, probe.data(), static_cast<CK_ULONG>(probe.size()));

    WrapResult result;
    result.templateStorage.resize(probe.size());
    for (size_t i = 0; i < probe.size(); ++i) {
        if (probe[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) continue;
        result.templateStorage[i].resize(probe[i].ulValueLen);
        probe[i].pValue = result.templateStorage[i].data();
    }

    CK_RV rv = functions->C_GetAttributeValue(session, keyHandle, probe.data(), static_cast<CK_ULONG>(probe.size()));
    if (rv != CKR_OK) {
        throw std::runtime_error("C_GetAttributeValue failed while extracting key template: " + std::to_string(rv));
    }

    for (size_t i = 0; i < probe.size(); ++i) {
        if (probe[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) continue;
        result.keyTemplate.push_back(probe[i]);
    }
    return result;
}

KeyTransport::WrapResult KeyTransport::wrapKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                CK_OBJECT_HANDLE keyToWrap, CK_OBJECT_HANDLE wrappingKey,
                                                WrapMechanism mechanism) const {
    WrapResult result = extractKeyTemplate(session, functions, keyToWrap);
    result.mechanism = mechanism;

    CK_MECHANISM ckMechanism{};
    static CK_RSA_PKCS_OAEP_PARAMS oaepParams;

    switch (mechanism) {
        case WrapMechanism::AesKeyWrap:
            ckMechanism = {CKM_AES_KEY_WRAP, nullptr, 0};
            break;
        case WrapMechanism::AesCbcPad:
            result.iv = generateRandomBytes(session, functions, 16);
            ckMechanism = {CKM_AES_CBC_PAD, result.iv.data(), static_cast<CK_ULONG>(result.iv.size())};
            break;
        case WrapMechanism::RsaPkcs:
            ckMechanism = {CKM_RSA_PKCS, nullptr, 0};
            break;
        case WrapMechanism::RsaOaep:
            oaepParams = {CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr, 0};
            ckMechanism = {CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams)};
            break;
    }

    CK_ULONG wrappedLen = 0;
    CK_RV rv = functions->C_WrapKey(session, &ckMechanism, wrappingKey, keyToWrap, nullptr, &wrappedLen);
    if (rv != CKR_OK) {
        throw std::runtime_error("C_WrapKey (sizing) failed: " + std::to_string(rv));
    }

    result.wrappedKey.resize(wrappedLen);
    rv = functions->C_WrapKey(session, &ckMechanism, wrappingKey, keyToWrap, result.wrappedKey.data(), &wrappedLen);
    if (rv != CKR_OK) {
        throw std::runtime_error("C_WrapKey failed: " + std::to_string(rv));
    }
    result.wrappedKey.resize(wrappedLen);
    return result;
}

CK_OBJECT_HANDLE KeyTransport::unwrapKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                          const WrapResult& wrapped, CK_OBJECT_HANDLE unwrappingKey,
                                          const std::string& newLabel) const {
    CK_MECHANISM ckMechanism{};
    static CK_RSA_PKCS_OAEP_PARAMS oaepParams;

    switch (wrapped.mechanism) {
        case WrapMechanism::AesKeyWrap:
            ckMechanism = {CKM_AES_KEY_WRAP, nullptr, 0};
            break;
        case WrapMechanism::AesCbcPad:
            ckMechanism = {CKM_AES_CBC_PAD, const_cast<CK_BYTE*>(wrapped.iv.data()),
                            static_cast<CK_ULONG>(wrapped.iv.size())};
            break;
        case WrapMechanism::RsaPkcs:
            ckMechanism = {CKM_RSA_PKCS, nullptr, 0};
            break;
        case WrapMechanism::RsaOaep:
            oaepParams = {CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr, 0};
            ckMechanism = {CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams)};
            break;
    }

    std::vector<CK_ATTRIBUTE> unwrapTemplate = wrapped.keyTemplate;
    std::string labelStorage = newLabel;
    if (!newLabel.empty()) {
        bool replaced = false;
        for (auto& attr : unwrapTemplate) {
            if (attr.type == CKA_LABEL) {
                attr.pValue = labelStorage.data();
                attr.ulValueLen = static_cast<CK_ULONG>(labelStorage.size());
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            unwrapTemplate.push_back({CKA_LABEL, labelStorage.data(), static_cast<CK_ULONG>(labelStorage.size())});
        }
    }

    CK_OBJECT_HANDLE unwrappedKey;
    CK_RV rv = functions->C_UnwrapKey(session, &ckMechanism, unwrappingKey,
                                       const_cast<CK_BYTE*>(wrapped.wrappedKey.data()),
                                       static_cast<CK_ULONG>(wrapped.wrappedKey.size()), unwrapTemplate.data(),
                                       static_cast<CK_ULONG>(unwrapTemplate.size()), &unwrappedKey);
    if (rv != CKR_OK) {
        throw std::runtime_error("C_UnwrapKey failed: " + std::to_string(rv));
    }
    return unwrappedKey;
}

}  // namespace pkcs11cpp
