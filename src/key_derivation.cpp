#include "pkcs11cpp/key_derivation.h"

#include <stdexcept>

namespace pkcs11cpp {

std::vector<CK_ATTRIBUTE> KeyDerivation::buildDerivedKeyTemplate(const DerivationParams& params,
                                                                   std::vector<std::vector<CK_BYTE>>& storage) {
    std::vector<CK_ATTRIBUTE> tmpl;

    auto addUlong = [&](CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
        storage.emplace_back(reinterpret_cast<CK_BYTE*>(&value), reinterpret_cast<CK_BYTE*>(&value) + sizeof(value));
        tmpl.push_back({type, storage.back().data(), static_cast<CK_ULONG>(storage.back().size())});
    };
    auto addBool = [&](CK_ATTRIBUTE_TYPE type, bool value) {
        CK_BBOOL v = value ? CK_TRUE : CK_FALSE;
        storage.emplace_back(1, v);
        tmpl.push_back({type, storage.back().data(), 1});
    };

    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    addUlong(CKA_CLASS, keyClass);
    addUlong(CKA_KEY_TYPE, params.derivedKeyType);
    addUlong(CKA_VALUE_LEN, params.derivedKeyLengthBytes);
    addBool(CKA_TOKEN, true);
    addBool(CKA_SENSITIVE, params.sensitive);
    addBool(CKA_EXTRACTABLE, params.extractable);
    if (params.canEncrypt) addBool(CKA_ENCRYPT, true);
    if (params.canDecrypt) addBool(CKA_DECRYPT, true);

    if (!params.derivedKeyLabel.empty()) {
        storage.emplace_back(params.derivedKeyLabel.begin(), params.derivedKeyLabel.end());
        tmpl.push_back({CKA_LABEL, storage.back().data(), static_cast<CK_ULONG>(storage.back().size())});
    }
    if (!params.derivedKeyId.empty()) {
        storage.push_back(params.derivedKeyId);
        tmpl.push_back({CKA_ID, storage.back().data(), static_cast<CK_ULONG>(storage.back().size())});
    }
    return tmpl;
}

CK_OBJECT_HANDLE KeyDerivation::deriveEcdhKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                               const DerivationParams& params) const {
    if (params.kdfType != KdfType::Ecdh1Derive) {
        throw std::invalid_argument("deriveEcdhKey: params.kdfType must be Ecdh1Derive");
    }

    CK_ECDH1_DERIVE_PARAMS ecdhParams{};
    ecdhParams.kdf = CKD_NULL;
    ecdhParams.ulSharedDataLen = 0;
    ecdhParams.pSharedData = nullptr;
    ecdhParams.ulPublicDataLen = static_cast<CK_ULONG>(params.peerPublicKey.size());
    ecdhParams.pPublicData = const_cast<CK_BYTE*>(params.peerPublicKey.data());

    CK_MECHANISM mechanism = {CKM_ECDH1_DERIVE, &ecdhParams, sizeof(ecdhParams)};

    std::vector<std::vector<CK_BYTE>> storage;
    auto tmpl = buildDerivedKeyTemplate(params, storage);

    CK_OBJECT_HANDLE derivedKey;
    CK_RV rv = functions->C_DeriveKey(session, &mechanism, params.baseKey, tmpl.data(),
                                       static_cast<CK_ULONG>(tmpl.size()), &derivedKey);
    if (rv != CKR_OK) {
        throw std::runtime_error("ECDH C_DeriveKey failed: " + std::to_string(rv));
    }
    return derivedKey;
}

CK_OBJECT_HANDLE KeyDerivation::deriveSp800_108Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                    const DerivationParams& params) const {
    if (params.kdfType != KdfType::Sp800_108CounterKdf) {
        throw std::invalid_argument("deriveSp800_108Key: params.kdfType must be Sp800_108CounterKdf");
    }

    // Concatenate label || 0x00 || context as the KDF's fixed input data,
    // per NIST SP 800-108's counter-mode construction.
    std::vector<CK_BYTE> fixedData;
    fixedData.insert(fixedData.end(), params.label.begin(), params.label.end());
    fixedData.push_back(0x00);
    fixedData.insert(fixedData.end(), params.context.begin(), params.context.end());

    CK_SP800_108_KDF_PARAMS kdfParams{};
    kdfParams.macType = CKM_AES_CMAC;
    kdfParams.ulNumberOfDataParams = 0;
    kdfParams.pDataParams = nullptr;
    kdfParams.ulAdditionalDerivedKeys = 0;
    kdfParams.pAdditionalDerivedKeys = nullptr;

    CK_MECHANISM mechanism = {CKM_SP800_108_COUNTER_KDF, &kdfParams, sizeof(kdfParams)};

    std::vector<std::vector<CK_BYTE>> storage;
    auto tmpl = buildDerivedKeyTemplate(params, storage);

    CK_OBJECT_HANDLE derivedKey;
    CK_RV rv = functions->C_DeriveKey(session, &mechanism, params.baseKey, tmpl.data(),
                                       static_cast<CK_ULONG>(tmpl.size()), &derivedKey);
    if (rv != CKR_OK) {
        throw std::runtime_error("SP800-108 C_DeriveKey failed: " + std::to_string(rv));
    }
    return derivedKey;
}

CK_OBJECT_HANDLE KeyDerivation::derivePbkdf2Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                 const DerivationParams& params) const {
    if (params.kdfType != KdfType::Pbkdf2) {
        throw std::invalid_argument("derivePbkdf2Key: params.kdfType must be Pbkdf2");
    }

    CK_PKCS5_PBKD2_PARAMS pbkdf2Params{};
    pbkdf2Params.saltSource = CKZ_SALT_SPECIFIED;
    pbkdf2Params.pSaltSourceData = const_cast<CK_BYTE*>(params.salt.data());
    pbkdf2Params.ulSaltSourceDataLen = static_cast<CK_ULONG>(params.salt.size());
    pbkdf2Params.iterations = params.iterations;
    pbkdf2Params.prf = params.prf;
    pbkdf2Params.pPrfData = nullptr;
    pbkdf2Params.ulPrfDataLen = 0;
    pbkdf2Params.pPassword = reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(params.password.c_str()));
    pbkdf2Params.ulPasswordLen = static_cast<CK_ULONG>(params.password.length());

    CK_MECHANISM mechanism = {CKM_PKCS5_PBKD2, &pbkdf2Params, sizeof(pbkdf2Params)};

    std::vector<std::vector<CK_BYTE>> storage;
    auto tmpl = buildDerivedKeyTemplate(params, storage);

    // PBKDF2 derives from a password, not an existing key object.
    CK_OBJECT_HANDLE derivedKey;
    CK_RV rv = functions->C_DeriveKey(session, &mechanism, CK_INVALID_HANDLE, tmpl.data(),
                                       static_cast<CK_ULONG>(tmpl.size()), &derivedKey);
    if (rv != CKR_OK) {
        throw std::runtime_error("PBKDF2 C_DeriveKey failed: " + std::to_string(rv));
    }
    return derivedKey;
}

std::vector<CK_OBJECT_HANDLE> KeyDerivation::deriveKeyChain(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                              CK_OBJECT_HANDLE masterKey,
                                                              const std::vector<DerivationParams>& chain) const {
    std::vector<CK_OBJECT_HANDLE> derivedKeys;
    derivedKeys.reserve(chain.size());
    CK_OBJECT_HANDLE currentKey = masterKey;

    for (const auto& step : chain) {
        DerivationParams stepParams = step;
        stepParams.baseKey = currentKey;

        CK_OBJECT_HANDLE derived;
        switch (step.kdfType) {
            case KdfType::Ecdh1Derive:
                derived = deriveEcdhKey(session, functions, stepParams);
                break;
            case KdfType::Sp800_108CounterKdf:
                derived = deriveSp800_108Key(session, functions, stepParams);
                break;
            case KdfType::Pbkdf2:
                derived = derivePbkdf2Key(session, functions, stepParams);
                break;
            default:
                throw std::invalid_argument("deriveKeyChain: unsupported KDF type in chain");
        }
        derivedKeys.push_back(derived);
        currentKey = derived;
    }
    return derivedKeys;
}

}  // namespace pkcs11cpp
