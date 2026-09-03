#include "pkcs11cpp/key_manager.h"

#include <stdexcept>

namespace pkcs11cpp {

namespace {
// DER-encoded OIDs for the three NIST curves this repo supports, used as
// the default CKA_EC_PARAMS value when the caller doesn't supply one.
std::vector<CK_BYTE> defaultEcParams(KeyManager::KeyAlgorithm algorithm) {
    switch (algorithm) {
        case KeyManager::KeyAlgorithm::ECDSA_P256:
            return {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};  // secp256r1
        case KeyManager::KeyAlgorithm::ECDSA_P384:
            return {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};  // secp384r1
        case KeyManager::KeyAlgorithm::ECDSA_P521:
            return {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};  // secp521r1
        default:
            throw std::invalid_argument("defaultEcParams: not an EC algorithm");
    }
}

CK_ULONG rsaModulusBits(KeyManager::KeyAlgorithm algorithm) {
    switch (algorithm) {
        case KeyManager::KeyAlgorithm::RSA_2048: return 2048;
        case KeyManager::KeyAlgorithm::RSA_3072: return 3072;
        case KeyManager::KeyAlgorithm::RSA_4096: return 4096;
        default: throw std::invalid_argument("rsaModulusBits: not an RSA algorithm");
    }
}

CK_ULONG aesKeyBits(KeyManager::KeyAlgorithm algorithm) {
    switch (algorithm) {
        case KeyManager::KeyAlgorithm::AES_128: return 128;
        case KeyManager::KeyAlgorithm::AES_192: return 192;
        case KeyManager::KeyAlgorithm::AES_256: return 256;
        default: throw std::invalid_argument("aesKeyBits: not an AES algorithm");
    }
}
}  // namespace

void KeyManager::addCommonKeyAttributes(const KeyGenerationParams& params, AttributeManager::AttributeSet& publicSet,
                                         AttributeManager::AttributeSet& privateSet) {
    if (params.tokenKey) {
        publicSet.addBoolean(CKA_TOKEN, true);
        privateSet.addBoolean(CKA_TOKEN, true);
    }
    privateSet.addBoolean(CKA_SENSITIVE, params.sensitive);
    privateSet.addBoolean(CKA_EXTRACTABLE, params.extractable);

    if (!params.label.empty()) {
        publicSet.addString(CKA_LABEL, params.label);
        privateSet.addString(CKA_LABEL, params.label);
    }
    if (!params.id.empty()) {
        publicSet.addBytes(CKA_ID, params.id);
        privateSet.addBytes(CKA_ID, params.id);
    }
}

KeyManager::KeyPair KeyManager::generateRsaKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                    const KeyGenerationParams& params) const {
    AttributeManager::AttributeSet publicSet, privateSet;

    std::vector<CK_BYTE> publicExponent = params.publicExponent.value_or(std::vector<CK_BYTE>{0x01, 0x00, 0x01});
    publicSet.addULong(CKA_CLASS, CKO_PUBLIC_KEY)
        .addULong(CKA_KEY_TYPE, CKK_RSA)
        .addULong(CKA_MODULUS_BITS, rsaModulusBits(params.algorithm))
        .addBytes(CKA_PUBLIC_EXPONENT, publicExponent);
    if (params.canVerify) publicSet.addBoolean(CKA_VERIFY, true);
    if (params.canEncrypt) publicSet.addBoolean(CKA_ENCRYPT, true);

    privateSet.addULong(CKA_CLASS, CKO_PRIVATE_KEY).addULong(CKA_KEY_TYPE, CKK_RSA);
    if (params.canSign) privateSet.addBoolean(CKA_SIGN, true);
    if (params.canDecrypt) privateSet.addBoolean(CKA_DECRYPT, true);

    addCommonKeyAttributes(params, publicSet, privateSet);

    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_RV rv = functions->C_GenerateKeyPair(session, &mechanism, publicSet.data(),
                                             static_cast<CK_ULONG>(publicSet.size()), privateSet.data(),
                                             static_cast<CK_ULONG>(privateSet.size()), &publicKey, &privateKey);
    if (rv != CKR_OK) {
        throw std::runtime_error("RSA C_GenerateKeyPair failed: " + std::to_string(rv));
    }
    return KeyPair{publicKey, privateKey, params.algorithm, params.label};
}

KeyManager::KeyPair KeyManager::generateEcKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                   const KeyGenerationParams& params) const {
    AttributeManager::AttributeSet publicSet, privateSet;
    std::vector<CK_BYTE> ecParams = params.ecParams.value_or(defaultEcParams(params.algorithm));

    publicSet.addULong(CKA_CLASS, CKO_PUBLIC_KEY).addULong(CKA_KEY_TYPE, CKK_ECDSA).addBytes(CKA_EC_PARAMS, ecParams);
    if (params.canVerify) publicSet.addBoolean(CKA_VERIFY, true);

    privateSet.addULong(CKA_CLASS, CKO_PRIVATE_KEY).addULong(CKA_KEY_TYPE, CKK_ECDSA);
    if (params.canSign) privateSet.addBoolean(CKA_SIGN, true);
    if (params.canDerive) privateSet.addBoolean(CKA_DERIVE, true);

    addCommonKeyAttributes(params, publicSet, privateSet);

    CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_RV rv = functions->C_GenerateKeyPair(session, &mechanism, publicSet.data(),
                                             static_cast<CK_ULONG>(publicSet.size()), privateSet.data(),
                                             static_cast<CK_ULONG>(privateSet.size()), &publicKey, &privateKey);
    if (rv != CKR_OK) {
        throw std::runtime_error("EC C_GenerateKeyPair failed: " + std::to_string(rv));
    }
    return KeyPair{publicKey, privateKey, params.algorithm, params.label};
}

KeyManager::KeyPair KeyManager::generateKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                 const KeyGenerationParams& params) const {
    switch (params.algorithm) {
        case KeyAlgorithm::RSA_2048:
        case KeyAlgorithm::RSA_3072:
        case KeyAlgorithm::RSA_4096:
            return generateRsaKeyPair(session, functions, params);
        case KeyAlgorithm::ECDSA_P256:
        case KeyAlgorithm::ECDSA_P384:
        case KeyAlgorithm::ECDSA_P521:
            return generateEcKeyPair(session, functions, params);
        default:
            throw std::invalid_argument("generateKeyPair: algorithm is not a key-pair algorithm");
    }
}

CK_OBJECT_HANDLE KeyManager::generateAesKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                             const KeyGenerationParams& params) const {
    AttributeManager::AttributeSet keySet;
    keySet.addULong(CKA_CLASS, CKO_SECRET_KEY)
        .addULong(CKA_KEY_TYPE, CKK_AES)
        .addULong(CKA_VALUE_LEN, aesKeyBits(params.algorithm) / 8)
        .addBoolean(CKA_SENSITIVE, params.sensitive)
        .addBoolean(CKA_EXTRACTABLE, params.extractable);
    if (params.tokenKey) keySet.addBoolean(CKA_TOKEN, true);
    if (params.canEncrypt) keySet.addBoolean(CKA_ENCRYPT, true);
    if (params.canDecrypt) keySet.addBoolean(CKA_DECRYPT, true);
    if (params.canWrap) keySet.addBoolean(CKA_WRAP, true);
    if (params.canUnwrap) keySet.addBoolean(CKA_UNWRAP, true);
    if (!params.label.empty()) keySet.addString(CKA_LABEL, params.label);
    if (!params.id.empty()) keySet.addBytes(CKA_ID, params.id);

    CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, nullptr, 0};
    CK_OBJECT_HANDLE key;
    CK_RV rv =
        functions->C_GenerateKey(session, &mechanism, keySet.data(), static_cast<CK_ULONG>(keySet.size()), &key);
    if (rv != CKR_OK) {
        throw std::runtime_error("AES C_GenerateKey failed: " + std::to_string(rv));
    }
    return key;
}

CK_OBJECT_HANDLE KeyManager::generateDes3Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                              const KeyGenerationParams& params) const {
    AttributeManager::AttributeSet keySet;
    // CKK_DES3 isn't in this project's minimal type subset (3DES is
    // deprecated and none of the other modules reference it) -- rather
    // than silently mislabel the key type, this stays explicit about the
    // limitation instead of generating a key tagged as the wrong algorithm.
    (void)session;
    (void)functions;
    (void)params;
    (void)keySet;
    throw std::runtime_error(
        "generateSecretKey: DES3 is deprecated and intentionally unsupported by this mock/demo build; "
        "add CKK_DES3/CKM_DES3_KEY_GEN to pkcs11cpp::types if you need it against a real module.");
}

CK_OBJECT_HANDLE KeyManager::generateSecretKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                const KeyGenerationParams& params) const {
    switch (params.algorithm) {
        case KeyAlgorithm::AES_128:
        case KeyAlgorithm::AES_192:
        case KeyAlgorithm::AES_256:
            return generateAesKey(session, functions, params);
        case KeyAlgorithm::DES3:
            return generateDes3Key(session, functions, params);
        default:
            throw std::invalid_argument("generateSecretKey: algorithm is not a secret-key algorithm");
    }
}

bool KeyManager::isSecretKeyAlgorithm(KeyAlgorithm algorithm) {
    return algorithm == KeyAlgorithm::AES_128 || algorithm == KeyAlgorithm::AES_192 ||
           algorithm == KeyAlgorithm::AES_256 || algorithm == KeyAlgorithm::DES3;
}

bool KeyManager::isKeyPairAlgorithm(KeyAlgorithm algorithm) {
    return algorithm == KeyAlgorithm::RSA_2048 || algorithm == KeyAlgorithm::RSA_3072 ||
           algorithm == KeyAlgorithm::RSA_4096 || algorithm == KeyAlgorithm::ECDSA_P256 ||
           algorithm == KeyAlgorithm::ECDSA_P384 || algorithm == KeyAlgorithm::ECDSA_P521;
}

}  // namespace pkcs11cpp
