#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "pkcs11cpp/attribute_manager.h"
#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Generates key pairs and secret keys on the token, translating a small,
// friendly KeyAlgorithm enum into the right mechanism + CK_ATTRIBUTE
// template for each algorithm family (RSA / EC / AES / 3DES).
class KeyManager {
public:
    enum class KeyAlgorithm {
        RSA_2048, RSA_3072, RSA_4096,
        ECDSA_P256, ECDSA_P384, ECDSA_P521,
        AES_128, AES_192, AES_256,
        DES3,
    };

    struct KeyGenerationParams {
        KeyAlgorithm algorithm;
        std::string label;
        std::vector<CK_BYTE> id;
        bool tokenKey = true;
        bool sensitive = true;
        bool extractable = false;

        bool canSign = false;
        bool canVerify = false;
        bool canEncrypt = false;
        bool canDecrypt = false;
        bool canWrap = false;
        bool canUnwrap = false;
        bool canDerive = false;

        std::optional<std::vector<CK_BYTE>> publicExponent;  // RSA only
        std::optional<std::vector<CK_BYTE>> ecParams;         // EC only, DER-encoded OID; auto-filled if absent
    };

    struct KeyPair {
        CK_OBJECT_HANDLE publicKey;
        CK_OBJECT_HANDLE privateKey;
        KeyAlgorithm algorithm;
        std::string label;
    };

    KeyPair generateKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                             const KeyGenerationParams& params) const;

    CK_OBJECT_HANDLE generateSecretKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                        const KeyGenerationParams& params) const;

    static bool isSecretKeyAlgorithm(KeyAlgorithm algorithm);
    static bool isKeyPairAlgorithm(KeyAlgorithm algorithm);

private:
    static void addCommonKeyAttributes(const KeyGenerationParams& params, AttributeManager::AttributeSet& publicSet,
                                        AttributeManager::AttributeSet& privateSet);

    KeyPair generateRsaKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                const KeyGenerationParams& params) const;
    KeyPair generateEcKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                               const KeyGenerationParams& params) const;
    CK_OBJECT_HANDLE generateAesKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                     const KeyGenerationParams& params) const;
    CK_OBJECT_HANDLE generateDes3Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                      const KeyGenerationParams& params) const;
};

}  // namespace pkcs11cpp
