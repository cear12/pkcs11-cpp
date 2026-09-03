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
        kRsa2048, kRsa3072, kRsa4096,
        kEcdsaP256, kEcdsaP384, kEcdsaP521,
        kAes128, kAes192, kAes256,
        kDeS3,
    };

    struct KeyGenerationParams {
        KeyAlgorithm algorithm_;
        std::string label_;
        std::vector<CK_BYTE> id_;
        bool token_key_ = true;
        bool sensitive_ = true;
        bool extractable_ = false;

        bool can_sign_ = false;
        bool can_verify_ = false;
        bool can_encrypt_ = false;
        bool can_decrypt_ = false;
        bool can_wrap_ = false;
        bool can_unwrap_ = false;
        bool can_derive_ = false;

        std::optional<std::vector<CK_BYTE>> public_exponent_;  // RSA only
        std::optional<std::vector<CK_BYTE>> ec_params_;         // EC only, DER-encoded OID; auto-filled if absent
    };

    struct KeyPair {
        CK_OBJECT_HANDLE public_key_;
        CK_OBJECT_HANDLE private_key_;
        KeyAlgorithm algorithm_;
        std::string label_;
    };

    KeyPair GenerateKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                             const KeyGenerationParams& params) const;

    CK_OBJECT_HANDLE GenerateSecretKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                        const KeyGenerationParams& params) const;

    static bool IsSecretKeyAlgorithm(KeyAlgorithm algorithm);
    static bool IsKeyPairAlgorithm(KeyAlgorithm algorithm);

private:
    static void AddCommonKeyAttributes(const KeyGenerationParams& params, AttributeManager::AttributeSet& public_set,
                                        AttributeManager::AttributeSet& private_set);

    KeyPair GenerateRsaKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                const KeyGenerationParams& params) const;
    KeyPair GenerateEcKeyPair(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                               const KeyGenerationParams& params) const;
    CK_OBJECT_HANDLE GenerateAesKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                     const KeyGenerationParams& params) const;
    CK_OBJECT_HANDLE GenerateDes3Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                      const KeyGenerationParams& params) const;
};

}  // namespace pkcs11cpp
