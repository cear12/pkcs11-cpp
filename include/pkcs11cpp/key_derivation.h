#pragma once

#include <string>
#include <vector>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Key-derivation-function (KDF) helpers on top of C_DeriveKey: ECDH key
// agreement, SP800-108 counter-mode KDF, PBKDF2, and chaining several
// derivations together (e.g. ECDH shared secret -> SP800-108 -> final
// session keys).
class KeyDerivation {
public:
    enum class KdfType { kEcdh1Derive, kSp800108CounterKdf, kPbkdf2 };

    struct DerivationParams {
        KdfType kdf_type_;
        CK_OBJECT_HANDLE base_key_ = CK_INVALID_HANDLE;

        // ECDH
        std::vector<CK_BYTE> peer_public_key_;

        // SP800-108
        std::vector<CK_BYTE> label_;
        std::vector<CK_BYTE> context_;

        // PBKDF2
        std::vector<CK_BYTE> salt_;
        CK_ULONG iterations_ = 100000;
        CK_MECHANISM_TYPE prf_ = CKM_SHA256_HMAC;
        std::string password_;

        // Derived-key shape
        CK_KEY_TYPE derived_key_type_ = CKK_AES;
        CK_ULONG derived_key_length_bytes_ = 32;
        std::string derived_key_label_;
        std::vector<CK_BYTE> derived_key_id_;
        bool sensitive_ = true;
        bool extractable_ = false;
        bool can_encrypt_ = true;
        bool can_decrypt_ = true;
    };

    CK_OBJECT_HANDLE DeriveEcdhKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                    const DerivationParams& params) const;
    CK_OBJECT_HANDLE DeriveSp800108Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                         const DerivationParams& params) const;
    CK_OBJECT_HANDLE DerivePbkdf2Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                      const DerivationParams& params) const;

    // Derives a chain of keys, each one from the previous: params[0] is
    // derived from masterKey, params[1] from params[0]'s result, etc.
    std::vector<CK_OBJECT_HANDLE> DeriveKeyChain(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                  CK_OBJECT_HANDLE master_key,
                                                  const std::vector<DerivationParams>& chain) const;

private:
    static std::vector<CK_ATTRIBUTE> BuildDerivedKeyTemplate(const DerivationParams& params,
                                                               std::vector<std::vector<CK_BYTE>>& storage);
};

}  // namespace pkcs11cpp
