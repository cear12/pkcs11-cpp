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
    enum class KdfType { Ecdh1Derive, Sp800_108CounterKdf, Pbkdf2 };

    struct DerivationParams {
        KdfType kdfType;
        CK_OBJECT_HANDLE baseKey = CK_INVALID_HANDLE;

        // ECDH
        std::vector<CK_BYTE> peerPublicKey;

        // SP800-108
        std::vector<CK_BYTE> label;
        std::vector<CK_BYTE> context;

        // PBKDF2
        std::vector<CK_BYTE> salt;
        CK_ULONG iterations = 100000;
        CK_MECHANISM_TYPE prf = CKM_SHA256_HMAC;
        std::string password;

        // Derived-key shape
        CK_KEY_TYPE derivedKeyType = CKK_AES;
        CK_ULONG derivedKeyLengthBytes = 32;
        std::string derivedKeyLabel;
        std::vector<CK_BYTE> derivedKeyId;
        bool sensitive = true;
        bool extractable = false;
        bool canEncrypt = true;
        bool canDecrypt = true;
    };

    CK_OBJECT_HANDLE deriveEcdhKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                    const DerivationParams& params) const;
    CK_OBJECT_HANDLE deriveSp800_108Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                         const DerivationParams& params) const;
    CK_OBJECT_HANDLE derivePbkdf2Key(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                      const DerivationParams& params) const;

    // Derives a chain of keys, each one from the previous: params[0] is
    // derived from masterKey, params[1] from params[0]'s result, etc.
    std::vector<CK_OBJECT_HANDLE> deriveKeyChain(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                  CK_OBJECT_HANDLE masterKey,
                                                  const std::vector<DerivationParams>& chain) const;

private:
    static std::vector<CK_ATTRIBUTE> buildDerivedKeyTemplate(const DerivationParams& params,
                                                               std::vector<std::vector<CK_BYTE>>& storage);
};

}  // namespace pkcs11cpp
