#pragma once

#include <string>
#include <vector>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Wraps a key under another key for export/transport (C_WrapKey) and
// reverses the process on the receiving side (C_UnwrapKey), carrying
// along enough of the original key's attribute template that the
// unwrapped copy comes back with the same class/type/usage flags.
class KeyTransport {
public:
    enum class WrapMechanism { AesKeyWrap, AesCbcPad, RsaPkcs, RsaOaep };

    struct WrapResult {
        std::vector<CK_BYTE> wrappedKey;
        WrapMechanism mechanism;
        std::vector<CK_BYTE> iv;  // only populated for AesCbcPad
        std::vector<CK_ATTRIBUTE> keyTemplate;
        std::vector<std::vector<CK_BYTE>> templateStorage;  // keeps keyTemplate's pointers alive
    };

    WrapResult wrapKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions, CK_OBJECT_HANDLE keyToWrap,
                        CK_OBJECT_HANDLE wrappingKey, WrapMechanism mechanism = WrapMechanism::AesKeyWrap) const;

    CK_OBJECT_HANDLE unwrapKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions, const WrapResult& wrapped,
                                CK_OBJECT_HANDLE unwrappingKey, const std::string& newLabel = "") const;

private:
    static std::vector<CK_BYTE> generateRandomBytes(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                      std::size_t length);
    static WrapResult extractKeyTemplate(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                          CK_OBJECT_HANDLE keyHandle);
};

}  // namespace pkcs11cpp
