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
  enum class WrapMechanism { kAesKeyWrap, kAesCbcPad, kRsaPkcs, kRsaOaep };

  struct WrapResult {
    std::vector<CK_BYTE> wrapped_key_;
    WrapMechanism mechanism_;
    std::vector<CK_BYTE> iv_;  // only populated for AesCbcPad
    std::vector<CK_ATTRIBUTE> key_template_;
    std::vector<std::vector<CK_BYTE>>
        template_storage_;  // keeps keyTemplate's pointers alive
  };

  WrapResult WrapKey(
      CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
      CK_OBJECT_HANDLE key_to_wrap, CK_OBJECT_HANDLE wrapping_key,
      WrapMechanism mechanism = WrapMechanism::kAesKeyWrap) const;

  CK_OBJECT_HANDLE UnwrapKey(CK_SESSION_HANDLE session,
                             CK_FUNCTION_LIST_PTR functions,
                             const WrapResult& wrapped,
                             CK_OBJECT_HANDLE unwrapping_key,
                             const std::string& new_label = "") const;

 private:
  static std::vector<CK_BYTE> GenerateRandomBytes(
      CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
      std::size_t length);
  static WrapResult ExtractKeyTemplate(CK_SESSION_HANDLE session,
                                       CK_FUNCTION_LIST_PTR functions,
                                       CK_OBJECT_HANDLE key_handle);
};

}  // namespace pkcs11cpp
