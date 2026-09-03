#include "pkcs11cpp/key_transport.h"

#include <array>
#include <stdexcept>

namespace pkcs11cpp {

namespace {
constexpr std::array<CK_ATTRIBUTE_TYPE, 12> kTransportAttributeTypes = {
    CKA_CLASS,     CKA_KEY_TYPE,    CKA_TOKEN, CKA_PRIVATE,
    CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_SIGN,  CKA_VERIFY,
    CKA_ENCRYPT,   CKA_DECRYPT,     CKA_WRAP,  CKA_UNWRAP,
};
}  // namespace

std::vector<CK_BYTE> KeyTransport::GenerateRandomBytes(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    std::size_t length) {
  std::vector<CK_BYTE> data(length);
  CK_RV rv = functions->C_GenerateRandom(session, data.data(),
                                         static_cast<CK_ULONG>(length));
  if (rv != CKR_OK) {
    throw std::runtime_error("C_GenerateRandom failed: " + std::to_string(rv));
  }
  return data;
}

KeyTransport::WrapResult KeyTransport::ExtractKeyTemplate(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    CK_OBJECT_HANDLE key_handle) {
  std::vector<CK_ATTRIBUTE> probe;
  probe.reserve(kTransportAttributeTypes.size());
  for (auto type : kTransportAttributeTypes)
    probe.push_back({type, nullptr, 0});

  functions->C_GetAttributeValue(session, key_handle, probe.data(),
                                 static_cast<CK_ULONG>(probe.size()));

  WrapResult result;
  result.template_storage_.resize(probe.size());
  for (size_t i = 0; i < probe.size(); ++i) {
    if (probe[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) continue;
    result.template_storage_[i].resize(probe[i].ulValueLen);
    probe[i].pValue = result.template_storage_[i].data();
  }

  CK_RV rv = functions->C_GetAttributeValue(
      session, key_handle, probe.data(), static_cast<CK_ULONG>(probe.size()));
  if (rv != CKR_OK) {
    throw std::runtime_error(
        "C_GetAttributeValue failed while extracting key template: " +
        std::to_string(rv));
  }

  for (size_t i = 0; i < probe.size(); ++i) {
    if (probe[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) continue;
    result.key_template_.push_back(probe[i]);
  }
  return result;
}

KeyTransport::WrapResult KeyTransport::WrapKey(CK_SESSION_HANDLE session,
                                               CK_FUNCTION_LIST_PTR functions,
                                               CK_OBJECT_HANDLE key_to_wrap,
                                               CK_OBJECT_HANDLE wrapping_key,
                                               WrapMechanism mechanism) const {
  WrapResult result = ExtractKeyTemplate(session, functions, key_to_wrap);
  result.mechanism_ = mechanism;

  CK_MECHANISM ck_mechanism{};
  static CK_RSA_PKCS_OAEP_PARAMS oaep_params;

  switch (mechanism) {
    case WrapMechanism::kAesKeyWrap:
      ck_mechanism = {CKM_AES_KEY_WRAP, nullptr, 0};
      break;
    case WrapMechanism::kAesCbcPad:
      result.iv_ = GenerateRandomBytes(session, functions, 16);
      ck_mechanism = {CKM_AES_CBC_PAD, result.iv_.data(),
                      static_cast<CK_ULONG>(result.iv_.size())};
      break;
    case WrapMechanism::kRsaPkcs:
      ck_mechanism = {CKM_RSA_PKCS, nullptr, 0};
      break;
    case WrapMechanism::kRsaOaep:
      oaep_params = {CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr,
                     0};
      ck_mechanism = {CKM_RSA_PKCS_OAEP, &oaep_params, sizeof(oaep_params)};
      break;
  }

  CK_ULONG wrapped_len = 0;
  CK_RV rv = functions->C_WrapKey(session, &ck_mechanism, wrapping_key,
                                  key_to_wrap, nullptr, &wrapped_len);
  if (rv != CKR_OK) {
    throw std::runtime_error("C_WrapKey (sizing) failed: " +
                             std::to_string(rv));
  }

  result.wrapped_key_.resize(wrapped_len);
  rv = functions->C_WrapKey(session, &ck_mechanism, wrapping_key, key_to_wrap,
                            result.wrapped_key_.data(), &wrapped_len);
  if (rv != CKR_OK) {
    throw std::runtime_error("C_WrapKey failed: " + std::to_string(rv));
  }
  result.wrapped_key_.resize(wrapped_len);
  return result;
}

CK_OBJECT_HANDLE KeyTransport::UnwrapKey(CK_SESSION_HANDLE session,
                                         CK_FUNCTION_LIST_PTR functions,
                                         const WrapResult& wrapped,
                                         CK_OBJECT_HANDLE unwrapping_key,
                                         const std::string& new_label) const {
  CK_MECHANISM ck_mechanism{};
  static CK_RSA_PKCS_OAEP_PARAMS oaep_params;

  switch (wrapped.mechanism_) {
    case WrapMechanism::kAesKeyWrap:
      ck_mechanism = {CKM_AES_KEY_WRAP, nullptr, 0};
      break;
    case WrapMechanism::kAesCbcPad:
      ck_mechanism = {CKM_AES_CBC_PAD, const_cast<CK_BYTE*>(wrapped.iv_.data()),
                      static_cast<CK_ULONG>(wrapped.iv_.size())};
      break;
    case WrapMechanism::kRsaPkcs:
      ck_mechanism = {CKM_RSA_PKCS, nullptr, 0};
      break;
    case WrapMechanism::kRsaOaep:
      oaep_params = {CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr,
                     0};
      ck_mechanism = {CKM_RSA_PKCS_OAEP, &oaep_params, sizeof(oaep_params)};
      break;
  }

  std::vector<CK_ATTRIBUTE> unwrap_template = wrapped.key_template_;
  std::string label_storage = new_label;
  if (!new_label.empty()) {
    bool replaced = false;
    for (auto& attr : unwrap_template) {
      if (attr.type == CKA_LABEL) {
        attr.pValue = label_storage.data();
        attr.ulValueLen = static_cast<CK_ULONG>(label_storage.size());
        replaced = true;
        break;
      }
    }
    if (!replaced) {
      unwrap_template.push_back({CKA_LABEL, label_storage.data(),
                                 static_cast<CK_ULONG>(label_storage.size())});
    }
  }

  CK_OBJECT_HANDLE unwrapped_key;
  CK_RV rv = functions->C_UnwrapKey(
      session, &ck_mechanism, unwrapping_key,
      const_cast<CK_BYTE*>(wrapped.wrapped_key_.data()),
      static_cast<CK_ULONG>(wrapped.wrapped_key_.size()),
      unwrap_template.data(), static_cast<CK_ULONG>(unwrap_template.size()),
      &unwrapped_key);
  if (rv != CKR_OK) {
    throw std::runtime_error("C_UnwrapKey failed: " + std::to_string(rv));
  }
  return unwrapped_key;
}

}  // namespace pkcs11cpp
