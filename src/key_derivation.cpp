#include "pkcs11cpp/key_derivation.h"

#include <stdexcept>

namespace pkcs11cpp {

std::vector<CK_ATTRIBUTE> KeyDerivation::BuildDerivedKeyTemplate(
    const DerivationParams& params,
    std::vector<std::vector<CK_BYTE>>& storage) {
  std::vector<CK_ATTRIBUTE> tmpl;

  auto add_ulong = [&](CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
    storage.emplace_back(reinterpret_cast<CK_BYTE*>(&value),
                         reinterpret_cast<CK_BYTE*>(&value) + sizeof(value));
    tmpl.push_back({type, storage.back().data(),
                    static_cast<CK_ULONG>(storage.back().size())});
  };
  auto add_bool = [&](CK_ATTRIBUTE_TYPE type, bool value) {
    CK_BBOOL v = value ? CK_TRUE : CK_FALSE;
    storage.emplace_back(1, v);
    tmpl.push_back({type, storage.back().data(), 1});
  };

  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  add_ulong(CKA_CLASS, key_class);
  add_ulong(CKA_KEY_TYPE, params.derived_key_type_);
  add_ulong(CKA_VALUE_LEN, params.derived_key_length_bytes_);
  add_bool(CKA_TOKEN, true);
  add_bool(CKA_SENSITIVE, params.sensitive_);
  add_bool(CKA_EXTRACTABLE, params.extractable_);
  if (params.can_encrypt_) add_bool(CKA_ENCRYPT, true);
  if (params.can_decrypt_) add_bool(CKA_DECRYPT, true);

  if (!params.derived_key_label_.empty()) {
    storage.emplace_back(params.derived_key_label_.begin(),
                         params.derived_key_label_.end());
    tmpl.push_back({CKA_LABEL, storage.back().data(),
                    static_cast<CK_ULONG>(storage.back().size())});
  }
  if (!params.derived_key_id_.empty()) {
    storage.push_back(params.derived_key_id_);
    tmpl.push_back({CKA_ID, storage.back().data(),
                    static_cast<CK_ULONG>(storage.back().size())});
  }
  return tmpl;
}

CK_OBJECT_HANDLE KeyDerivation::DeriveEcdhKey(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const DerivationParams& params) const {
  if (params.kdf_type_ != KdfType::kEcdh1Derive) {
    throw std::invalid_argument(
        "DeriveEcdhKey: params.kdfType must be Ecdh1Derive");
  }

  CK_ECDH1_DERIVE_PARAMS ecdh_params{};
  ecdh_params.kdf = CKD_NULL;
  ecdh_params.ulSharedDataLen = 0;
  ecdh_params.pSharedData = nullptr;
  ecdh_params.ulPublicDataLen =
      static_cast<CK_ULONG>(params.peer_public_key_.size());
  ecdh_params.pPublicData =
      const_cast<CK_BYTE*>(params.peer_public_key_.data());

  CK_MECHANISM mechanism = {CKM_ECDH1_DERIVE, &ecdh_params,
                            sizeof(ecdh_params)};

  std::vector<std::vector<CK_BYTE>> storage;
  auto tmpl = BuildDerivedKeyTemplate(params, storage);

  CK_OBJECT_HANDLE derived_key;
  CK_RV rv =
      functions->C_DeriveKey(session, &mechanism, params.base_key_, tmpl.data(),
                             static_cast<CK_ULONG>(tmpl.size()), &derived_key);
  if (rv != CKR_OK) {
    throw std::runtime_error("ECDH C_DeriveKey failed: " + std::to_string(rv));
  }
  return derived_key;
}

CK_OBJECT_HANDLE KeyDerivation::DeriveSp800108Key(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const DerivationParams& params) const {
  if (params.kdf_type_ != KdfType::kSp800108CounterKdf) {
    throw std::invalid_argument(
        "DeriveSp800_108Key: params.kdfType must be Sp800_108CounterKdf");
  }

  // Concatenate label || 0x00 || context as the KDF's fixed input data,
  // per NIST SP 800-108's counter-mode construction.
  std::vector<CK_BYTE> fixed_data;
  fixed_data.insert(fixed_data.end(), params.label_.begin(),
                    params.label_.end());
  fixed_data.push_back(0x00);
  fixed_data.insert(fixed_data.end(), params.context_.begin(),
                    params.context_.end());

  CK_SP800_108_KDF_PARAMS kdf_params{};
  kdf_params.macType = CKM_AES_CMAC;
  kdf_params.ulNumberOfDataParams = 0;
  kdf_params.pDataParams = nullptr;
  kdf_params.ulAdditionalDerivedKeys = 0;
  kdf_params.pAdditionalDerivedKeys = nullptr;

  CK_MECHANISM mechanism = {CKM_SP800_108_COUNTER_KDF, &kdf_params,
                            sizeof(kdf_params)};

  std::vector<std::vector<CK_BYTE>> storage;
  auto tmpl = BuildDerivedKeyTemplate(params, storage);

  CK_OBJECT_HANDLE derived_key;
  CK_RV rv =
      functions->C_DeriveKey(session, &mechanism, params.base_key_, tmpl.data(),
                             static_cast<CK_ULONG>(tmpl.size()), &derived_key);
  if (rv != CKR_OK) {
    throw std::runtime_error("SP800-108 C_DeriveKey failed: " +
                             std::to_string(rv));
  }
  return derived_key;
}

CK_OBJECT_HANDLE KeyDerivation::DerivePbkdf2Key(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const DerivationParams& params) const {
  if (params.kdf_type_ != KdfType::kPbkdf2) {
    throw std::invalid_argument(
        "DerivePbkdf2Key: params.kdfType must be Pbkdf2");
  }

  CK_PKCS5_PBKD2_PARAMS pbkdf2_params{};
  pbkdf2_params.saltSource = CKZ_SALT_SPECIFIED;
  pbkdf2_params.pSaltSourceData = const_cast<CK_BYTE*>(params.salt_.data());
  pbkdf2_params.ulSaltSourceDataLen =
      static_cast<CK_ULONG>(params.salt_.size());
  pbkdf2_params.iterations = params.iterations_;
  pbkdf2_params.prf = params.prf_;
  pbkdf2_params.pPrfData = nullptr;
  pbkdf2_params.ulPrfDataLen = 0;
  pbkdf2_params.pPassword = reinterpret_cast<CK_UTF8CHAR_PTR>(
      const_cast<char*>(params.password_.c_str()));
  pbkdf2_params.ulPasswordLen =
      static_cast<CK_ULONG>(params.password_.length());

  CK_MECHANISM mechanism = {CKM_PKCS5_PBKD2, &pbkdf2_params,
                            sizeof(pbkdf2_params)};

  std::vector<std::vector<CK_BYTE>> storage;
  auto tmpl = BuildDerivedKeyTemplate(params, storage);

  // PBKDF2 derives from a password, not an existing key object.
  CK_OBJECT_HANDLE derived_key;
  CK_RV rv = functions->C_DeriveKey(
      session, &mechanism, CK_INVALID_HANDLE, tmpl.data(),
      static_cast<CK_ULONG>(tmpl.size()), &derived_key);
  if (rv != CKR_OK) {
    throw std::runtime_error("PBKDF2 C_DeriveKey failed: " +
                             std::to_string(rv));
  }
  return derived_key;
}

std::vector<CK_OBJECT_HANDLE> KeyDerivation::DeriveKeyChain(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    CK_OBJECT_HANDLE master_key,
    const std::vector<DerivationParams>& chain) const {
  std::vector<CK_OBJECT_HANDLE> derived_keys;
  derived_keys.reserve(chain.size());
  CK_OBJECT_HANDLE current_key = master_key;

  for (const auto& step : chain) {
    DerivationParams step_params = step;
    step_params.base_key_ = current_key;

    CK_OBJECT_HANDLE derived;
    switch (step.kdf_type_) {
      case KdfType::kEcdh1Derive:
        derived = DeriveEcdhKey(session, functions, step_params);
        break;
      case KdfType::kSp800108CounterKdf:
        derived = DeriveSp800108Key(session, functions, step_params);
        break;
      case KdfType::kPbkdf2:
        derived = DerivePbkdf2Key(session, functions, step_params);
        break;
      default:
        throw std::invalid_argument(
            "DeriveKeyChain: unsupported KDF type in chain");
    }
    derived_keys.push_back(derived);
    current_key = derived;
  }
  return derived_keys;
}

}  // namespace pkcs11cpp
