#include "pkcs11cpp/key_manager.h"

#include <stdexcept>

namespace pkcs11cpp {

namespace {
// DER-encoded OIDs for the three NIST curves this repo supports, used as
// the default CKA_EC_PARAMS value when the caller doesn't supply one.
std::vector<CK_BYTE> DefaultEcParams(KeyManager::KeyAlgorithm algorithm) {
  switch (algorithm) {
    case KeyManager::KeyAlgorithm::kEcdsaP256:
      return {0x06, 0x08, 0x2a, 0x86, 0x48,
              0xce, 0x3d, 0x03, 0x01, 0x07};  // secp256r1
    case KeyManager::KeyAlgorithm::kEcdsaP384:
      return {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};  // secp384r1
    case KeyManager::KeyAlgorithm::kEcdsaP521:
      return {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};  // secp521r1
    default:
      throw std::invalid_argument("defaultEcParams: not an EC algorithm");
  }
}

CK_ULONG RsaModulusBits(KeyManager::KeyAlgorithm algorithm) {
  switch (algorithm) {
    case KeyManager::KeyAlgorithm::kRsa2048:
      return 2048;
    case KeyManager::KeyAlgorithm::kRsa3072:
      return 3072;
    case KeyManager::KeyAlgorithm::kRsa4096:
      return 4096;
    default:
      throw std::invalid_argument("rsaModulusBits: not an RSA algorithm");
  }
}

CK_ULONG AesKeyBits(KeyManager::KeyAlgorithm algorithm) {
  switch (algorithm) {
    case KeyManager::KeyAlgorithm::kAes128:
      return 128;
    case KeyManager::KeyAlgorithm::kAes192:
      return 192;
    case KeyManager::KeyAlgorithm::kAes256:
      return 256;
    default:
      throw std::invalid_argument("aesKeyBits: not an AES algorithm");
  }
}
}  // namespace

void KeyManager::AddCommonKeyAttributes(
    const KeyGenerationParams& params,
    AttributeManager::AttributeSet& public_set,
    AttributeManager::AttributeSet& private_set) {
  if (params.token_key_) {
    public_set.AddBoolean(CKA_TOKEN, true);
    private_set.AddBoolean(CKA_TOKEN, true);
  }
  private_set.AddBoolean(CKA_SENSITIVE, params.sensitive_);
  private_set.AddBoolean(CKA_EXTRACTABLE, params.extractable_);

  if (!params.label_.empty()) {
    public_set.AddString(CKA_LABEL, params.label_);
    private_set.AddString(CKA_LABEL, params.label_);
  }
  if (!params.id_.empty()) {
    public_set.AddBytes(CKA_ID, params.id_);
    private_set.AddBytes(CKA_ID, params.id_);
  }
}

KeyManager::KeyPair KeyManager::GenerateRsaKeyPair(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const KeyGenerationParams& params) const {
  AttributeManager::AttributeSet public_set, private_set;

  std::vector<CK_BYTE> public_exponent =
      params.public_exponent_.value_or(std::vector<CK_BYTE>{0x01, 0x00, 0x01});
  public_set.AddULong(CKA_CLASS, CKO_PUBLIC_KEY)
      .AddULong(CKA_KEY_TYPE, CKK_RSA)
      .AddULong(CKA_MODULUS_BITS, RsaModulusBits(params.algorithm_))
      .AddBytes(CKA_PUBLIC_EXPONENT, public_exponent);
  if (params.can_verify_) public_set.AddBoolean(CKA_VERIFY, true);
  if (params.can_encrypt_) public_set.AddBoolean(CKA_ENCRYPT, true);

  private_set.AddULong(CKA_CLASS, CKO_PRIVATE_KEY)
      .AddULong(CKA_KEY_TYPE, CKK_RSA);
  if (params.can_sign_) private_set.AddBoolean(CKA_SIGN, true);
  if (params.can_decrypt_) private_set.AddBoolean(CKA_DECRYPT, true);

  AddCommonKeyAttributes(params, public_set, private_set);

  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  CK_OBJECT_HANDLE public_key, private_key;
  CK_RV rv = functions->C_GenerateKeyPair(
      session, &mechanism, public_set.Data(),
      static_cast<CK_ULONG>(public_set.Size()), private_set.Data(),
      static_cast<CK_ULONG>(private_set.Size()), &public_key, &private_key);
  if (rv != CKR_OK) {
    throw std::runtime_error("RSA C_GenerateKeyPair failed: " +
                             std::to_string(rv));
  }
  return KeyPair{public_key, private_key, params.algorithm_, params.label_};
}

KeyManager::KeyPair KeyManager::GenerateEcKeyPair(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const KeyGenerationParams& params) const {
  AttributeManager::AttributeSet public_set, private_set;
  std::vector<CK_BYTE> ec_params =
      params.ec_params_.value_or(DefaultEcParams(params.algorithm_));

  public_set.AddULong(CKA_CLASS, CKO_PUBLIC_KEY)
      .AddULong(CKA_KEY_TYPE, CKK_ECDSA)
      .AddBytes(CKA_EC_PARAMS, ec_params);
  if (params.can_verify_) public_set.AddBoolean(CKA_VERIFY, true);

  private_set.AddULong(CKA_CLASS, CKO_PRIVATE_KEY)
      .AddULong(CKA_KEY_TYPE, CKK_ECDSA);
  if (params.can_sign_) private_set.AddBoolean(CKA_SIGN, true);
  if (params.can_derive_) private_set.AddBoolean(CKA_DERIVE, true);

  AddCommonKeyAttributes(params, public_set, private_set);

  CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_OBJECT_HANDLE public_key, private_key;
  CK_RV rv = functions->C_GenerateKeyPair(
      session, &mechanism, public_set.Data(),
      static_cast<CK_ULONG>(public_set.Size()), private_set.Data(),
      static_cast<CK_ULONG>(private_set.Size()), &public_key, &private_key);
  if (rv != CKR_OK) {
    throw std::runtime_error("EC C_GenerateKeyPair failed: " +
                             std::to_string(rv));
  }
  return KeyPair{public_key, private_key, params.algorithm_, params.label_};
}

KeyManager::KeyPair KeyManager::GenerateKeyPair(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const KeyGenerationParams& params) const {
  switch (params.algorithm_) {
    case KeyAlgorithm::kRsa2048:
    case KeyAlgorithm::kRsa3072:
    case KeyAlgorithm::kRsa4096:
      return GenerateRsaKeyPair(session, functions, params);
    case KeyAlgorithm::kEcdsaP256:
    case KeyAlgorithm::kEcdsaP384:
    case KeyAlgorithm::kEcdsaP521:
      return GenerateEcKeyPair(session, functions, params);
    default:
      throw std::invalid_argument(
          "GenerateKeyPair: algorithm is not a key-pair algorithm");
  }
}

CK_OBJECT_HANDLE KeyManager::GenerateAesKey(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const KeyGenerationParams& params) const {
  AttributeManager::AttributeSet key_set;
  key_set.AddULong(CKA_CLASS, CKO_SECRET_KEY)
      .AddULong(CKA_KEY_TYPE, CKK_AES)
      .AddULong(CKA_VALUE_LEN, AesKeyBits(params.algorithm_) / 8)
      .AddBoolean(CKA_SENSITIVE, params.sensitive_)
      .AddBoolean(CKA_EXTRACTABLE, params.extractable_);
  if (params.token_key_) key_set.AddBoolean(CKA_TOKEN, true);
  if (params.can_encrypt_) key_set.AddBoolean(CKA_ENCRYPT, true);
  if (params.can_decrypt_) key_set.AddBoolean(CKA_DECRYPT, true);
  if (params.can_wrap_) key_set.AddBoolean(CKA_WRAP, true);
  if (params.can_unwrap_) key_set.AddBoolean(CKA_UNWRAP, true);
  if (!params.label_.empty()) key_set.AddString(CKA_LABEL, params.label_);
  if (!params.id_.empty()) key_set.AddBytes(CKA_ID, params.id_);

  CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, nullptr, 0};
  CK_OBJECT_HANDLE key;
  CK_RV rv =
      functions->C_GenerateKey(session, &mechanism, key_set.Data(),
                               static_cast<CK_ULONG>(key_set.Size()), &key);
  if (rv != CKR_OK) {
    throw std::runtime_error("AES C_GenerateKey failed: " + std::to_string(rv));
  }
  return key;
}

CK_OBJECT_HANDLE KeyManager::GenerateDes3Key(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const KeyGenerationParams& params) const {
  AttributeManager::AttributeSet key_set;
  // CKK_DES3 isn't in this project's minimal type subset (3DES is
  // deprecated and none of the other modules reference it) -- rather
  // than silently mislabel the key type, this stays explicit about the
  // limitation instead of generating a key tagged as the wrong algorithm.
  (void)session;
  (void)functions;
  (void)params;
  (void)key_set;
  throw std::runtime_error(
      "GenerateSecretKey: DES3 is deprecated and intentionally unsupported by "
      "this mock/demo build; "
      "add CKK_DES3/CKM_DES3_KEY_GEN to pkcs11cpp::types if you need it "
      "against a real module.");
}

CK_OBJECT_HANDLE KeyManager::GenerateSecretKey(
    CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
    const KeyGenerationParams& params) const {
  switch (params.algorithm_) {
    case KeyAlgorithm::kAes128:
    case KeyAlgorithm::kAes192:
    case KeyAlgorithm::kAes256:
      return GenerateAesKey(session, functions, params);
    case KeyAlgorithm::kDeS3:
      return GenerateDes3Key(session, functions, params);
    default:
      throw std::invalid_argument(
          "GenerateSecretKey: algorithm is not a secret-key algorithm");
  }
}

bool KeyManager::IsSecretKeyAlgorithm(KeyAlgorithm algorithm) {
  return algorithm == KeyAlgorithm::kAes128 ||
         algorithm == KeyAlgorithm::kAes192 ||
         algorithm == KeyAlgorithm::kAes256 || algorithm == KeyAlgorithm::kDeS3;
}

bool KeyManager::IsKeyPairAlgorithm(KeyAlgorithm algorithm) {
  return algorithm == KeyAlgorithm::kRsa2048 ||
         algorithm == KeyAlgorithm::kRsa3072 ||
         algorithm == KeyAlgorithm::kRsa4096 ||
         algorithm == KeyAlgorithm::kEcdsaP256 ||
         algorithm == KeyAlgorithm::kEcdsaP384 ||
         algorithm == KeyAlgorithm::kEcdsaP521;
}

}  // namespace pkcs11cpp
