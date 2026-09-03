#include "pkcs11cpp/mock_module.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>
#include <random>
#include <vector>

#include "pkcs11cpp/sha256.h"

namespace pkcs11cpp::mock {

namespace {

struct StoredObject {
  std::map<CK_ATTRIBUTE_TYPE, std::vector<CK_BYTE>> attributes_;
};

struct SessionState {
  // C_FindObjects* state.
  std::vector<CK_OBJECT_HANDLE> find_results_;
  std::size_t find_cursor_ = 0;
  bool find_active_ = false;

  // C_SignInit / C_VerifyInit / C_EncryptInit / C_DecryptInit / C_DigestInit
  // each just remember "what operation is pending" -- this mock only
  // supports one active operation of each kind per session, same as the
  // real PKCS#11 state machine.
  CK_OBJECT_HANDLE active_key_ = CK_INVALID_HANDLE;
  CK_MECHANISM active_mechanism_{};
  std::vector<CK_BYTE> active_mechanism_param_;
};

class Token {
 public:
  static Token& Instance() {
    static Token token;
    return token;
  }

  void Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    objects_.clear();
    sessions_.clear();
    next_object_handle_ = 1;
    next_session_handle_ = 1;
    low_memory_ = false;
  }

  void SetLowMemory(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    low_memory_ = enabled;
  }

  bool LowMemory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return low_memory_;
  }

  CK_SESSION_HANDLE OpenSession() {
    std::lock_guard<std::mutex> lock(mutex_);
    CK_SESSION_HANDLE handle = next_session_handle_++;
    sessions_[handle] = SessionState{};
    return handle;
  }

  bool CloseSession(CK_SESSION_HANDLE handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.erase(handle) > 0;
  }

  SessionState* Session(CK_SESSION_HANDLE handle) {
    auto it = sessions_.find(handle);
    return it == sessions_.end() ? nullptr : &it->second;
  }

  CK_OBJECT_HANDLE CreateObject(const CK_ATTRIBUTE* tmpl, CK_ULONG count) {
    std::lock_guard<std::mutex> lock(mutex_);
    CK_OBJECT_HANDLE handle = next_object_handle_++;
    StoredObject obj;
    for (CK_ULONG i = 0; i < count; ++i) {
      const auto& attr = tmpl[i];
      const auto* bytes = static_cast<const CK_BYTE*>(attr.pValue);
      obj.attributes_[attr.type] =
          std::vector<CK_BYTE>(bytes, bytes + attr.ulValueLen);
    }
    objects_[handle] = std::move(obj);
    return handle;
  }

  StoredObject* Object(CK_OBJECT_HANDLE handle) {
    auto it = objects_.find(handle);
    return it == objects_.end() ? nullptr : &it->second;
  }

  void DestroyObject(CK_OBJECT_HANDLE handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    objects_.erase(handle);
  }

  std::vector<CK_OBJECT_HANDLE> FindMatching(const CK_ATTRIBUTE* tmpl,
                                             CK_ULONG count) const {
    std::vector<CK_OBJECT_HANDLE> matches;
    for (const auto& [handle, obj] : objects_) {
      bool ok = true;
      for (CK_ULONG i = 0; ok && i < count; ++i) {
        const auto& attr = tmpl[i];
        auto it = obj.attributes_.find(attr.type);
        if (it == obj.attributes_.end()) {
          ok = false;
          break;
        }
        const auto* bytes = static_cast<const CK_BYTE*>(attr.pValue);
        if (it->second.size() != attr.ulValueLen ||
            !std::equal(it->second.begin(), it->second.end(), bytes)) {
          ok = false;
        }
      }
      if (ok) matches.push_back(handle);
    }
    return matches;
  }

  std::vector<CK_BYTE> RandomBytes(std::size_t length) {
    std::vector<CK_BYTE> out(length);
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& b : out) b = static_cast<CK_BYTE>(dist(rng_));
    return out;
  }

 private:
  mutable std::mutex mutex_;
  std::map<CK_OBJECT_HANDLE, StoredObject> objects_;
  std::map<CK_SESSION_HANDLE, SessionState> sessions_;
  CK_OBJECT_HANDLE next_object_handle_ = 1;
  CK_SESSION_HANDLE next_session_handle_ = 1;
  bool low_memory_ = false;
  std::mt19937 rng_{std::random_device{}()};
};

// Expands `secret` into `length` pseudo-random bytes by concatenating
// successive HMAC-SHA256(secret, counter) blocks -- a simplified
// HKDF-expand. Used both as a keystream (mock Encrypt/Decrypt) and as a
// key-derivation primitive (mock DeriveKey).
std::vector<CK_BYTE> ExpandKeystream(const std::vector<CK_BYTE>& secret,
                                     std::size_t length,
                                     const std::vector<CK_BYTE>& context = {}) {
  std::vector<CK_BYTE> out;
  out.reserve(length);
  for (std::uint32_t counter = 0; out.size() < length; ++counter) {
    std::vector<CK_BYTE> block = context;
    block.push_back(static_cast<CK_BYTE>(counter >> 24));
    block.push_back(static_cast<CK_BYTE>(counter >> 16));
    block.push_back(static_cast<CK_BYTE>(counter >> 8));
    block.push_back(static_cast<CK_BYTE>(counter));

    auto digest = HmacSha256(secret, block);
    std::size_t take =
        std::min<std::size_t>(digest.size(), length - out.size());
    out.insert(out.end(), digest.begin(),
               digest.begin() + static_cast<long>(take));
  }
  return out;
}

std::vector<CK_BYTE> KeyValueOrEmpty(CK_OBJECT_HANDLE handle) {
  auto* obj = Token::Instance().Object(handle);
  if (obj == nullptr) return {};
  auto it = obj->attributes_.find(CKA_VALUE);
  return it == obj->attributes_.end() ? std::vector<CK_BYTE>{} : it->second;
}

// --- CK_FUNCTION_LIST entry points ------------------------------------------

CK_RV MockInitialize(CK_VOID_PTR) { return CKR_OK; }

CK_RV MockOpenSession(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY,
                      CK_SESSION_HANDLE_PTR ph_session) {
  *ph_session = Token::Instance().OpenSession();
  return CKR_OK;
}

CK_RV MockCloseSession(CK_SESSION_HANDLE h_session) {
  return Token::Instance().CloseSession(h_session) ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV MockLogin(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) {
  // The mock does not enforce a real PIN policy; any credentials succeed
  // so tests can focus on the wrapper logic rather than auth plumbing.
  return CKR_OK;
}

CK_RV MockGenerateRandom(CK_SESSION_HANDLE, CK_BYTE_PTR p_random_data,
                         CK_ULONG ul_random_len) {
  auto bytes = Token::Instance().RandomBytes(ul_random_len);
  std::memcpy(p_random_data, bytes.data(), ul_random_len);
  return CKR_OK;
}

CK_RV MockGenerateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                      CK_ATTRIBUTE_PTR p_template, CK_ULONG ul_count,
                      CK_OBJECT_HANDLE_PTR ph_key) {
  CK_ULONG value_len = 32;
  for (CK_ULONG i = 0; i < ul_count; ++i) {
    if (p_template[i].type == CKA_VALUE_LEN) {
      value_len = *static_cast<CK_ULONG*>(p_template[i].pValue);
    }
  }

  std::vector<CK_ATTRIBUTE> full(p_template, p_template + ul_count);
  auto key_value = Token::Instance().RandomBytes(value_len);
  full.push_back(
      {CKA_VALUE, key_value.data(), static_cast<CK_ULONG>(key_value.size())});

  *ph_key = Token::Instance().CreateObject(full.data(),
                                           static_cast<CK_ULONG>(full.size()));
  return CKR_OK;
}

CK_RV MockGenerateKeyPair(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                          CK_ATTRIBUTE_PTR p_public_template,
                          CK_ULONG ul_public_count,
                          CK_ATTRIBUTE_PTR p_private_template,
                          CK_ULONG ul_private_count,
                          CK_OBJECT_HANDLE_PTR ph_public_key,
                          CK_OBJECT_HANDLE_PTR ph_private_key) {
  auto private_material = Token::Instance().RandomBytes(32);
  auto public_material =
      Token::Instance().RandomBytes(32);  // mock "public point"/modulus

  std::vector<CK_ATTRIBUTE> pub_full(p_public_template,
                                     p_public_template + ul_public_count);
  pub_full.push_back({CKA_VALUE, public_material.data(),
                      static_cast<CK_ULONG>(public_material.size())});
  *ph_public_key = Token::Instance().CreateObject(
      pub_full.data(), static_cast<CK_ULONG>(pub_full.size()));

  std::vector<CK_ATTRIBUTE> priv_full(p_private_template,
                                      p_private_template + ul_private_count);
  priv_full.push_back({CKA_VALUE, private_material.data(),
                       static_cast<CK_ULONG>(private_material.size())});
  *ph_private_key = Token::Instance().CreateObject(
      priv_full.data(), static_cast<CK_ULONG>(priv_full.size()));

  return CKR_OK;
}

CK_RV MockDeriveKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR p_mechanism,
                    CK_OBJECT_HANDLE h_base_key, CK_ATTRIBUTE_PTR p_template,
                    CK_ULONG ul_count, CK_OBJECT_HANDLE_PTR ph_key) {
  CK_ULONG value_len = 32;
  for (CK_ULONG i = 0; i < ul_count; ++i) {
    if (p_template[i].type == CKA_VALUE_LEN) {
      value_len = *static_cast<CK_ULONG*>(p_template[i].pValue);
    }
  }

  auto base_value = KeyValueOrEmpty(h_base_key);
  if (base_value.empty()) {
    // PBKDF2 in this repo derives from a password, not a base key
    // object (hBaseKey == CK_INVALID_HANDLE); fall back to the
    // mechanism's own parameter bytes as the derivation secret so the
    // call still produces a deterministic, reproducible key.
    base_value.assign(
        reinterpret_cast<const CK_BYTE*>(&p_mechanism->mechanism),
        reinterpret_cast<const CK_BYTE*>(&p_mechanism->mechanism) +
            sizeof(p_mechanism->mechanism));
  }

  std::vector<CK_BYTE> context;
  if (p_mechanism->pParameter != nullptr && p_mechanism->ulParameterLen > 0) {
    const auto* raw = static_cast<const CK_BYTE*>(p_mechanism->pParameter);
    context.assign(raw,
                   raw + std::min<CK_ULONG>(p_mechanism->ulParameterLen, 64));
  }

  auto derived = ExpandKeystream(base_value, value_len, context);

  std::vector<CK_ATTRIBUTE> full(p_template, p_template + ul_count);
  full.push_back(
      {CKA_VALUE, derived.data(), static_cast<CK_ULONG>(derived.size())});
  *ph_key = Token::Instance().CreateObject(full.data(),
                                           static_cast<CK_ULONG>(full.size()));
  return CKR_OK;
}

CK_RV MockWrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                  CK_OBJECT_HANDLE h_wrapping_key, CK_OBJECT_HANDLE h_key,
                  CK_BYTE_PTR p_wrapped_key, CK_ULONG_PTR pul_wrapped_key_len) {
  auto key_value = KeyValueOrEmpty(h_key);
  if (p_wrapped_key == nullptr) {
    *pul_wrapped_key_len = static_cast<CK_ULONG>(key_value.size());
    return CKR_OK;
  }

  auto wrapping_secret = KeyValueOrEmpty(h_wrapping_key);
  auto keystream = ExpandKeystream(wrapping_secret, key_value.size());
  std::vector<CK_BYTE> wrapped(key_value.size());
  for (std::size_t i = 0; i < key_value.size(); ++i)
    wrapped[i] = key_value[i] ^ keystream[i];

  std::memcpy(p_wrapped_key, wrapped.data(), wrapped.size());
  *pul_wrapped_key_len = static_cast<CK_ULONG>(wrapped.size());
  return CKR_OK;
}

CK_RV MockUnwrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                    CK_OBJECT_HANDLE h_unwrapping_key,
                    CK_BYTE_PTR p_wrapped_key, CK_ULONG ul_wrapped_key_len,
                    CK_ATTRIBUTE_PTR p_template, CK_ULONG ul_count,
                    CK_OBJECT_HANDLE_PTR ph_key) {
  auto unwrapping_secret = KeyValueOrEmpty(h_unwrapping_key);
  auto keystream = ExpandKeystream(unwrapping_secret, ul_wrapped_key_len);

  std::vector<CK_BYTE> plain(ul_wrapped_key_len);
  for (CK_ULONG i = 0; i < ul_wrapped_key_len; ++i)
    plain[i] = p_wrapped_key[i] ^ keystream[i];

  std::vector<CK_ATTRIBUTE> full(p_template, p_template + ul_count);
  full.push_back(
      {CKA_VALUE, plain.data(), static_cast<CK_ULONG>(plain.size())});
  *ph_key = Token::Instance().CreateObject(full.data(),
                                           static_cast<CK_ULONG>(full.size()));
  return CKR_OK;
}

CK_RV MockSignInit(CK_SESSION_HANDLE h_session, CK_MECHANISM_PTR p_mechanism,
                   CK_OBJECT_HANDLE h_key) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr) return CKR_GENERAL_ERROR;
  session->active_key_ = h_key;
  session->active_mechanism_ = *p_mechanism;
  return CKR_OK;
}

CK_RV MockSign(CK_SESSION_HANDLE h_session, CK_BYTE_PTR p_data,
               CK_ULONG ul_data_len, CK_BYTE_PTR p_signature,
               CK_ULONG_PTR pul_signature_len) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr) return CKR_GENERAL_ERROR;

  if (p_signature == nullptr) {
    *pul_signature_len = Sha256::kDigestSize;
    return CKR_OK;
  }

  auto key_value = KeyValueOrEmpty(session->active_key_);
  std::vector<CK_BYTE> data(p_data, p_data + ul_data_len);
  auto mac = HmacSha256(key_value, data);
  std::memcpy(p_signature, mac.data(), mac.size());
  *pul_signature_len = static_cast<CK_ULONG>(mac.size());
  return CKR_OK;
}

CK_RV MockVerifyInit(CK_SESSION_HANDLE h_session, CK_MECHANISM_PTR p_mechanism,
                     CK_OBJECT_HANDLE h_key) {
  return MockSignInit(h_session, p_mechanism, h_key);
}

CK_RV MockVerify(CK_SESSION_HANDLE h_session, CK_BYTE_PTR p_data,
                 CK_ULONG ul_data_len, CK_BYTE_PTR p_signature,
                 CK_ULONG ul_signature_len) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr) return CKR_GENERAL_ERROR;

  auto key_value = KeyValueOrEmpty(session->active_key_);
  std::vector<CK_BYTE> data(p_data, p_data + ul_data_len);
  auto mac = HmacSha256(key_value, data);

  if (ul_signature_len != mac.size() ||
      !std::equal(mac.begin(), mac.end(), p_signature)) {
    return CKR_GENERAL_ERROR;
  }
  return CKR_OK;
}

CK_RV MockEncryptInit(CK_SESSION_HANDLE h_session, CK_MECHANISM_PTR p_mechanism,
                      CK_OBJECT_HANDLE h_key) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr) return CKR_GENERAL_ERROR;
  session->active_key_ = h_key;
  session->active_mechanism_ = *p_mechanism;
  session->active_mechanism_param_.clear();
  if (p_mechanism->pParameter != nullptr && p_mechanism->ulParameterLen > 0) {
    const auto* raw = static_cast<const CK_BYTE*>(p_mechanism->pParameter);
    session->active_mechanism_param_.assign(raw,
                                            raw + p_mechanism->ulParameterLen);
  }
  return CKR_OK;
}

CK_RV MockDecryptInit(CK_SESSION_HANDLE h_session, CK_MECHANISM_PTR p_mechanism,
                      CK_OBJECT_HANDLE h_key) {
  return MockEncryptInit(h_session, p_mechanism, h_key);
}

// Encrypt and Decrypt are the same XOR-keystream transform (see the class
// comment in mock_module.h for why this stands in for AES).
CK_RV XorTransform(CK_SESSION_HANDLE h_session, CK_BYTE_PTR p_in,
                   CK_ULONG ul_in_len, CK_BYTE_PTR p_out,
                   CK_ULONG_PTR pul_out_len) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr) return CKR_GENERAL_ERROR;

  if (p_out == nullptr) {
    *pul_out_len = ul_in_len;
    return CKR_OK;
  }

  auto key_value = KeyValueOrEmpty(session->active_key_);
  auto keystream =
      ExpandKeystream(key_value, ul_in_len, session->active_mechanism_param_);
  for (CK_ULONG i = 0; i < ul_in_len; ++i) p_out[i] = p_in[i] ^ keystream[i];
  *pul_out_len = ul_in_len;
  return CKR_OK;
}

CK_RV MockEncrypt(CK_SESSION_HANDLE h_session, CK_BYTE_PTR p_data,
                  CK_ULONG ul_data_len, CK_BYTE_PTR p_encrypted,
                  CK_ULONG_PTR pul_encrypted_len) {
  return XorTransform(h_session, p_data, ul_data_len, p_encrypted,
                      pul_encrypted_len);
}

CK_RV MockDecrypt(CK_SESSION_HANDLE h_session, CK_BYTE_PTR p_data,
                  CK_ULONG ul_data_len, CK_BYTE_PTR p_decrypted,
                  CK_ULONG_PTR pul_decrypted_len) {
  return XorTransform(h_session, p_data, ul_data_len, p_decrypted,
                      pul_decrypted_len);
}

CK_RV MockDigestInit(CK_SESSION_HANDLE h_session,
                     CK_MECHANISM_PTR p_mechanism) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr) return CKR_GENERAL_ERROR;
  session->active_mechanism_ = *p_mechanism;
  return CKR_OK;
}

CK_RV MockDigest(CK_SESSION_HANDLE h_session, CK_BYTE_PTR p_data,
                 CK_ULONG ul_data_len, CK_BYTE_PTR p_digest,
                 CK_ULONG_PTR pul_digest_len) {
  (void)h_session;
  if (p_digest == nullptr) {
    *pul_digest_len = Sha256::kDigestSize;
    return CKR_OK;
  }
  auto digest =
      Sha256::Hash(std::vector<CK_BYTE>(p_data, p_data + ul_data_len));
  std::memcpy(p_digest, digest.data(), digest.size());
  *pul_digest_len = static_cast<CK_ULONG>(digest.size());
  return CKR_OK;
}

CK_RV MockGetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE h_object,
                            CK_ATTRIBUTE_PTR p_template, CK_ULONG ul_count) {
  auto* obj = Token::Instance().Object(h_object);
  if (obj == nullptr) return CKR_GENERAL_ERROR;

  for (CK_ULONG i = 0; i < ul_count; ++i) {
    auto it = obj->attributes_.find(p_template[i].type);
    if (it == obj->attributes_.end()) {
      p_template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
      continue;
    }
    if (p_template[i].pValue == nullptr) {
      p_template[i].ulValueLen = static_cast<CK_ULONG>(it->second.size());
    } else {
      std::memcpy(p_template[i].pValue, it->second.data(), it->second.size());
      p_template[i].ulValueLen = static_cast<CK_ULONG>(it->second.size());
    }
  }
  return CKR_OK;
}

CK_RV MockSetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE h_object,
                            CK_ATTRIBUTE_PTR p_template, CK_ULONG ul_count) {
  auto* obj = Token::Instance().Object(h_object);
  if (obj == nullptr) return CKR_GENERAL_ERROR;

  for (CK_ULONG i = 0; i < ul_count; ++i) {
    const auto* bytes = static_cast<const CK_BYTE*>(p_template[i].pValue);
    obj->attributes_[p_template[i].type] =
        std::vector<CK_BYTE>(bytes, bytes + p_template[i].ulValueLen);
  }
  return CKR_OK;
}

CK_RV MockFindObjectsInit(CK_SESSION_HANDLE h_session,
                          CK_ATTRIBUTE_PTR p_template, CK_ULONG ul_count) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr) return CKR_GENERAL_ERROR;
  session->find_results_ = Token::Instance().FindMatching(p_template, ul_count);
  session->find_cursor_ = 0;
  session->find_active_ = true;
  return CKR_OK;
}

CK_RV MockFindObjects(CK_SESSION_HANDLE h_session,
                      CK_OBJECT_HANDLE_PTR ph_object,
                      CK_ULONG ul_max_object_count,
                      CK_ULONG_PTR pul_object_count) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr || !session->find_active_) return CKR_GENERAL_ERROR;

  CK_ULONG produced = 0;
  while (produced < ul_max_object_count &&
         session->find_cursor_ < session->find_results_.size()) {
    ph_object[produced++] = session->find_results_[session->find_cursor_++];
  }
  *pul_object_count = produced;
  return CKR_OK;
}

CK_RV MockFindObjectsFinal(CK_SESSION_HANDLE h_session) {
  auto* session = Token::Instance().Session(h_session);
  if (session == nullptr) return CKR_GENERAL_ERROR;
  session->find_active_ = false;
  session->find_results_.clear();
  session->find_cursor_ = 0;
  return CKR_OK;
}

CK_RV MockDestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE h_object) {
  Token::Instance().DestroyObject(h_object);
  return CKR_OK;
}

CK_RV MockGetSlotList(CK_BBOOL, CK_ULONG* p_slot_list, CK_ULONG_PTR pul_count) {
  if (p_slot_list == nullptr) {
    *pul_count = 1;
    return CKR_OK;
  }
  if (*pul_count < 1) return CKR_GENERAL_ERROR;
  p_slot_list[0] = 0;
  *pul_count = 1;
  return CKR_OK;
}

CK_RV MockGetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO* p_info) {
  std::memset(p_info, 0, sizeof(*p_info));
  std::snprintf(p_info->slotDescription, sizeof(p_info->slotDescription),
                "pkcs11cpp mock slot");
  p_info->flags = CKF_TOKEN_PRESENT;
  return CKR_OK;
}

CK_RV MockGetTokenInfo(CK_SLOT_ID, CK_TOKEN_INFO* p_info) {
  std::memset(p_info, 0, sizeof(*p_info));
  std::snprintf(p_info->label, sizeof(p_info->label), "pkcs11cpp mock token");
  p_info->flags = 0;
  bool low = Token::Instance().LowMemory();
  p_info->ulFreePrivateMemory = low ? 512 : (1u << 20);
  p_info->ulFreePublicMemory = low ? 512 : (1u << 20);
  return CKR_OK;
}

struct MechanismEntry {
  CK_MECHANISM_TYPE type_;
  CK_ULONG min_key_size_;
  CK_ULONG max_key_size_;
  CK_FLAGS flags_;
};

const std::vector<MechanismEntry>& MechanismTable() {
  static const std::vector<MechanismEntry> kTable = {
      {CKM_RSA_PKCS_KEY_PAIR_GEN, 2048, 4096, CKF_GENERATE_KEY_PAIR},
      {CKM_RSA_PKCS, 2048, 4096,
       CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP |
           CKF_UNWRAP},
      {CKM_SHA256_RSA_PKCS, 2048, 4096, CKF_SIGN | CKF_VERIFY},
      {CKM_EC_KEY_PAIR_GEN, 256, 521, CKF_GENERATE_KEY_PAIR},
      {CKM_ECDSA, 256, 521, CKF_SIGN | CKF_VERIFY},
      {CKM_ECDH1_DERIVE, 256, 521, CKF_DERIVE},
      {CKM_AES_KEY_GEN, 128, 256, CKF_GENERATE},
      {CKM_AES_ECB, 128, 256, CKF_ENCRYPT | CKF_DECRYPT},
      {CKM_AES_CBC_PAD, 128, 256, CKF_ENCRYPT | CKF_DECRYPT},
      {CKM_AES_GCM, 128, 256, CKF_ENCRYPT | CKF_DECRYPT},
      {CKM_AES_KEY_WRAP, 128, 256, CKF_WRAP | CKF_UNWRAP},
      {CKM_SHA256, 0, 0, CKF_DERIVE},
      {CKM_PKCS5_PBKD2, 0, 0, CKF_GENERATE},
      {CKM_SP800_108_COUNTER_KDF, 0, 0, CKF_DERIVE},
  };
  return kTable;
}

CK_RV MockGetMechanismList(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR p_mechanism_list,
                           CK_ULONG_PTR pul_count) {
  const auto& table = MechanismTable();
  if (p_mechanism_list == nullptr) {
    *pul_count = static_cast<CK_ULONG>(table.size());
    return CKR_OK;
  }
  for (std::size_t i = 0; i < table.size(); ++i)
    p_mechanism_list[i] = table[i].type_;
  *pul_count = static_cast<CK_ULONG>(table.size());
  return CKR_OK;
}

CK_RV MockGetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE type,
                           CK_MECHANISM_INFO_PTR p_info) {
  for (const auto& entry : MechanismTable()) {
    if (entry.type_ == type) {
      p_info->ulMinKeySize = entry.min_key_size_;
      p_info->ulMaxKeySize = entry.max_key_size_;
      p_info->flags = entry.flags_;
      return CKR_OK;
    }
  }
  return CKR_GENERAL_ERROR;
}

CK_FUNCTION_LIST BuildFunctionList() {
  CK_FUNCTION_LIST list{};
  list.C_Initialize = MockInitialize;
  list.C_OpenSession = MockOpenSession;
  list.C_CloseSession = MockCloseSession;
  list.C_Login = MockLogin;
  list.C_GenerateRandom = MockGenerateRandom;
  list.C_GenerateKey = MockGenerateKey;
  list.C_GenerateKeyPair = MockGenerateKeyPair;
  list.C_DeriveKey = MockDeriveKey;
  list.C_WrapKey = MockWrapKey;
  list.C_UnwrapKey = MockUnwrapKey;
  list.C_SignInit = MockSignInit;
  list.C_Sign = MockSign;
  list.C_VerifyInit = MockVerifyInit;
  list.C_Verify = MockVerify;
  list.C_EncryptInit = MockEncryptInit;
  list.C_Encrypt = MockEncrypt;
  list.C_DecryptInit = MockDecryptInit;
  list.C_Decrypt = MockDecrypt;
  list.C_DigestInit = MockDigestInit;
  list.C_Digest = MockDigest;
  list.C_GetAttributeValue = MockGetAttributeValue;
  list.C_SetAttributeValue = MockSetAttributeValue;
  list.C_FindObjectsInit = MockFindObjectsInit;
  list.C_FindObjects = MockFindObjects;
  list.C_FindObjectsFinal = MockFindObjectsFinal;
  list.C_DestroyObject = MockDestroyObject;
  list.C_GetSlotList = MockGetSlotList;
  list.C_GetSlotInfo = MockGetSlotInfo;
  list.C_GetTokenInfo = MockGetTokenInfo;
  list.C_GetMechanismList = MockGetMechanismList;
  list.C_GetMechanismInfo = MockGetMechanismInfo;
  return list;
}

}  // namespace

CK_FUNCTION_LIST_PTR GetFunctionList() {
  static CK_FUNCTION_LIST list = BuildFunctionList();
  return &list;
}

void Reset() { Token::Instance().Reset(); }

void SimulateLowMemory(bool enabled) {
  Token::Instance().SetLowMemory(enabled);
}

}  // namespace pkcs11cpp::mock
