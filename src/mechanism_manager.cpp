#include "pkcs11cpp/mechanism_manager.h"

#include <algorithm>
#include <stdexcept>

#include "pkcs11cpp/logging.h"

namespace pkcs11cpp {

void MechanismManager::DiscoverMechanisms(CK_FUNCTION_LIST_PTR functions,
                                          CK_SLOT_ID slot_id) {
  CK_ULONG mechanism_count = 0;
  CK_RV rv = functions->C_GetMechanismList(slot_id, nullptr, &mechanism_count);
  if (rv != CKR_OK) {
    throw std::runtime_error("C_GetMechanismList (sizing) failed: " +
                             std::to_string(rv));
  }

  std::vector<CK_MECHANISM_TYPE> mechanisms(mechanism_count);
  rv = functions->C_GetMechanismList(slot_id, mechanisms.data(),
                                     &mechanism_count);
  if (rv != CKR_OK) {
    throw std::runtime_error("C_GetMechanismList failed: " +
                             std::to_string(rv));
  }

  std::vector<MechanismInfo> mechanism_infos;
  mechanism_infos.reserve(mechanisms.size());
  for (auto mech_type : mechanisms) {
    MechanismInfo mech_info;
    mech_info.type_ = mech_type;

    rv = functions->C_GetMechanismInfo(slot_id, mech_type, &mech_info.info_);
    if (rv == CKR_OK) {
      mech_info.name_ = GetMechanismName(mech_type);
      mech_info.capabilities_ = AnalyzeMechanismCapabilities(mech_info.info_);
      mechanism_infos.push_back(std::move(mech_info));
    } else {
      log::Warn("C_GetMechanismInfo failed for mechanism " +
                std::to_string(mech_type) + ": rv=" + std::to_string(rv));
    }
  }

  slot_mechanisms_[slot_id] = std::move(mechanism_infos);
}

const std::vector<MechanismManager::MechanismInfo>*
MechanismManager::MechanismsForSlot(CK_SLOT_ID slot_id) const {
  auto it = slot_mechanisms_.find(slot_id);
  return it == slot_mechanisms_.end() ? nullptr : &it->second;
}

std::optional<CK_MECHANISM_TYPE> MechanismManager::SelectBestMechanism(
    CK_SLOT_ID slot_id, const std::string& operation, CK_KEY_TYPE key_type,
    CK_ULONG key_size) const {
  auto it = slot_mechanisms_.find(slot_id);
  if (it == slot_mechanisms_.end()) {
    return std::nullopt;
  }

  std::vector<const MechanismInfo*> candidates;
  for (const auto& mech : it->second) {
    if (mech.capabilities_.count(operation) == 0 ||
        !IsCompatibleWithKeyType(mech.type_, key_type)) {
      continue;
    }
    if (key_size > 0 && mech.info_.ulMinKeySize > 0 &&
        mech.info_.ulMaxKeySize > 0) {
      if (key_size < mech.info_.ulMinKeySize ||
          key_size > mech.info_.ulMaxKeySize) {
        continue;
      }
    }
    candidates.push_back(&mech);
  }

  if (candidates.empty()) {
    return std::nullopt;
  }

  const MechanismInfo* best =
      SelectPreferredMechanism(operation, key_type, candidates);
  return best != nullptr ? std::make_optional(best->type_) : std::nullopt;
}

CK_MECHANISM MechanismManager::CreateOptimizedMechanism(
    CK_MECHANISM_TYPE mechanism_type,
    const std::map<std::string, std::any>& parameters) const {
  CK_MECHANISM mechanism = {mechanism_type, nullptr, 0};

  switch (mechanism_type) {
    case CKM_RSA_PKCS_OAEP: {
      oaep_params_storage_.hashAlg = CKM_SHA256;
      oaep_params_storage_.mgf = CKG_MGF1_SHA256;
      oaep_params_storage_.source = CKZ_DATA_SPECIFIED;
      oaep_params_storage_.pSourceData = nullptr;
      oaep_params_storage_.ulSourceDataLen = 0;

      if (auto it = parameters.find("hashAlg"); it != parameters.end()) {
        oaep_params_storage_.hashAlg =
            std::any_cast<CK_MECHANISM_TYPE>(it->second);
      }

      mechanism.pParameter = &oaep_params_storage_;
      mechanism.ulParameterLen = sizeof(oaep_params_storage_);
      break;
    }
    case CKM_AES_GCM: {
      gcm_params_storage_.ulIvLen = 12;
      gcm_params_storage_.ulAADLen = 0;
      gcm_params_storage_.ulTagBits = 128;

      if (auto it = parameters.find("iv"); it != parameters.end()) {
        static thread_local std::vector<CK_BYTE> iv_storage;
        iv_storage = std::any_cast<std::vector<CK_BYTE>>(it->second);
        gcm_params_storage_.pIv = iv_storage.data();
        gcm_params_storage_.ulIvLen = static_cast<CK_ULONG>(iv_storage.size());
      }

      mechanism.pParameter = &gcm_params_storage_;
      mechanism.ulParameterLen = sizeof(gcm_params_storage_);
      break;
    }
    case CKM_ECDH1_DERIVE: {
      ecdh_params_storage_.kdf = CKD_NULL;
      ecdh_params_storage_.ulSharedDataLen = 0;
      ecdh_params_storage_.pSharedData = nullptr;
      ecdh_params_storage_.pPublicData = nullptr;
      ecdh_params_storage_.ulPublicDataLen = 0;

      if (auto it = parameters.find("publicKey"); it != parameters.end()) {
        static thread_local std::vector<CK_BYTE> pub_storage;
        pub_storage = std::any_cast<std::vector<CK_BYTE>>(it->second);
        ecdh_params_storage_.pPublicData = pub_storage.data();
        ecdh_params_storage_.ulPublicDataLen =
            static_cast<CK_ULONG>(pub_storage.size());
      }

      mechanism.pParameter = &ecdh_params_storage_;
      mechanism.ulParameterLen = sizeof(ecdh_params_storage_);
      break;
    }
    default:
      break;
  }

  return mechanism;
}

std::string MechanismManager::GetMechanismName(CK_MECHANISM_TYPE type) const {
  static const std::unordered_map<CK_MECHANISM_TYPE, std::string> kNameMap = {
      {CKM_RSA_PKCS, "RSA_PKCS"},
      {CKM_RSA_PKCS_OAEP, "RSA_PKCS_OAEP"},
      {CKM_RSA_PSS, "RSA_PSS"},
      {CKM_RSA_PKCS_KEY_PAIR_GEN, "RSA_PKCS_KEY_PAIR_GEN"},
      {CKM_AES_KEY_GEN, "AES_KEY_GEN"},
      {CKM_AES_ECB, "AES_ECB"},
      {CKM_AES_CBC, "AES_CBC"},
      {CKM_AES_CBC_PAD, "AES_CBC_PAD"},
      {CKM_AES_GCM, "AES_GCM"},
      {CKM_AES_KEY_WRAP, "AES_KEY_WRAP"},
      {CKM_SHA256, "SHA256"},
      {CKM_SHA256_RSA_PKCS, "SHA256_RSA_PKCS"},
      {CKM_ECDSA, "ECDSA"},
      {CKM_EC_KEY_PAIR_GEN, "EC_KEY_PAIR_GEN"},
      {CKM_ECDH1_DERIVE, "ECDH1_DERIVE"},
      {CKM_PKCS5_PBKD2, "PKCS5_PBKD2"},
      {CKM_SP800_108_COUNTER_KDF, "SP800_108_COUNTER_KDF"},
  };
  auto it = kNameMap.find(type);
  return it != kNameMap.end() ? it->second : "UNKNOWN_" + std::to_string(type);
}

std::set<std::string> MechanismManager::AnalyzeMechanismCapabilities(
    const CK_MECHANISM_INFO& info) const {
  std::set<std::string> capabilities;
  if (info.flags & CKF_ENCRYPT) capabilities.insert("encrypt");
  if (info.flags & CKF_DECRYPT) capabilities.insert("decrypt");
  if (info.flags & CKF_SIGN) capabilities.insert("sign");
  if (info.flags & CKF_VERIFY) capabilities.insert("verify");
  if (info.flags & CKF_WRAP) capabilities.insert("wrap");
  if (info.flags & CKF_UNWRAP) capabilities.insert("unwrap");
  if (info.flags & CKF_DERIVE) capabilities.insert("derive");
  if (info.flags & CKF_GENERATE) capabilities.insert("generate");
  if (info.flags & CKF_GENERATE_KEY_PAIR)
    capabilities.insert("generate_keypair");
  return capabilities;
}

bool MechanismManager::IsCompatibleWithKeyType(CK_MECHANISM_TYPE mechanism,
                                               CK_KEY_TYPE key_type) const {
  switch (key_type) {
    case CKK_RSA:
      return mechanism == CKM_RSA_PKCS || mechanism == CKM_RSA_PKCS_OAEP ||
             mechanism == CKM_RSA_PSS ||
             mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN ||
             mechanism == CKM_SHA256_RSA_PKCS;
    case CKK_ECDSA:
      return mechanism == CKM_ECDSA || mechanism == CKM_ECDH1_DERIVE ||
             mechanism == CKM_EC_KEY_PAIR_GEN;
    case CKK_AES:
      return mechanism == CKM_AES_KEY_GEN || mechanism == CKM_AES_ECB ||
             mechanism == CKM_AES_CBC || mechanism == CKM_AES_CBC_PAD ||
             mechanism == CKM_AES_GCM || mechanism == CKM_AES_KEY_WRAP;
    case CKK_GENERIC_SECRET:
      return mechanism == CKM_SHA256 || mechanism == CKM_PKCS5_PBKD2 ||
             mechanism == CKM_SP800_108_COUNTER_KDF;
    default:
      return true;  // unknown key type: don't rule out mechanisms we don't have
                    // an opinion about
  }
}

const MechanismManager::MechanismInfo*
MechanismManager::SelectPreferredMechanism(
    const std::string& /*operation*/, CK_KEY_TYPE /*keyType*/,
    const std::vector<const MechanismInfo*>& candidates) const {
  if (candidates.empty()) return nullptr;

  // Prefer the mechanism supporting the widest key-size range (a proxy
  // for "the token's general-purpose implementation" over a narrow
  // special-case one), breaking ties by picking the first candidate in
  // discovery order for determinism.
  const MechanismInfo* best = candidates.front();
  for (const auto* candidate : candidates) {
    CK_ULONG best_range = best->info_.ulMaxKeySize - best->info_.ulMinKeySize;
    CK_ULONG candidate_range =
        candidate->info_.ulMaxKeySize - candidate->info_.ulMinKeySize;
    if (candidate_range > best_range) {
      best = candidate;
    }
  }
  return best;
}

}  // namespace pkcs11cpp
