#pragma once

#include <any>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Discovers which mechanisms (algorithms) a PKCS#11 slot actually
// supports, and helps pick the best one for a given operation + key type
// instead of hardcoding a mechanism and hoping the token supports it.
class MechanismManager {
 public:
  struct MechanismInfo {
    CK_MECHANISM_TYPE type_;
    CK_MECHANISM_INFO info_;
    std::string name_;
    std::set<std::string> capabilities_;  // "encrypt", "sign", "derive", ...
  };

  void DiscoverMechanisms(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slot_id);

  std::optional<CK_MECHANISM_TYPE> SelectBestMechanism(
      CK_SLOT_ID slot_id, const std::string& operation, CK_KEY_TYPE key_type,
      CK_ULONG key_size = 0) const;

  CK_MECHANISM CreateOptimizedMechanism(
      CK_MECHANISM_TYPE mechanism_type,
      const std::map<std::string, std::any>& parameters = {}) const;

  const std::vector<MechanismInfo>* MechanismsForSlot(CK_SLOT_ID slot_id) const;

 private:
  std::string GetMechanismName(CK_MECHANISM_TYPE type) const;
  std::set<std::string> AnalyzeMechanismCapabilities(
      const CK_MECHANISM_INFO& info) const;
  bool IsCompatibleWithKeyType(CK_MECHANISM_TYPE mechanism,
                               CK_KEY_TYPE key_type) const;
  const MechanismInfo* SelectPreferredMechanism(
      const std::string& operation, CK_KEY_TYPE key_type,
      const std::vector<const MechanismInfo*>& candidates) const;

  std::unordered_map<CK_SLOT_ID, std::vector<MechanismInfo>> slot_mechanisms_;

  // Static buffers for the mechanism-parameter structs returned by
  // CreateOptimizedMechanism -- CK_MECHANISM only stores a pointer, so
  // whatever it points to must outlive the C_*Init call that consumes
  // it. Kept as instance state (rather than the original code's
  // function-local `static`) so concurrent calls on different
  // MechanismManager instances do not stomp on each other.
  mutable CK_RSA_PKCS_OAEP_PARAMS oaep_params_storage_{};
  mutable CK_GCM_PARAMS gcm_params_storage_{};
  mutable CK_ECDH1_DERIVE_PARAMS ecdh_params_storage_{};
};

}  // namespace pkcs11cpp
