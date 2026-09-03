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
        CK_MECHANISM_TYPE type;
        CK_MECHANISM_INFO info;
        std::string name;
        std::set<std::string> capabilities;  // "encrypt", "sign", "derive", ...
    };

    void discoverMechanisms(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slotId);

    std::optional<CK_MECHANISM_TYPE> selectBestMechanism(CK_SLOT_ID slotId, const std::string& operation,
                                                          CK_KEY_TYPE keyType, CK_ULONG keySize = 0) const;

    CK_MECHANISM createOptimizedMechanism(CK_MECHANISM_TYPE mechanismType,
                                           const std::map<std::string, std::any>& parameters = {}) const;

    const std::vector<MechanismInfo>* mechanismsForSlot(CK_SLOT_ID slotId) const;

private:
    std::string getMechanismName(CK_MECHANISM_TYPE type) const;
    std::set<std::string> analyzeMechanismCapabilities(const CK_MECHANISM_INFO& info) const;
    bool isCompatibleWithKeyType(CK_MECHANISM_TYPE mechanism, CK_KEY_TYPE keyType) const;
    const MechanismInfo* selectPreferredMechanism(const std::string& operation, CK_KEY_TYPE keyType,
                                                   const std::vector<const MechanismInfo*>& candidates) const;

    std::unordered_map<CK_SLOT_ID, std::vector<MechanismInfo>> slotMechanisms_;

    // Static buffers for the mechanism-parameter structs returned by
    // createOptimizedMechanism -- CK_MECHANISM only stores a pointer, so
    // whatever it points to must outlive the C_*Init call that consumes
    // it. Kept as instance state (rather than the original code's
    // function-local `static`) so concurrent calls on different
    // MechanismManager instances do not stomp on each other.
    mutable CK_RSA_PKCS_OAEP_PARAMS oaepParamsStorage_{};
    mutable CK_GCM_PARAMS gcmParamsStorage_{};
    mutable CK_ECDH1_DERIVE_PARAMS ecdhParamsStorage_{};
};

}  // namespace pkcs11cpp
