#include "pkcs11cpp/mechanism_manager.h"

#include <algorithm>
#include <stdexcept>

#include "pkcs11cpp/logging.h"

namespace pkcs11cpp {

void MechanismManager::discoverMechanisms(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slotId) {
    CK_ULONG mechanismCount = 0;
    CK_RV rv = functions->C_GetMechanismList(slotId, nullptr, &mechanismCount);
    if (rv != CKR_OK) {
        throw std::runtime_error("C_GetMechanismList (sizing) failed: " + std::to_string(rv));
    }

    std::vector<CK_MECHANISM_TYPE> mechanisms(mechanismCount);
    rv = functions->C_GetMechanismList(slotId, mechanisms.data(), &mechanismCount);
    if (rv != CKR_OK) {
        throw std::runtime_error("C_GetMechanismList failed: " + std::to_string(rv));
    }

    std::vector<MechanismInfo> mechanismInfos;
    mechanismInfos.reserve(mechanisms.size());
    for (auto mechType : mechanisms) {
        MechanismInfo mechInfo;
        mechInfo.type = mechType;

        rv = functions->C_GetMechanismInfo(slotId, mechType, &mechInfo.info);
        if (rv == CKR_OK) {
            mechInfo.name = getMechanismName(mechType);
            mechInfo.capabilities = analyzeMechanismCapabilities(mechInfo.info);
            mechanismInfos.push_back(std::move(mechInfo));
        } else {
            log::warn("C_GetMechanismInfo failed for mechanism " + std::to_string(mechType) + ": rv=" +
                      std::to_string(rv));
        }
    }

    slotMechanisms_[slotId] = std::move(mechanismInfos);
}

const std::vector<MechanismManager::MechanismInfo>* MechanismManager::mechanismsForSlot(CK_SLOT_ID slotId) const {
    auto it = slotMechanisms_.find(slotId);
    return it == slotMechanisms_.end() ? nullptr : &it->second;
}

std::optional<CK_MECHANISM_TYPE> MechanismManager::selectBestMechanism(CK_SLOT_ID slotId,
                                                                        const std::string& operation,
                                                                        CK_KEY_TYPE keyType, CK_ULONG keySize) const {
    auto it = slotMechanisms_.find(slotId);
    if (it == slotMechanisms_.end()) {
        return std::nullopt;
    }

    std::vector<const MechanismInfo*> candidates;
    for (const auto& mech : it->second) {
        if (mech.capabilities.count(operation) == 0 || !isCompatibleWithKeyType(mech.type, keyType)) {
            continue;
        }
        if (keySize > 0 && mech.info.ulMinKeySize > 0 && mech.info.ulMaxKeySize > 0) {
            if (keySize < mech.info.ulMinKeySize || keySize > mech.info.ulMaxKeySize) {
                continue;
            }
        }
        candidates.push_back(&mech);
    }

    if (candidates.empty()) {
        return std::nullopt;
    }

    const MechanismInfo* best = selectPreferredMechanism(operation, keyType, candidates);
    return best != nullptr ? std::make_optional(best->type) : std::nullopt;
}

CK_MECHANISM MechanismManager::createOptimizedMechanism(CK_MECHANISM_TYPE mechanismType,
                                                          const std::map<std::string, std::any>& parameters) const {
    CK_MECHANISM mechanism = {mechanismType, nullptr, 0};

    switch (mechanismType) {
        case CKM_RSA_PKCS_OAEP: {
            oaepParamsStorage_.hashAlg = CKM_SHA256;
            oaepParamsStorage_.mgf = CKG_MGF1_SHA256;
            oaepParamsStorage_.source = CKZ_DATA_SPECIFIED;
            oaepParamsStorage_.pSourceData = nullptr;
            oaepParamsStorage_.ulSourceDataLen = 0;

            if (auto it = parameters.find("hashAlg"); it != parameters.end()) {
                oaepParamsStorage_.hashAlg = std::any_cast<CK_MECHANISM_TYPE>(it->second);
            }

            mechanism.pParameter = &oaepParamsStorage_;
            mechanism.ulParameterLen = sizeof(oaepParamsStorage_);
            break;
        }
        case CKM_AES_GCM: {
            gcmParamsStorage_.ulIvLen = 12;
            gcmParamsStorage_.ulAADLen = 0;
            gcmParamsStorage_.ulTagBits = 128;

            if (auto it = parameters.find("iv"); it != parameters.end()) {
                static thread_local std::vector<CK_BYTE> ivStorage;
                ivStorage = std::any_cast<std::vector<CK_BYTE>>(it->second);
                gcmParamsStorage_.pIv = ivStorage.data();
                gcmParamsStorage_.ulIvLen = static_cast<CK_ULONG>(ivStorage.size());
            }

            mechanism.pParameter = &gcmParamsStorage_;
            mechanism.ulParameterLen = sizeof(gcmParamsStorage_);
            break;
        }
        case CKM_ECDH1_DERIVE: {
            ecdhParamsStorage_.kdf = CKD_NULL;
            ecdhParamsStorage_.ulSharedDataLen = 0;
            ecdhParamsStorage_.pSharedData = nullptr;
            ecdhParamsStorage_.pPublicData = nullptr;
            ecdhParamsStorage_.ulPublicDataLen = 0;

            if (auto it = parameters.find("publicKey"); it != parameters.end()) {
                static thread_local std::vector<CK_BYTE> pubStorage;
                pubStorage = std::any_cast<std::vector<CK_BYTE>>(it->second);
                ecdhParamsStorage_.pPublicData = pubStorage.data();
                ecdhParamsStorage_.ulPublicDataLen = static_cast<CK_ULONG>(pubStorage.size());
            }

            mechanism.pParameter = &ecdhParamsStorage_;
            mechanism.ulParameterLen = sizeof(ecdhParamsStorage_);
            break;
        }
        default:
            break;
    }

    return mechanism;
}

std::string MechanismManager::getMechanismName(CK_MECHANISM_TYPE type) const {
    static const std::unordered_map<CK_MECHANISM_TYPE, std::string> nameMap = {
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
    auto it = nameMap.find(type);
    return it != nameMap.end() ? it->second : "UNKNOWN_" + std::to_string(type);
}

std::set<std::string> MechanismManager::analyzeMechanismCapabilities(const CK_MECHANISM_INFO& info) const {
    std::set<std::string> capabilities;
    if (info.flags & CKF_ENCRYPT) capabilities.insert("encrypt");
    if (info.flags & CKF_DECRYPT) capabilities.insert("decrypt");
    if (info.flags & CKF_SIGN) capabilities.insert("sign");
    if (info.flags & CKF_VERIFY) capabilities.insert("verify");
    if (info.flags & CKF_WRAP) capabilities.insert("wrap");
    if (info.flags & CKF_UNWRAP) capabilities.insert("unwrap");
    if (info.flags & CKF_DERIVE) capabilities.insert("derive");
    if (info.flags & CKF_GENERATE) capabilities.insert("generate");
    if (info.flags & CKF_GENERATE_KEY_PAIR) capabilities.insert("generate_keypair");
    return capabilities;
}

bool MechanismManager::isCompatibleWithKeyType(CK_MECHANISM_TYPE mechanism, CK_KEY_TYPE keyType) const {
    switch (keyType) {
        case CKK_RSA:
            return mechanism == CKM_RSA_PKCS || mechanism == CKM_RSA_PKCS_OAEP || mechanism == CKM_RSA_PSS ||
                   mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN || mechanism == CKM_SHA256_RSA_PKCS;
        case CKK_ECDSA:
            return mechanism == CKM_ECDSA || mechanism == CKM_ECDH1_DERIVE || mechanism == CKM_EC_KEY_PAIR_GEN;
        case CKK_AES:
            return mechanism == CKM_AES_KEY_GEN || mechanism == CKM_AES_ECB || mechanism == CKM_AES_CBC ||
                   mechanism == CKM_AES_CBC_PAD || mechanism == CKM_AES_GCM || mechanism == CKM_AES_KEY_WRAP;
        case CKK_GENERIC_SECRET:
            return mechanism == CKM_SHA256 || mechanism == CKM_PKCS5_PBKD2 || mechanism == CKM_SP800_108_COUNTER_KDF;
        default:
            return true;  // unknown key type: don't rule out mechanisms we don't have an opinion about
    }
}

const MechanismManager::MechanismInfo* MechanismManager::selectPreferredMechanism(
    const std::string& /*operation*/, CK_KEY_TYPE /*keyType*/,
    const std::vector<const MechanismInfo*>& candidates) const {
    if (candidates.empty()) return nullptr;

    // Prefer the mechanism supporting the widest key-size range (a proxy
    // for "the token's general-purpose implementation" over a narrow
    // special-case one), breaking ties by picking the first candidate in
    // discovery order for determinism.
    const MechanismInfo* best = candidates.front();
    for (const auto* candidate : candidates) {
        CK_ULONG bestRange = best->info.ulMaxKeySize - best->info.ulMinKeySize;
        CK_ULONG candidateRange = candidate->info.ulMaxKeySize - candidate->info.ulMinKeySize;
        if (candidateRange > bestRange) {
            best = candidate;
        }
    }
    return best;
}

}  // namespace pkcs11cpp
