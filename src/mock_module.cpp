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
    std::map<CK_ATTRIBUTE_TYPE, std::vector<CK_BYTE>> attributes;
};

struct SessionState {
    // C_FindObjects* state.
    std::vector<CK_OBJECT_HANDLE> findResults;
    std::size_t findCursor = 0;
    bool findActive = false;

    // C_SignInit / C_VerifyInit / C_EncryptInit / C_DecryptInit / C_DigestInit
    // each just remember "what operation is pending" -- this mock only
    // supports one active operation of each kind per session, same as the
    // real PKCS#11 state machine.
    CK_OBJECT_HANDLE activeKey = CK_INVALID_HANDLE;
    CK_MECHANISM activeMechanism{};
    std::vector<CK_BYTE> activeMechanismParam;
};

class Token {
public:
    static Token& instance() {
        static Token token;
        return token;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        objects_.clear();
        sessions_.clear();
        nextObjectHandle_ = 1;
        nextSessionHandle_ = 1;
        lowMemory_ = false;
    }

    void setLowMemory(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        lowMemory_ = enabled;
    }

    bool lowMemory() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return lowMemory_;
    }

    CK_SESSION_HANDLE openSession() {
        std::lock_guard<std::mutex> lock(mutex_);
        CK_SESSION_HANDLE handle = nextSessionHandle_++;
        sessions_[handle] = SessionState{};
        return handle;
    }

    bool closeSession(CK_SESSION_HANDLE handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.erase(handle) > 0;
    }

    SessionState* session(CK_SESSION_HANDLE handle) {
        auto it = sessions_.find(handle);
        return it == sessions_.end() ? nullptr : &it->second;
    }

    CK_OBJECT_HANDLE createObject(const CK_ATTRIBUTE* tmpl, CK_ULONG count) {
        std::lock_guard<std::mutex> lock(mutex_);
        CK_OBJECT_HANDLE handle = nextObjectHandle_++;
        StoredObject obj;
        for (CK_ULONG i = 0; i < count; ++i) {
            const auto& attr = tmpl[i];
            const auto* bytes = static_cast<const CK_BYTE*>(attr.pValue);
            obj.attributes[attr.type] = std::vector<CK_BYTE>(bytes, bytes + attr.ulValueLen);
        }
        objects_[handle] = std::move(obj);
        return handle;
    }

    StoredObject* object(CK_OBJECT_HANDLE handle) {
        auto it = objects_.find(handle);
        return it == objects_.end() ? nullptr : &it->second;
    }

    void destroyObject(CK_OBJECT_HANDLE handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        objects_.erase(handle);
    }

    std::vector<CK_OBJECT_HANDLE> findMatching(const CK_ATTRIBUTE* tmpl, CK_ULONG count) const {
        std::vector<CK_OBJECT_HANDLE> matches;
        for (const auto& [handle, obj] : objects_) {
            bool ok = true;
            for (CK_ULONG i = 0; ok && i < count; ++i) {
                const auto& attr = tmpl[i];
                auto it = obj.attributes.find(attr.type);
                if (it == obj.attributes.end()) {
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

    std::vector<CK_BYTE> randomBytes(std::size_t length) {
        std::vector<CK_BYTE> out(length);
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& b : out) b = static_cast<CK_BYTE>(dist(rng_));
        return out;
    }

private:
    mutable std::mutex mutex_;
    std::map<CK_OBJECT_HANDLE, StoredObject> objects_;
    std::map<CK_SESSION_HANDLE, SessionState> sessions_;
    CK_OBJECT_HANDLE nextObjectHandle_ = 1;
    CK_SESSION_HANDLE nextSessionHandle_ = 1;
    bool lowMemory_ = false;
    std::mt19937 rng_{std::random_device{}()};
};

// Expands `secret` into `length` pseudo-random bytes by concatenating
// successive HMAC-SHA256(secret, counter) blocks -- a simplified
// HKDF-expand. Used both as a keystream (mock Encrypt/Decrypt) and as a
// key-derivation primitive (mock DeriveKey).
std::vector<CK_BYTE> expandKeystream(const std::vector<CK_BYTE>& secret, std::size_t length,
                                      const std::vector<CK_BYTE>& context = {}) {
    std::vector<CK_BYTE> out;
    out.reserve(length);
    for (std::uint32_t counter = 0; out.size() < length; ++counter) {
        std::vector<CK_BYTE> block = context;
        block.push_back(static_cast<CK_BYTE>(counter >> 24));
        block.push_back(static_cast<CK_BYTE>(counter >> 16));
        block.push_back(static_cast<CK_BYTE>(counter >> 8));
        block.push_back(static_cast<CK_BYTE>(counter));

        auto digest = hmacSha256(secret, block);
        std::size_t take = std::min<std::size_t>(digest.size(), length - out.size());
        out.insert(out.end(), digest.begin(), digest.begin() + static_cast<long>(take));
    }
    return out;
}

std::vector<CK_BYTE> keyValueOrEmpty(CK_OBJECT_HANDLE handle) {
    auto* obj = Token::instance().object(handle);
    if (obj == nullptr) return {};
    auto it = obj->attributes.find(CKA_VALUE);
    return it == obj->attributes.end() ? std::vector<CK_BYTE>{} : it->second;
}

// --- CK_FUNCTION_LIST entry points ------------------------------------------

CK_RV Mock_Initialize(CK_VOID_PTR) { return CKR_OK; }

CK_RV Mock_OpenSession(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR phSession) {
    *phSession = Token::instance().openSession();
    return CKR_OK;
}

CK_RV Mock_CloseSession(CK_SESSION_HANDLE hSession) {
    return Token::instance().closeSession(hSession) ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV Mock_Login(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) {
    // The mock does not enforce a real PIN policy; any credentials succeed
    // so tests can focus on the wrapper logic rather than auth plumbing.
    return CKR_OK;
}

CK_RV Mock_GenerateRandom(CK_SESSION_HANDLE, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    auto bytes = Token::instance().randomBytes(ulRandomLen);
    std::memcpy(pRandomData, bytes.data(), ulRandomLen);
    return CKR_OK;
}

CK_RV Mock_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        CK_OBJECT_HANDLE_PTR phKey) {
    CK_ULONG valueLen = 32;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        if (pTemplate[i].type == CKA_VALUE_LEN) {
            valueLen = *static_cast<CK_ULONG*>(pTemplate[i].pValue);
        }
    }

    std::vector<CK_ATTRIBUTE> full(pTemplate, pTemplate + ulCount);
    auto keyValue = Token::instance().randomBytes(valueLen);
    full.push_back({CKA_VALUE, keyValue.data(), static_cast<CK_ULONG>(keyValue.size())});

    *phKey = Token::instance().createObject(full.data(), static_cast<CK_ULONG>(full.size()));
    return CKR_OK;
}

CK_RV Mock_GenerateKeyPair(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                            CK_ATTRIBUTE_PTR pPublicTemplate, CK_ULONG ulPublicCount,
                            CK_ATTRIBUTE_PTR pPrivateTemplate, CK_ULONG ulPrivateCount,
                            CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
    auto privateMaterial = Token::instance().randomBytes(32);
    auto publicMaterial = Token::instance().randomBytes(32);  // mock "public point"/modulus

    std::vector<CK_ATTRIBUTE> pubFull(pPublicTemplate, pPublicTemplate + ulPublicCount);
    pubFull.push_back({CKA_VALUE, publicMaterial.data(), static_cast<CK_ULONG>(publicMaterial.size())});
    *phPublicKey = Token::instance().createObject(pubFull.data(), static_cast<CK_ULONG>(pubFull.size()));

    std::vector<CK_ATTRIBUTE> privFull(pPrivateTemplate, pPrivateTemplate + ulPrivateCount);
    privFull.push_back({CKA_VALUE, privateMaterial.data(), static_cast<CK_ULONG>(privateMaterial.size())});
    *phPrivateKey = Token::instance().createObject(privFull.data(), static_cast<CK_ULONG>(privFull.size()));

    return CKR_OK;
}

CK_RV Mock_DeriveKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
    CK_ULONG valueLen = 32;
    for (CK_ULONG i = 0; i < ulCount; ++i) {
        if (pTemplate[i].type == CKA_VALUE_LEN) {
            valueLen = *static_cast<CK_ULONG*>(pTemplate[i].pValue);
        }
    }

    auto baseValue = keyValueOrEmpty(hBaseKey);
    if (baseValue.empty()) {
        // PBKDF2 in this repo derives from a password, not a base key
        // object (hBaseKey == CK_INVALID_HANDLE); fall back to the
        // mechanism's own parameter bytes as the derivation secret so the
        // call still produces a deterministic, reproducible key.
        baseValue.assign(reinterpret_cast<const CK_BYTE*>(&pMechanism->mechanism),
                          reinterpret_cast<const CK_BYTE*>(&pMechanism->mechanism) + sizeof(pMechanism->mechanism));
    }

    std::vector<CK_BYTE> context;
    if (pMechanism->pParameter != nullptr && pMechanism->ulParameterLen > 0) {
        const auto* raw = static_cast<const CK_BYTE*>(pMechanism->pParameter);
        context.assign(raw, raw + std::min<CK_ULONG>(pMechanism->ulParameterLen, 64));
    }

    auto derived = expandKeystream(baseValue, valueLen, context);

    std::vector<CK_ATTRIBUTE> full(pTemplate, pTemplate + ulCount);
    full.push_back({CKA_VALUE, derived.data(), static_cast<CK_ULONG>(derived.size())});
    *phKey = Token::instance().createObject(full.data(), static_cast<CK_ULONG>(full.size()));
    return CKR_OK;
}

CK_RV Mock_WrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
    auto keyValue = keyValueOrEmpty(hKey);
    if (pWrappedKey == nullptr) {
        *pulWrappedKeyLen = static_cast<CK_ULONG>(keyValue.size());
        return CKR_OK;
    }

    auto wrappingSecret = keyValueOrEmpty(hWrappingKey);
    auto keystream = expandKeystream(wrappingSecret, keyValue.size());
    std::vector<CK_BYTE> wrapped(keyValue.size());
    for (std::size_t i = 0; i < keyValue.size(); ++i) wrapped[i] = keyValue[i] ^ keystream[i];

    std::memcpy(pWrappedKey, wrapped.data(), wrapped.size());
    *pulWrappedKeyLen = static_cast<CK_ULONG>(wrapped.size());
    return CKR_OK;
}

CK_RV Mock_UnwrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE hUnwrappingKey,
                      CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
                      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
    auto unwrappingSecret = keyValueOrEmpty(hUnwrappingKey);
    auto keystream = expandKeystream(unwrappingSecret, ulWrappedKeyLen);

    std::vector<CK_BYTE> plain(ulWrappedKeyLen);
    for (CK_ULONG i = 0; i < ulWrappedKeyLen; ++i) plain[i] = pWrappedKey[i] ^ keystream[i];

    std::vector<CK_ATTRIBUTE> full(pTemplate, pTemplate + ulCount);
    full.push_back({CKA_VALUE, plain.data(), static_cast<CK_ULONG>(plain.size())});
    *phKey = Token::instance().createObject(full.data(), static_cast<CK_ULONG>(full.size()));
    return CKR_OK;
}

CK_RV Mock_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr) return CKR_GENERAL_ERROR;
    session->activeKey = hKey;
    session->activeMechanism = *pMechanism;
    return CKR_OK;
}

CK_RV Mock_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr) return CKR_GENERAL_ERROR;

    if (pSignature == nullptr) {
        *pulSignatureLen = Sha256::kDigestSize;
        return CKR_OK;
    }

    auto keyValue = keyValueOrEmpty(session->activeKey);
    std::vector<CK_BYTE> data(pData, pData + ulDataLen);
    auto mac = hmacSha256(keyValue, data);
    std::memcpy(pSignature, mac.data(), mac.size());
    *pulSignatureLen = static_cast<CK_ULONG>(mac.size());
    return CKR_OK;
}

CK_RV Mock_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    return Mock_SignInit(hSession, pMechanism, hKey);
}

CK_RV Mock_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                   CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr) return CKR_GENERAL_ERROR;

    auto keyValue = keyValueOrEmpty(session->activeKey);
    std::vector<CK_BYTE> data(pData, pData + ulDataLen);
    auto mac = hmacSha256(keyValue, data);

    if (ulSignatureLen != mac.size() || !std::equal(mac.begin(), mac.end(), pSignature)) {
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

CK_RV Mock_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr) return CKR_GENERAL_ERROR;
    session->activeKey = hKey;
    session->activeMechanism = *pMechanism;
    session->activeMechanismParam.clear();
    if (pMechanism->pParameter != nullptr && pMechanism->ulParameterLen > 0) {
        const auto* raw = static_cast<const CK_BYTE*>(pMechanism->pParameter);
        session->activeMechanismParam.assign(raw, raw + pMechanism->ulParameterLen);
    }
    return CKR_OK;
}

CK_RV Mock_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    return Mock_EncryptInit(hSession, pMechanism, hKey);
}

// Encrypt and Decrypt are the same XOR-keystream transform (see the class
// comment in mock_module.h for why this stands in for AES).
CK_RV xorTransform(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pIn, CK_ULONG ulInLen,
                    CK_BYTE_PTR pOut, CK_ULONG_PTR pulOutLen) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr) return CKR_GENERAL_ERROR;

    if (pOut == nullptr) {
        *pulOutLen = ulInLen;
        return CKR_OK;
    }

    auto keyValue = keyValueOrEmpty(session->activeKey);
    auto keystream = expandKeystream(keyValue, ulInLen, session->activeMechanismParam);
    for (CK_ULONG i = 0; i < ulInLen; ++i) pOut[i] = pIn[i] ^ keystream[i];
    *pulOutLen = ulInLen;
    return CKR_OK;
}

CK_RV Mock_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                    CK_BYTE_PTR pEncrypted, CK_ULONG_PTR pulEncryptedLen) {
    return xorTransform(hSession, pData, ulDataLen, pEncrypted, pulEncryptedLen);
}

CK_RV Mock_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                    CK_BYTE_PTR pDecrypted, CK_ULONG_PTR pulDecryptedLen) {
    return xorTransform(hSession, pData, ulDataLen, pDecrypted, pulDecryptedLen);
}

CK_RV Mock_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr) return CKR_GENERAL_ERROR;
    session->activeMechanism = *pMechanism;
    return CKR_OK;
}

CK_RV Mock_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                   CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    (void)hSession;
    if (pDigest == nullptr) {
        *pulDigestLen = Sha256::kDigestSize;
        return CKR_OK;
    }
    auto digest = Sha256::hash(std::vector<CK_BYTE>(pData, pData + ulDataLen));
    std::memcpy(pDigest, digest.data(), digest.size());
    *pulDigestLen = static_cast<CK_ULONG>(digest.size());
    return CKR_OK;
}

CK_RV Mock_GetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount) {
    auto* obj = Token::instance().object(hObject);
    if (obj == nullptr) return CKR_GENERAL_ERROR;

    for (CK_ULONG i = 0; i < ulCount; ++i) {
        auto it = obj->attributes.find(pTemplate[i].type);
        if (it == obj->attributes.end()) {
            pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            continue;
        }
        if (pTemplate[i].pValue == nullptr) {
            pTemplate[i].ulValueLen = static_cast<CK_ULONG>(it->second.size());
        } else {
            std::memcpy(pTemplate[i].pValue, it->second.data(), it->second.size());
            pTemplate[i].ulValueLen = static_cast<CK_ULONG>(it->second.size());
        }
    }
    return CKR_OK;
}

CK_RV Mock_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                              CK_ULONG ulCount) {
    auto* obj = Token::instance().object(hObject);
    if (obj == nullptr) return CKR_GENERAL_ERROR;

    for (CK_ULONG i = 0; i < ulCount; ++i) {
        const auto* bytes = static_cast<const CK_BYTE*>(pTemplate[i].pValue);
        obj->attributes[pTemplate[i].type] = std::vector<CK_BYTE>(bytes, bytes + pTemplate[i].ulValueLen);
    }
    return CKR_OK;
}

CK_RV Mock_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr) return CKR_GENERAL_ERROR;
    session->findResults = Token::instance().findMatching(pTemplate, ulCount);
    session->findCursor = 0;
    session->findActive = true;
    return CKR_OK;
}

CK_RV Mock_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                        CK_ULONG_PTR pulObjectCount) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr || !session->findActive) return CKR_GENERAL_ERROR;

    CK_ULONG produced = 0;
    while (produced < ulMaxObjectCount && session->findCursor < session->findResults.size()) {
        phObject[produced++] = session->findResults[session->findCursor++];
    }
    *pulObjectCount = produced;
    return CKR_OK;
}

CK_RV Mock_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    auto* session = Token::instance().session(hSession);
    if (session == nullptr) return CKR_GENERAL_ERROR;
    session->findActive = false;
    session->findResults.clear();
    session->findCursor = 0;
    return CKR_OK;
}

CK_RV Mock_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE hObject) {
    Token::instance().destroyObject(hObject);
    return CKR_OK;
}

CK_RV Mock_GetSlotList(CK_BBOOL, CK_ULONG* pSlotList, CK_ULONG_PTR pulCount) {
    if (pSlotList == nullptr) {
        *pulCount = 1;
        return CKR_OK;
    }
    if (*pulCount < 1) return CKR_GENERAL_ERROR;
    pSlotList[0] = 0;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV Mock_GetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO* pInfo) {
    std::memset(pInfo, 0, sizeof(*pInfo));
    std::snprintf(pInfo->slotDescription, sizeof(pInfo->slotDescription), "pkcs11cpp mock slot");
    pInfo->flags = CKF_TOKEN_PRESENT;
    return CKR_OK;
}

CK_RV Mock_GetTokenInfo(CK_SLOT_ID, CK_TOKEN_INFO* pInfo) {
    std::memset(pInfo, 0, sizeof(*pInfo));
    std::snprintf(pInfo->label, sizeof(pInfo->label), "pkcs11cpp mock token");
    pInfo->flags = 0;
    bool low = Token::instance().lowMemory();
    pInfo->ulFreePrivateMemory = low ? 512 : (1u << 20);
    pInfo->ulFreePublicMemory = low ? 512 : (1u << 20);
    return CKR_OK;
}

struct MechanismEntry {
    CK_MECHANISM_TYPE type;
    CK_ULONG minKeySize;
    CK_ULONG maxKeySize;
    CK_FLAGS flags;
};

const std::vector<MechanismEntry>& mechanismTable() {
    static const std::vector<MechanismEntry> table = {
        {CKM_RSA_PKCS_KEY_PAIR_GEN, 2048, 4096, CKF_GENERATE_KEY_PAIR},
        {CKM_RSA_PKCS, 2048, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY | CKF_WRAP | CKF_UNWRAP},
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
    return table;
}

CK_RV Mock_GetMechanismList(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
    const auto& table = mechanismTable();
    if (pMechanismList == nullptr) {
        *pulCount = static_cast<CK_ULONG>(table.size());
        return CKR_OK;
    }
    for (std::size_t i = 0; i < table.size(); ++i) pMechanismList[i] = table[i].type;
    *pulCount = static_cast<CK_ULONG>(table.size());
    return CKR_OK;
}

CK_RV Mock_GetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
    for (const auto& entry : mechanismTable()) {
        if (entry.type == type) {
            pInfo->ulMinKeySize = entry.minKeySize;
            pInfo->ulMaxKeySize = entry.maxKeySize;
            pInfo->flags = entry.flags;
            return CKR_OK;
        }
    }
    return CKR_GENERAL_ERROR;
}

CK_FUNCTION_LIST buildFunctionList() {
    CK_FUNCTION_LIST list{};
    list.C_Initialize = Mock_Initialize;
    list.C_OpenSession = Mock_OpenSession;
    list.C_CloseSession = Mock_CloseSession;
    list.C_Login = Mock_Login;
    list.C_GenerateRandom = Mock_GenerateRandom;
    list.C_GenerateKey = Mock_GenerateKey;
    list.C_GenerateKeyPair = Mock_GenerateKeyPair;
    list.C_DeriveKey = Mock_DeriveKey;
    list.C_WrapKey = Mock_WrapKey;
    list.C_UnwrapKey = Mock_UnwrapKey;
    list.C_SignInit = Mock_SignInit;
    list.C_Sign = Mock_Sign;
    list.C_VerifyInit = Mock_VerifyInit;
    list.C_Verify = Mock_Verify;
    list.C_EncryptInit = Mock_EncryptInit;
    list.C_Encrypt = Mock_Encrypt;
    list.C_DecryptInit = Mock_DecryptInit;
    list.C_Decrypt = Mock_Decrypt;
    list.C_DigestInit = Mock_DigestInit;
    list.C_Digest = Mock_Digest;
    list.C_GetAttributeValue = Mock_GetAttributeValue;
    list.C_SetAttributeValue = Mock_SetAttributeValue;
    list.C_FindObjectsInit = Mock_FindObjectsInit;
    list.C_FindObjects = Mock_FindObjects;
    list.C_FindObjectsFinal = Mock_FindObjectsFinal;
    list.C_DestroyObject = Mock_DestroyObject;
    list.C_GetSlotList = Mock_GetSlotList;
    list.C_GetSlotInfo = Mock_GetSlotInfo;
    list.C_GetTokenInfo = Mock_GetTokenInfo;
    list.C_GetMechanismList = Mock_GetMechanismList;
    list.C_GetMechanismInfo = Mock_GetMechanismInfo;
    return list;
}

}  // namespace

CK_FUNCTION_LIST_PTR getFunctionList() {
    static CK_FUNCTION_LIST list = buildFunctionList();
    return &list;
}

void reset() { Token::instance().reset(); }

void simulateLowMemory(bool enabled) { Token::instance().setLowMemory(enabled); }

}  // namespace pkcs11cpp::mock
