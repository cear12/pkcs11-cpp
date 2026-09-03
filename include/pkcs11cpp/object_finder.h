#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Wraps the C_FindObjectsInit / C_FindObjects / C_FindObjectsFinal
// three-call protocol behind a single findObjects() call, with a small
// time-based cache so repeatedly searching for "the signing key" during a
// batch of operations doesn't re-hit the token every time.
class ObjectFinder {
public:
    struct SearchCriteria {
        std::optional<CK_OBJECT_CLASS> objectClass;
        std::optional<CK_KEY_TYPE> keyType;
        std::optional<std::vector<CK_BYTE>> id;
        std::optional<std::string> label;
        std::optional<bool> canSign;
        std::optional<bool> canEncrypt;

        SearchCriteria& withClass(CK_OBJECT_CLASS cls) { objectClass = cls; return *this; }
        SearchCriteria& withKeyType(CK_KEY_TYPE type) { keyType = type; return *this; }
        SearchCriteria& withLabel(const std::string& lbl) { label = lbl; return *this; }
        SearchCriteria& forSigning(bool required = true) { canSign = required; return *this; }
        SearchCriteria& forEncryption(bool required = true) { canEncrypt = required; return *this; }
    };

    explicit ObjectFinder(std::chrono::seconds cacheTimeout = std::chrono::seconds(300))
        : cacheTimeout_(cacheTimeout) {}

    std::vector<CK_OBJECT_HANDLE> findObjects(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                               const SearchCriteria& criteria);

    void clearCache();

private:
    struct CacheEntry {
        std::vector<CK_OBJECT_HANDLE> handles;
        std::chrono::steady_clock::time_point cachedAt;
    };

    static std::string cacheKeyFor(const SearchCriteria& criteria);
    static void buildSearchTemplate(const SearchCriteria& criteria, std::vector<CK_ATTRIBUTE>& searchTemplate,
                                     std::vector<std::vector<CK_BYTE>>& attributeData);
    static void addBooleanAttribute(const std::optional<bool>& value, CK_ATTRIBUTE_TYPE type,
                                     std::vector<CK_ATTRIBUTE>& searchTemplate,
                                     std::vector<std::vector<CK_BYTE>>& attributeData);

    mutable std::mutex cacheMutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::chrono::seconds cacheTimeout_;
};

}  // namespace pkcs11cpp
