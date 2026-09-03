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
// three-call protocol behind a single FindObjects() call, with a small
// time-based cache so repeatedly searching for "the signing key" during a
// batch of operations doesn't re-hit the token every time.
class ObjectFinder {
public:
    struct SearchCriteria {
        std::optional<CK_OBJECT_CLASS> object_class_;
        std::optional<CK_KEY_TYPE> key_type_;
        std::optional<std::vector<CK_BYTE>> id_;
        std::optional<std::string> label_;
        std::optional<bool> can_sign_;
        std::optional<bool> can_encrypt_;

        SearchCriteria& WithClass(CK_OBJECT_CLASS cls) { object_class_ = cls; return *this; }
        SearchCriteria& WithKeyType(CK_KEY_TYPE type) { key_type_ = type; return *this; }
        SearchCriteria& WithLabel(const std::string& lbl) { label_ = lbl; return *this; }
        SearchCriteria& ForSigning(bool required = true) { can_sign_ = required; return *this; }
        SearchCriteria& ForEncryption(bool required = true) { can_encrypt_ = required; return *this; }
    };

    explicit ObjectFinder(std::chrono::seconds cache_timeout = std::chrono::seconds(300))
        : cache_timeout_(cache_timeout) {}

    std::vector<CK_OBJECT_HANDLE> FindObjects(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                               const SearchCriteria& criteria);

    void ClearCache();

private:
    struct CacheEntry {
        std::vector<CK_OBJECT_HANDLE> handles_;
        std::chrono::steady_clock::time_point cached_at_;
    };

    static std::string CacheKeyFor(const SearchCriteria& criteria);
    static void BuildSearchTemplate(const SearchCriteria& criteria, std::vector<CK_ATTRIBUTE>& search_template,
                                     std::vector<std::vector<CK_BYTE>>& attribute_data);
    static void AddBooleanAttribute(const std::optional<bool>& value, CK_ATTRIBUTE_TYPE type,
                                     std::vector<CK_ATTRIBUTE>& search_template,
                                     std::vector<std::vector<CK_BYTE>>& attribute_data);

    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::chrono::seconds cache_timeout_;
};

}  // namespace pkcs11cpp
