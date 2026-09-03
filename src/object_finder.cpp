#include "pkcs11cpp/object_finder.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace pkcs11cpp {

std::vector<CK_OBJECT_HANDLE> ObjectFinder::findObjects(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                          const SearchCriteria& criteria) {
    std::string cacheKey = cacheKeyFor(criteria);
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        auto it = cache_.find(cacheKey);
        if (it != cache_.end() && std::chrono::steady_clock::now() - it->second.cachedAt < cacheTimeout_) {
            return it->second.handles;
        }
    }

    std::vector<CK_ATTRIBUTE> searchTemplate;
    std::vector<std::vector<CK_BYTE>> attributeData;
    buildSearchTemplate(criteria, searchTemplate, attributeData);

    CK_RV rv = functions->C_FindObjectsInit(session, searchTemplate.data(),
                                             static_cast<CK_ULONG>(searchTemplate.size()));
    if (rv != CKR_OK) {
        throw std::runtime_error("C_FindObjectsInit failed: " + std::to_string(rv));
    }

    std::vector<CK_OBJECT_HANDLE> found;
    CK_OBJECT_HANDLE batch[32];
    CK_ULONG batchCount = 0;
    do {
        rv = functions->C_FindObjects(session, batch, 32, &batchCount);
        if (rv != CKR_OK) break;
        found.insert(found.end(), batch, batch + batchCount);
    } while (batchCount > 0);

    functions->C_FindObjectsFinal(session);

    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        cache_[cacheKey] = CacheEntry{found, std::chrono::steady_clock::now()};
    }
    return found;
}

void ObjectFinder::clearCache() {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cache_.clear();
}

std::string ObjectFinder::cacheKeyFor(const SearchCriteria& criteria) {
    // A simple, deterministic textual encoding of the criteria -- good
    // enough to disambiguate cache entries without pulling in a hashing
    // dependency for what is, at most, a handful of optional fields.
    std::ostringstream key;
    if (criteria.objectClass) key << "class=" << *criteria.objectClass << ";";
    if (criteria.keyType) key << "keyType=" << *criteria.keyType << ";";
    if (criteria.label) key << "label=" << *criteria.label << ";";
    if (criteria.id) {
        key << "id=";
        for (auto b : *criteria.id) key << std::hex << static_cast<int>(b);
        key << std::dec << ";";
    }
    if (criteria.canSign) key << "canSign=" << *criteria.canSign << ";";
    if (criteria.canEncrypt) key << "canEncrypt=" << *criteria.canEncrypt << ";";
    return key.str();
}

void ObjectFinder::buildSearchTemplate(const SearchCriteria& criteria, std::vector<CK_ATTRIBUTE>& searchTemplate,
                                        std::vector<std::vector<CK_BYTE>>& attributeData) {
    if (criteria.objectClass) {
        attributeData.emplace_back(sizeof(CK_OBJECT_CLASS));
        *reinterpret_cast<CK_OBJECT_CLASS*>(attributeData.back().data()) = *criteria.objectClass;
        searchTemplate.push_back({CKA_CLASS, attributeData.back().data(),
                                   static_cast<CK_ULONG>(attributeData.back().size())});
    }
    if (criteria.keyType) {
        attributeData.emplace_back(sizeof(CK_KEY_TYPE));
        *reinterpret_cast<CK_KEY_TYPE*>(attributeData.back().data()) = *criteria.keyType;
        searchTemplate.push_back({CKA_KEY_TYPE, attributeData.back().data(),
                                   static_cast<CK_ULONG>(attributeData.back().size())});
    }
    if (criteria.label) {
        attributeData.emplace_back(criteria.label->begin(), criteria.label->end());
        searchTemplate.push_back({CKA_LABEL, attributeData.back().data(),
                                   static_cast<CK_ULONG>(attributeData.back().size())});
    }
    if (criteria.id) {
        attributeData.push_back(*criteria.id);
        searchTemplate.push_back({CKA_ID, attributeData.back().data(),
                                   static_cast<CK_ULONG>(attributeData.back().size())});
    }
    addBooleanAttribute(criteria.canSign, CKA_SIGN, searchTemplate, attributeData);
    addBooleanAttribute(criteria.canEncrypt, CKA_ENCRYPT, searchTemplate, attributeData);
}

void ObjectFinder::addBooleanAttribute(const std::optional<bool>& value, CK_ATTRIBUTE_TYPE type,
                                        std::vector<CK_ATTRIBUTE>& searchTemplate,
                                        std::vector<std::vector<CK_BYTE>>& attributeData) {
    if (!value) return;
    attributeData.emplace_back(sizeof(CK_BBOOL));
    *reinterpret_cast<CK_BBOOL*>(attributeData.back().data()) = *value ? CK_TRUE : CK_FALSE;
    searchTemplate.push_back({type, attributeData.back().data(),
                               static_cast<CK_ULONG>(attributeData.back().size())});
}

}  // namespace pkcs11cpp
