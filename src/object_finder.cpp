#include "pkcs11cpp/object_finder.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace pkcs11cpp {

std::vector<CK_OBJECT_HANDLE> ObjectFinder::FindObjects(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                                          const SearchCriteria& criteria) {
    std::string cache_key = CacheKeyFor(criteria);
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = cache_.find(cache_key);
        if (it != cache_.end() && std::chrono::steady_clock::now() - it->second.cached_at_ < cache_timeout_) {
            return it->second.handles_;
        }
    }

    std::vector<CK_ATTRIBUTE> search_template;
    std::vector<std::vector<CK_BYTE>> attribute_data;
    BuildSearchTemplate(criteria, search_template, attribute_data);

    CK_RV rv = functions->C_FindObjectsInit(session, search_template.data(),
                                             static_cast<CK_ULONG>(search_template.size()));
    if (rv != CKR_OK) {
        throw std::runtime_error("C_FindObjectsInit failed: " + std::to_string(rv));
    }

    std::vector<CK_OBJECT_HANDLE> found;
    CK_OBJECT_HANDLE batch[32];
    CK_ULONG batch_count = 0;
    do {
        rv = functions->C_FindObjects(session, batch, 32, &batch_count);
        if (rv != CKR_OK) break;
        found.insert(found.end(), batch, batch + batch_count);
    } while (batch_count > 0);

    functions->C_FindObjectsFinal(session);

    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        cache_[cache_key] = CacheEntry{found, std::chrono::steady_clock::now()};
    }
    return found;
}

void ObjectFinder::ClearCache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

std::string ObjectFinder::CacheKeyFor(const SearchCriteria& criteria) {
    // A simple, deterministic textual encoding of the criteria -- good
    // enough to disambiguate cache entries without pulling in a hashing
    // dependency for what is, at most, a handful of optional fields.
    std::ostringstream key;
    if (criteria.object_class_) key << "class=" << *criteria.object_class_ << ";";
    if (criteria.key_type_) key << "keyType=" << *criteria.key_type_ << ";";
    if (criteria.label_) key << "label=" << *criteria.label_ << ";";
    if (criteria.id_) {
        key << "id=";
        for (auto b : *criteria.id_) key << std::hex << static_cast<int>(b);
        key << std::dec << ";";
    }
    if (criteria.can_sign_) key << "canSign=" << *criteria.can_sign_ << ";";
    if (criteria.can_encrypt_) key << "canEncrypt=" << *criteria.can_encrypt_ << ";";
    return key.str();
}

void ObjectFinder::BuildSearchTemplate(const SearchCriteria& criteria, std::vector<CK_ATTRIBUTE>& search_template,
                                        std::vector<std::vector<CK_BYTE>>& attribute_data) {
    if (criteria.object_class_) {
        attribute_data.emplace_back(sizeof(CK_OBJECT_CLASS));
        *reinterpret_cast<CK_OBJECT_CLASS*>(attribute_data.back().data()) = *criteria.object_class_;
        search_template.push_back({CKA_CLASS, attribute_data.back().data(),
                                   static_cast<CK_ULONG>(attribute_data.back().size())});
    }
    if (criteria.key_type_) {
        attribute_data.emplace_back(sizeof(CK_KEY_TYPE));
        *reinterpret_cast<CK_KEY_TYPE*>(attribute_data.back().data()) = *criteria.key_type_;
        search_template.push_back({CKA_KEY_TYPE, attribute_data.back().data(),
                                   static_cast<CK_ULONG>(attribute_data.back().size())});
    }
    if (criteria.label_) {
        attribute_data.emplace_back(criteria.label_->begin(), criteria.label_->end());
        search_template.push_back({CKA_LABEL, attribute_data.back().data(),
                                   static_cast<CK_ULONG>(attribute_data.back().size())});
    }
    if (criteria.id_) {
        attribute_data.push_back(*criteria.id_);
        search_template.push_back({CKA_ID, attribute_data.back().data(),
                                   static_cast<CK_ULONG>(attribute_data.back().size())});
    }
    AddBooleanAttribute(criteria.can_sign_, CKA_SIGN, search_template, attribute_data);
    AddBooleanAttribute(criteria.can_encrypt_, CKA_ENCRYPT, search_template, attribute_data);
}

void ObjectFinder::AddBooleanAttribute(const std::optional<bool>& value, CK_ATTRIBUTE_TYPE type,
                                        std::vector<CK_ATTRIBUTE>& search_template,
                                        std::vector<std::vector<CK_BYTE>>& attribute_data) {
    if (!value) return;
    attribute_data.emplace_back(sizeof(CK_BBOOL));
    *reinterpret_cast<CK_BBOOL*>(attribute_data.back().data()) = *value ? CK_TRUE : CK_FALSE;
    search_template.push_back({type, attribute_data.back().data(),
                               static_cast<CK_ULONG>(attribute_data.back().size())});
}

}  // namespace pkcs11cpp
