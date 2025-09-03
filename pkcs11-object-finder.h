class PKCS11ObjectFinder {
private:
    struct ObjectInfo {
        CK_OBJECT_HANDLE handle;
        CK_OBJECT_CLASS objectClass;
        CK_KEY_TYPE keyType;
        std::vector<CK_BYTE> id;
        std::string label;
        std::chrono::steady_clock::time_point cacheTime;
    };
    
    mutable std::unordered_map<std::string, std::vector<ObjectInfo>> objectCache;
    mutable std::mutex cacheMutex;
    std::chrono::seconds cacheTimeout{300}; // 5 минут
    
public:
    class SearchCriteria {
    public:
        std::optional<CK_OBJECT_CLASS> objectClass;
        std::optional<CK_KEY_TYPE> keyType;
        std::optional<std::vector<CK_BYTE>> id;
        std::optional<std::string> label;
        std::optional<CK_ULONG> modulusBits;
        std::optional<bool> tokenObject;
        std::optional<bool> privateObject;
        std::optional<bool> sensitive;
        std::optional<bool> extractable;
        
        // Функциональные критерии
        std::optional<bool> canSign;
        std::optional<bool> canVerify;
        std::optional<bool> canEncrypt;
        std::optional<bool> canDecrypt;
        std::optional<bool> canWrap;
        std::optional<bool> canUnwrap;
        
        SearchCriteria& withClass(CK_OBJECT_CLASS cls) {
            objectClass = cls;
            return *this;
        }
        
        SearchCriteria& withKeyType(CK_KEY_TYPE type) {
            keyType = type;
            return *this;
        }
        
        SearchCriteria& withLabel(const std::string& lbl) {
            label = lbl;
            return *this;
        }
        
        SearchCriteria& withModulusBits(CK_ULONG bits) {
            modulusBits = bits;
            return *this;
        }
        
        SearchCriteria& forSigning(bool required = true) {
            canSign = required;
            return *this;
        }
        
        SearchCriteria& forEncryption(bool required = true) {
            canEncrypt = required;
            return *this;
        }
    };
    
    std::vector<CK_OBJECT_HANDLE> findObjects(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        const SearchCriteria& criteria) const {
        
        // Проверяем кэш
        std::string cacheKey = generateCacheKey(criteria);
        {
            std::lock_guard<std::mutex> lock(cacheMutex);
            auto it = objectCache.find(cacheKey);
            if (it != objectCache.end()) {
                auto now = std::chrono::steady_clock::now();
                if (now - it->second[0].cacheTime < cacheTimeout) {
                    std::vector<CK_OBJECT_HANDLE> handles;
                    for (const auto& obj : it->second) {
                        handles.push_back(obj.handle);
                    }
                    return handles;
                }
            }
        }
        
        // Строим шаблон поиска
        std::vector<CK_ATTRIBUTE> searchTemplate;
        std::vector<std::vector<CK_BYTE>> attributeData;
        
        buildSearchTemplate(criteria, searchTemplate, attributeData);
        
        // Выполняем поиск
        CK_RV rv = functions->C_FindObjectsInit(
            session, searchTemplate.data(), searchTemplate.size());
        
        if (rv != CKR_OK) {
            throw std::runtime_error("C_FindObjectsInit failed");
        }
        
        std::vector<CK_OBJECT_HANDLE> foundObjects;
        CK_OBJECT_HANDLE objects[100];
        CK_ULONG objectCount;
        
        do {
            rv = functions->C_FindObjects(session, objects, 100, &objectCount);
            if (rv == CKR_OK) {
                for (CK_ULONG i = 0; i < objectCount; ++i) {
                    foundObjects.push_back(objects[i]);
                }
            }
        } while (rv == CKR_OK && objectCount > 0);
        
        functions->C_FindObjectsFinal(session);
        
        // Кэшируем результаты
        cacheResults(cacheKey, foundObjects, session, functions);
        
        return foundObjects;
    }
    
private:
    void buildSearchTemplate(
        const SearchCriteria& criteria,
        std::vector<CK_ATTRIBUTE>& searchTemplate,
        std::vector<std::vector<CK_BYTE>>& attributeData) const {
        
        if (criteria.objectClass) {
            attributeData.emplace_back(sizeof(CK_OBJECT_CLASS));
            *reinterpret_cast<CK_OBJECT_CLASS*>(attributeData.back().data()) = 
                *criteria.objectClass;
            searchTemplate.push_back({
                CKA_CLASS, 
                attributeData.back().data(), 
                attributeData.back().size()
            });
        }
        
        if (criteria.keyType) {
            attributeData.emplace_back(sizeof(CK_KEY_TYPE));
            *reinterpret_cast<CK_KEY_TYPE*>(attributeData.back().data()) = 
                *criteria.keyType;
            searchTemplate.push_back({
                CKA_KEY_TYPE, 
                attributeData.back().data(), 
                attributeData.back().size()
            });
        }
        
        if (criteria.label) {
            attributeData.emplace_back(criteria.label->begin(), criteria.label->end());
            searchTemplate.push_back({
                CKA_LABEL, 
                attributeData.back().data(), 
                attributeData.back().size()
            });
        }
        
        // Добавляем остальные критерии...
        addBooleanAttribute(criteria.canSign, CKA_SIGN, searchTemplate, attributeData);
        addBooleanAttribute(criteria.canEncrypt, CKA_ENCRYPT, searchTemplate, attributeData);
        // ... и т.д.
    }
    
    void addBooleanAttribute(
        const std::optional<bool>& value,
        CK_ATTRIBUTE_TYPE type,
        std::vector<CK_ATTRIBUTE>& searchTemplate,
        std::vector<std::vector<CK_BYTE>>& attributeData) const {
        
        if (value) {
            attributeData.emplace_back(sizeof(CK_BBOOL));
            *reinterpret_cast<CK_BBOOL*>(attributeData.back().data()) = 
                *value ? CK_TRUE : CK_FALSE;
            searchTemplate.push_back({
                type, 
                attributeData.back().data(), 
                attributeData.back().size()
            });
        }
    }
};
