class PKCS11KeyTransport {
public:
    enum class WrapMechanism {
        AES_KEY_WRAP,
        AES_CBC_PAD,
        RSA_PKCS,
        RSA_OAEP
    };
    
    struct WrapResult {
        std::vector<CK_BYTE> wrappedKey;
        WrapMechanism mechanism;
        std::vector<CK_BYTE> iv; // Для механизмов, требующих IV
        CK_KEY_TYPE originalKeyType;
        std::vector<CK_ATTRIBUTE> keyTemplate;
    };
    
    // Wrap ключа с автоматическим выбором механизма
    WrapResult wrapKey(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        CK_OBJECT_HANDLE keyToWrap,
        CK_OBJECT_HANDLE wrappingKey,
        WrapMechanism preferredMechanism = WrapMechanism::AES_KEY_WRAP) {
        
        WrapResult result;
        result.mechanism = preferredMechanism;
        
        // Получаем информацию о ключе для wrap
        result.originalKeyType = getKeyType(session, functions, keyToWrap);
        result.keyTemplate = extractKeyTemplate(session, functions, keyToWrap);
        
        // Настраиваем механизм
        CK_MECHANISM mechanism;
        std::vector<CK_BYTE> iv;
        
        switch (preferredMechanism) {
            case WrapMechanism::AES_KEY_WRAP:
                mechanism = { CKM_AES_KEY_WRAP, nullptr, 0 };
                break;
                
            case WrapMechanism::AES_CBC_PAD:
                // Генерируем IV
                iv = generateRandomBytes(session, functions, 16);
                result.iv = iv;
                mechanism = { CKM_AES_CBC_PAD, iv.data(), iv.size() };
                break;
                
            case WrapMechanism::RSA_PKCS:
                mechanism = { CKM_RSA_PKCS, nullptr, 0 };
                break;
                
            case WrapMechanism::RSA_OAEP: {
                // Настраиваем OAEP параметры
                static CK_RSA_PKCS_OAEP_PARAMS oaepParams = {
                    CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr, 0
                };
                mechanism = { CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams) };
                break;
            }
        }
        
        // Определяем размер wrapped ключа
        CK_ULONG wrappedKeyLen;
        CK_RV rv = functions->C_WrapKey(
            session, &mechanism, wrappingKey, keyToWrap, 
            nullptr, &wrappedKeyLen);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to get wrapped key length");
        }
        
        // Выполняем wrap
        result.wrappedKey.resize(wrappedKeyLen);
        rv = functions->C_WrapKey(
            session, &mechanism, wrappingKey, keyToWrap,
            result.wrappedKey.data(), &wrappedKeyLen);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to wrap key");
        }
        
        result.wrappedKey.resize(wrappedKeyLen);
        return result;
    }
    
    // Unwrap ключа с восстановлением атрибутов
    CK_OBJECT_HANDLE unwrapKey(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        const WrapResult& wrapResult,
        CK_OBJECT_HANDLE unwrappingKey,
        const std::string& newLabel = "") {
        
        // Подготавливаем механизм для unwrap
        CK_MECHANISM mechanism;
        
        switch (wrapResult.mechanism) {
            case WrapMechanism::AES_KEY_WRAP:
                mechanism = { CKM_AES_KEY_WRAP, nullptr, 0 };
                break;
                
            case WrapMechanism::AES_CBC_PAD:
                mechanism = { 
                    CKM_AES_CBC_PAD, 
                    const_cast<CK_BYTE*>(wrapResult.iv.data()), 
                    wrapResult.iv.size() 
                };
                break;
                
            case WrapMechanism::RSA_PKCS:
                mechanism = { CKM_RSA_PKCS, nullptr, 0 };
                break;
                
            case WrapMechanism::RSA_OAEP: {
                static CK_RSA_PKCS_OAEP_PARAMS oaepParams = {
                    CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr, 0
                };
                mechanism = { CKM_RSA_PKCS_OAEP, &oaepParams, sizeof(oaepParams) };
                break;
            }
        }
        
        // Подготавливаем шаблон для нового ключа
        std::vector<CK_ATTRIBUTE> unwrapTemplate = wrapResult.keyTemplate;
        
        // Обновляем label если указан
        if (!newLabel.empty()) {
            updateLabelInTemplate(unwrapTemplate, newLabel);
        }
        
        // Выполняем unwrap
        CK_OBJECT_HANDLE unwrappedKey;
        CK_RV rv = functions->C_UnwrapKey(
            session, &mechanism, unwrappingKey,
            const_cast<CK_BYTE*>(wrapResult.wrappedKey.data()),
            wrapResult.wrappedKey.size(),
            unwrapTemplate.data(), unwrapTemplate.size(),
            &unwrappedKey);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to unwrap key: " + std::to_string(rv));
        }
        
        return unwrappedKey;
    }
    
private:
    std::vector<CK_BYTE> generateRandomBytes(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        size_t length) {
        
        std::vector<CK_BYTE> randomData(length);
        CK_RV rv = functions->C_GenerateRandom(
            session, randomData.data(), length);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to generate random data");
        }
        
        return randomData;
    }
    
    std::vector<CK_ATTRIBUTE> extractKeyTemplate(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        CK_OBJECT_HANDLE keyHandle) {
        
        // Определяем какие атрибуты извлекать
        std::vector<CK_ATTRIBUTE_TYPE> attributeTypes = {
            CKA_CLASS, CKA_KEY_TYPE, CKA_TOKEN, CKA_PRIVATE,
            CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_SIGN, CKA_VERIFY,
            CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP
        };
        
        std::vector<CK_ATTRIBUTE> attributes;
        for (auto attrType : attributeTypes) {
            attributes.push_back({attrType, nullptr, 0});
        }
        
        // Получаем размеры атрибутов
        CK_RV rv = functions->C_GetAttributeValue(
            session, keyHandle, attributes.data(), attributes.size());
        
        // Выделяем память и получаем значения
        std::vector<std::vector<CK_BYTE>> attributeData(attributes.size());
        for (size_t i = 0; i < attributes.size(); ++i) {
            if (attributes[i].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
                attributeData[i].resize(attributes[i].ulValueLen);
                attributes[i].pValue = attributeData[i].data();
            }
        }
        
        rv = functions->C_GetAttributeValue(
            session, keyHandle, attributes.data(), attributes.size());
        
        return attributes;
    }
};
