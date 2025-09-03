class PKCS11AttributeManager {
public:
    // Структура для хранения метаданных атрибута
    struct AttributeMetadata {
        CK_ATTRIBUTE_TYPE type;
        std::string name;
        bool isModifiable;
        bool isSensitive;
        size_t expectedSize;
        std::function<bool(const std::vector<CK_BYTE>&)> validator;
    };
    
    // Расширенный класс для работы с атрибутами
    class AttributeSet {
    private:
        std::vector<CK_ATTRIBUTE> attributes;
        std::vector<std::vector<CK_BYTE>> attributeData;
        std::unordered_map<CK_ATTRIBUTE_TYPE, size_t> attributeIndex;
        
    public:
        // Добавление атрибута с валидацией
        AttributeSet& addAttribute(
            CK_ATTRIBUTE_TYPE type, 
            const std::vector<CK_BYTE>& value,
            bool validate = true) {
            
            if (validate) {
                validateAttribute(type, value);
            }
            
            // Проверяем, существует ли уже атрибут
            auto it = attributeIndex.find(type);
            if (it != attributeIndex.end()) {
                // Обновляем существующий
                size_t index = it->second;
                attributeData[index] = value;
                attributes[index].pValue = attributeData[index].data();
                attributes[index].ulValueLen = attributeData[index].size();
            } else {
                // Добавляем новый
                size_t index = attributes.size();
                attributeIndex[type] = index;
                attributeData.push_back(value);
                attributes.push_back({
                    type,
                    attributeData.back().data(),
                    attributeData.back().size()
                });
            }
            
            return *this;
        }
        
        // Специализированные методы для разных типов атрибутов
        AttributeSet& addBoolean(CK_ATTRIBUTE_TYPE type, bool value) {
            CK_BBOOL boolValue = value ? CK_TRUE : CK_FALSE;
            return addAttribute(type, 
                std::vector<CK_BYTE>(
                    reinterpret_cast<CK_BYTE*>(&boolValue),
                    reinterpret_cast<CK_BYTE*>(&boolValue) + sizeof(boolValue)));
        }
        
        AttributeSet& addULong(CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
            return addAttribute(type,
                std::vector<CK_BYTE>(
                    reinterpret_cast<CK_BYTE*>(&value),
                    reinterpret_cast<CK_BYTE*>(&value) + sizeof(value)));
        }
        
        AttributeSet& addString(CK_ATTRIBUTE_TYPE type, const std::string& value) {
            return addAttribute(type,
                std::vector<CK_BYTE>(value.begin(), value.end()));
        }
        
        AttributeSet& addBytes(CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value) {
            return addAttribute(type, value);
        }
        
        // Создание объекта с расширенными метаданными
        AttributeSet& addMetadata(const std::string& key, const std::string& value) {
            // Используем vendor-specific атрибуты для метаданных
            CK_ATTRIBUTE_TYPE vendorType = CKA_VENDOR_DEFINED + 
                std::hash<std::string>{}(key) % 1000;
            
            std::string metadataValue = key + "=" + value;
            return addString(vendorType, metadataValue);
        }
        
        // Получение указателей для PKCS#11 API
        CK_ATTRIBUTE* data() { return attributes.data(); }
        size_t size() const { return attributes.size(); }
        
        // Проверка наличия атрибута
        bool hasAttribute(CK_ATTRIBUTE_TYPE type) const {
            return attributeIndex.count(type) > 0;
        }
        
        // Получение значения атрибута
        std::optional<std::vector<CK_BYTE>> getAttribute(CK_ATTRIBUTE_TYPE type) const {
            auto it = attributeIndex.find(type);
            if (it != attributeIndex.end()) {
                return attributeData[it->second];
            }
            return std::nullopt;
        }
    };
    
    // Модификация атрибутов существующего объекта
    void modifyObjectAttributes(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        CK_OBJECT_HANDLE object,
        const AttributeSet& newAttributes) {
        
        // Получаем текущие атрибуты объекта
        auto currentAttributes = readObjectAttributes(session, functions, object);
        
        // Проверяем какие атрибуты можно модифицировать
        std::vector<CK_ATTRIBUTE> modifiableAttributes;
        
        for (size_t i = 0; i < newAttributes.size(); ++i) {
            CK_ATTRIBUTE_TYPE type = newAttributes.data()[i].type;
            
            if (isAttributeModifiable(type)) {
                modifiableAttributes.push_back(newAttributes.data()[i]);
            } else {
                // Выводим предупреждение о немодифицируемом атрибуте
                logWarning("Attempt to modify read-only attribute: " + 
                          std::to_string(type));
            }
        }
        
        if (!modifiableAttributes.empty()) {
            CK_RV rv = functions->C_SetAttributeValue(
                session, object, 
                modifiableAttributes.data(), 
                modifiableAttributes.size());
                
            if (rv != CKR_OK) {
                throw std::runtime_error("Failed to modify attributes: " + 
                                       std::to_string(rv));
            }
        }
    }
    
    // Создание расширенного шаблона для различных типов ключей
    static AttributeSet createRSAPrivateKeyTemplate(
        const std::string& label,
        const std::vector<CK_BYTE>& id,
        bool extractable = false,
        bool sensitive = true) {
        
        AttributeSet attrs;
        
        return attrs
            .addULong(CKA_CLASS, CKO_PRIVATE_KEY)
            .addULong(CKA_KEY_TYPE, CKK_RSA)
            .addBoolean(CKA_TOKEN, true)
            .addBoolean(CKA_PRIVATE, true)
            .addBoolean(CKA_SENSITIVE, sensitive)
            .addBoolean(CKA_EXTRACTABLE, extractable)
            .addBoolean(CKA_SIGN, true)
            .addBoolean(CKA_DECRYPT, true)
            .addString(CKA_LABEL, label)
            .addBytes(CKA_ID, id)
            .addMetadata("created", getCurrentTimestamp())
            .addMetadata("purpose", "signing_and_decryption");
    }
    
    static AttributeSet createAESKeyTemplate(
        const std::string& label,
        const std::vector<CK_BYTE>& id,
        CK_ULONG keySize = 256) {
        
        AttributeSet attrs;
        
        return attrs
            .addULong(CKA_CLASS, CKO_SECRET_KEY)
            .addULong(CKA_KEY_TYPE, CKK_AES)
            .addULong(CKA_VALUE_LEN, keySize / 8)
            .addBoolean(CKA_TOKEN, true)
            .addBoolean(CKA_SENSITIVE, true)
            .addBoolean(CKA_EXTRACTABLE, false)
            .addBoolean(CKA_ENCRYPT, true)
            .addBoolean(CKA_DECRYPT, true)
            .addBoolean(CKA_WRAP, true)
            .addBoolean(CKA_UNWRAP, true)
            .addString(CKA_LABEL, label)
            .addBytes(CKA_ID, id)
            .addMetadata("created", getCurrentTimestamp())
            .addMetadata("algorithm", "AES-" + std::to_string(keySize));
    }
    
private:
    static bool isAttributeModifiable(CK_ATTRIBUTE_TYPE type) {
        // Список модифицируемых атрибутов согласно PKCS#11 спецификации
        static const std::set<CK_ATTRIBUTE_TYPE> modifiableAttrs = {
            CKA_LABEL, CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY,
            CKA_WRAP, CKA_UNWRAP, CKA_DERIVE, CKA_SENSITIVE, CKA_EXTRACTABLE
        };
        
        return modifiableAttrs.count(type) > 0 || 
               type >= CKA_VENDOR_DEFINED; // Vendor-specific атрибуты
    }
    
    static void validateAttribute(CK_ATTRIBUTE_TYPE type, const std::vector<CK_BYTE>& value) {
        // Базовая валидация размеров для известных атрибутов
        switch (type) {
            case CKA_CLASS:
            case CKA_KEY_TYPE:
                if (value.size() != sizeof(CK_ULONG)) {
                    throw std::invalid_argument("Invalid size for ULONG attribute");
                }
                break;
                
            case CKA_TOKEN:
            case CKA_PRIVATE:
            case CKA_SENSITIVE:
            case CKA_EXTRACTABLE:
            case CKA_SIGN:
            case CKA_VERIFY:
            case CKA_ENCRYPT:
            case CKA_DECRYPT:
            case CKA_WRAP:
            case CKA_UNWRAP:
                if (value.size() != sizeof(CK_BBOOL)) {
                    throw std::invalid_argument("Invalid size for BOOLEAN attribute");
                }
                break;
        }
    }
    
    static std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }
};
