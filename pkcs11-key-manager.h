class PKCS11KeyManager {
public:
    enum class KeyAlgorithm {
        RSA_2048, RSA_3072, RSA_4096,
        ECDSA_P256, ECDSA_P384, ECDSA_P521,
        EDDSA_ED25519,
        AES_128, AES_192, AES_256,
        DES3
    };
    
    struct KeyGenerationParams {
        KeyAlgorithm algorithm;
        std::string label;
        std::vector<CK_BYTE> id;
        bool tokenKey = true;
        bool sensitive = true;
        bool extractable = false;
        
        // RSA специфичные параметры
        std::optional<std::vector<CK_BYTE>> publicExponent;
        
        // EC специфичные параметры
        std::optional<std::vector<CK_BYTE>> ecParams;
        
        // Функциональные возможности
        bool canSign = false;
        bool canVerify = false;
        bool canEncrypt = false;
        bool canDecrypt = false;
        bool canWrap = false;
        bool canUnwrap = false;
        bool canDerive = false;
        
        // Метаданные
        std::map<std::string, std::string> metadata;
    };
    
    struct KeyPair {
        CK_OBJECT_HANDLE publicKey;
        CK_OBJECT_HANDLE privateKey;
        KeyAlgorithm algorithm;
        std::string label;
        std::vector<CK_BYTE> id;
    };
    
    KeyPair generateKeyPair(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        const KeyGenerationParams& params) {
        
        CK_MECHANISM mechanism;
        std::vector<CK_ATTRIBUTE> publicTemplate, privateTemplate;
        std::vector<std::vector<CK_BYTE>> attributeBuffers;
        
        // Настраиваем механизм и шаблоны в зависимости от алгоритма
        switch (params.algorithm) {
            case KeyAlgorithm::RSA_2048:
            case KeyAlgorithm::RSA_3072:
            case KeyAlgorithm::RSA_4096:
                setupRSAGeneration(params, mechanism, publicTemplate, 
                                 privateTemplate, attributeBuffers);
                break;
                
            case KeyAlgorithm::ECDSA_P256:
            case KeyAlgorithm::ECDSA_P384:
            case KeyAlgorithm::ECDSA_P521:
                setupECDSAGeneration(params, mechanism, publicTemplate,
                                   privateTemplate, attributeBuffers);
                break;
                
            case KeyAlgorithm::EDDSA_ED25519:
                setupEdDSAGeneration(params, mechanism, publicTemplate,
                                   privateTemplate, attributeBuffers);
                break;
                
            default:
                throw std::invalid_argument("Unsupported key algorithm for key pair generation");
        }
        
        // Генерируем ключевую пару
        CK_OBJECT_HANDLE publicKey, privateKey;
        CK_RV rv = functions->C_GenerateKeyPair(
            session, &mechanism,
            publicTemplate.data(), publicTemplate.size(),
            privateTemplate.data(), privateTemplate.size(),
            &publicKey, &privateKey);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Key pair generation failed: " + std::to_string(rv));
        }
        
        KeyPair result;
        result.publicKey = publicKey;
        result.privateKey = privateKey;
        result.algorithm = params.algorithm;
        result.label = params.label;
        result.id = params.id;
        
        // Добавляем метаданные если указаны
        if (!params.metadata.empty()) {
            addMetadataToKeys(session, functions, result, params.metadata);
        }
        
        return result;
    }
    
    CK_OBJECT_HANDLE generateSecretKey(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        const KeyGenerationParams& params) {
        
        if (!isSecretKeyAlgorithm(params.algorithm)) {
            throw std::invalid_argument("Algorithm is not for secret keys");
        }
        
        CK_MECHANISM mechanism;
        std::vector<CK_ATTRIBUTE> keyTemplate;
        std::vector<std::vector<CK_BYTE>> attributeBuffers;
        
        switch (params.algorithm) {
            case KeyAlgorithm::AES_128:
            case KeyAlgorithm::AES_192:
            case KeyAlgorithm::AES_256:
                setupAESGeneration(params, mechanism, keyTemplate, attributeBuffers);
                break;
                
            case KeyAlgorithm::DES3:
                setupDES3Generation(params, mechanism, keyTemplate, attributeBuffers);
                break;
                
            default:
                throw std::invalid_argument("Unsupported secret key algorithm");
        }
        
        CK_OBJECT_HANDLE secretKey;
        CK_RV rv = functions->C_GenerateKey(
            session, &mechanism,
            keyTemplate.data(), keyTemplate.size(),
            &secretKey);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Secret key generation failed: " + std::to_string(rv));
        }
        
        return secretKey;
    }
    
    // Генерация ключа с кастомными параметрами кривой для ECDSA
    KeyPair generateCustomECKey(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        const std::vector<CK_BYTE>& curveOID,
        const KeyGenerationParams& baseParams) {
        
        KeyGenerationParams params = baseParams;
        params.ecParams = curveOID;
        params.algorithm = KeyAlgorithm::ECDSA_P256; // Базовый тип
        
        return generateKeyPair(session, functions, params);
    }
    
private:
    void setupRSAGeneration(
        const KeyGenerationParams& params,
        CK_MECHANISM& mechanism,
        std::vector<CK_ATTRIBUTE>& publicTemplate,
        std::vector<CK_ATTRIBUTE>& privateTemplate,
        std::vector<std::vector<CK_BYTE>>& attributeBuffers) {
        
        mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        
        // Определяем размер модуля
        CK_ULONG modulusBits;
        switch (params.algorithm) {
            case KeyAlgorithm::RSA_2048: modulusBits = 2048; break;
            case KeyAlgorithm::RSA_3072: modulusBits = 3072; break;
            case KeyAlgorithm::RSA_4096: modulusBits = 4096; break;
            default: throw std::invalid_argument("Invalid RSA key size");
        }
        
        // Публичная экспонента (по умолчанию 65537)
        std::vector<CK_BYTE> publicExp = params.publicExponent.value_or(
            std::vector<CK_BYTE>{0x01, 0x00, 0x01});
        attributeBuffers.push_back(publicExp);
        
        // Шаблон публичного ключа
        CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
        CK_KEY_TYPE keyType = CKK_RSA;
        CK_BBOOL trueVal = CK_TRUE;
        CK_BBOOL falseVal = CK_FALSE;
        
        attributeBuffers.push_back(std::vector<CK_BYTE>(
            reinterpret_cast<CK_BYTE*>(&pubClass),
            reinterpret_cast<CK_BYTE*>(&pubClass) + sizeof(pubClass)));
        publicTemplate.push_back({CKA_CLASS, attributeBuffers.back().data(), 
                                 attributeBuffers.back().size()});
        
        attributeBuffers.push_back(std::vector<CK_BYTE>(
            reinterpret_cast<CK_BYTE*>(&keyType),
            reinterpret_cast<CK_BYTE*>(&keyType) + sizeof(keyType)));
        publicTemplate.push_back({CKA_KEY_TYPE, attributeBuffers.back().data(),
                                 attributeBuffers.back().size()});
        
        attributeBuffers.push_back(std::vector<CK_BYTE>(
            reinterpret_cast<CK_BYTE*>(&modulusBits),
            reinterpret_cast<CK_BYTE*>(&modulusBits) + sizeof(modulusBits)));
        publicTemplate.push_back({CKA_MODULUS_BITS, attributeBuffers.back().data(),
                                 attributeBuffers.back().size()});
        
        publicTemplate.push_back({CKA_PUBLIC_EXPONENT, publicExp.data(), publicExp.size()});
        
        if (params.tokenKey) {
            publicTemplate.push_back({CKA_TOKEN, &trueVal, sizeof(trueVal)});
        }
        
        if (params.canVerify) {
            publicTemplate.push_back({CKA_VERIFY, &trueVal, sizeof(trueVal)});
        }
        
        if (params.canEncrypt) {
            publicTemplate.push_back({CKA_ENCRYPT, &trueVal, sizeof(trueVal)});
        }
        
        // Добавляем label и id
        if (!params.label.empty()) {
            attributeBuffers.push_back(std::vector<CK_BYTE>(params.label.begin(), 
                                                           params.label.end()));
            publicTemplate.push_back({CKA_LABEL, attributeBuffers.back().data(),
                                     attributeBuffers.back().size()});
        }
        
        if (!params.id.empty()) {
            publicTemplate.push_back({CKA_ID, const_cast<CK_BYTE*>(params.id.data()),
                                     params.id.size()});
        }
        
        // Шаблон приватного ключа
        CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
        
        attributeBuffers.push_back(std::vector<CK_BYTE>(
            reinterpret_cast<CK_BYTE*>(&privClass),
            reinterpret_cast<CK_BYTE*>(&privClass) + sizeof(privClass)));
        privateTemplate.push_back({CKA_CLASS, attributeBuffers.back().data(),
                                  attributeBuffers.back().size()});
        
        attributeBuffers.push_back(std::vector<CK_BYTE>(
            reinterpret_cast<CK_BYTE*>(&keyType),
            reinterpret_cast<CK_BYTE*>(&keyType) + sizeof(keyType)));
        privateTemplate.push_back({CKA_KEY_TYPE, attributeBuffers.back().data(),
                                  attributeBuffers.back().size()});
        
        if (params.tokenKey) {
            privateTemplate.push_back({CKA_TOKEN, &trueVal, sizeof(trueVal)});
        }
        
        if (params.sensitive) {
            privateTemplate.push_back({CKA_SENSITIVE, &trueVal, sizeof(trueVal)});
        }
        
        CK_BBOOL extractableVal = params.extractable ? CK_TRUE : CK_FALSE;
        privateTemplate.push_back({CKA_EXTRACTABLE, &extractableVal, sizeof(extractableVal)});
        
        if (params.canSign) {
            privateTemplate.push_back({CKA_SIGN, &trueVal, sizeof(trueVal)});
        }
        
        if (params.canDecrypt) {
            privateTemplate.push_back({CKA_DECRYPT, &trueVal, sizeof(trueVal)});
        }
        
        // Добавляем label и id для приватного ключа
        if (!params.label.empty()) {
            attributeBuffers.push_back(std::vector<CK_BYTE>(params.label.begin(),
                                                           params.label.end()));
            privateTemplate.push_back({CKA_LABEL, attributeBuffers.back().data(),
                                      attributeBuffers.back().size()});
        }
        
        if (!params.id.empty()) {
            privateTemplate.push_back({CKA_ID, const_cast<CK_BYTE*>(params.id.data()),
                                      params.id.size()});
        }
    }
    
    void setupECDSAGeneration(
        const KeyGenerationParams& params,
        CK_MECHANISM& mechanism,
        std::vector<CK_ATTRIBUTE>& publicTemplate,
        std::vector<CK_ATTRIBUTE>& privateTemplate,
        std::vector<std::vector<CK_BYTE>>& attributeBuffers) {
        
        mechanism = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
        
        // Определяем параметры кривой
        std::vector<CK_BYTE> ecParams;
        
        if (params.ecParams) {
            ecParams = *params.ecParams;
        } else {
            switch (params.algorithm) {
                case KeyAlgorithm::ECDSA_P256:
                    // OID для secp256r1 (P-256)
                    ecParams = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
                    break;
                case KeyAlgorithm::ECDSA_P384:
                    // OID для secp384r1 (P-384)  
                    ecParams = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
                    break;
                case KeyAlgorithm::ECDSA_P521:
                    // OID для secp521r1 (P-521)
                    ecParams = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};
                    break;
                default:
                    throw std::invalid_argument("Invalid ECDSA curve");
            }
        }
        
        attributeBuffers.push_back(ecParams);
        
        // Базовые атрибуты для обеих частей ключа
        CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = CKK_ECDSA;
        CK_BBOOL trueVal = CK_TRUE;
        
        // Публичный ключ
        publicTemplate.push_back({CKA_CLASS, &pubClass, sizeof(pubClass)});
        publicTemplate.push_back({CKA_KEY_TYPE, &keyType, sizeof(keyType)});
        publicTemplate.push_back({CKA_EC_PARAMS, attributeBuffers.back().data(),
                                 attributeBuffers.back().size()});
        
        if (params.canVerify) {
            publicTemplate.push_back({CKA_VERIFY, &trueVal, sizeof(trueVal)});
        }
        
        // Приватный ключ
        privateTemplate.push_back({CKA_CLASS, &privClass, sizeof(privClass)});
        privateTemplate.push_back({CKA_KEY_TYPE, &keyType, sizeof(keyType)});
        
        if (params.canSign) {
            privateTemplate.push_back({CKA_SIGN, &trueVal, sizeof(trueVal)});
        }
        
        if (params.canDerive) {
            privateTemplate.push_back({CKA_DERIVE, &trueVal, sizeof(trueVal)});
        }
        
        // Общие атрибуты
        addCommonKeyAttributes(params, publicTemplate, privateTemplate, attributeBuffers);
    }
    
    void addCommonKeyAttributes(
        const KeyGenerationParams& params,
        std::vector<CK_ATTRIBUTE>& publicTemplate,
        std::vector<CK_ATTRIBUTE>& privateTemplate,
        std::vector<std::vector<CK_BYTE>>& attributeBuffers) {
        
        CK_BBOOL trueVal = CK_TRUE;
        CK_BBOOL falseVal = CK_FALSE;
        
        // Token объекты
        if (params.tokenKey) {
            publicTemplate.push_back({CKA_TOKEN, &trueVal, sizeof(trueVal)});
            privateTemplate.push_back({CKA_TOKEN, &trueVal, sizeof(trueVal)});
        }
        
        // Sensitive и extractable только для приватного ключа
        if (params.sensitive) {
            privateTemplate.push_back({CKA_SENSITIVE, &trueVal, sizeof(trueVal)});
        }
        
        CK_BBOOL extractableVal = params.extractable ? CK_TRUE : CK_FALSE;
        privateTemplate.push_back({CKA_EXTRACTABLE, &extractableVal, sizeof(extractableVal)});
        
        // Label
        if (!params.label.empty()) {
            attributeBuffers.push_back(std::vector<CK_BYTE>(params.label.begin(),
                                                           params.label.end()));
            publicTemplate.push_back({CKA_LABEL, attributeBuffers.back().data(),
                                     attributeBuffers.back().size()});
            
            attributeBuffers.push_back(std::vector<CK_BYTE>(params.label.begin(),
                                                           params.label.end()));
            privateTemplate.push_back({CKA_LABEL, attributeBuffers.back().data(),
                                      attributeBuffers.back().size()});
        }
        
        // ID
        if (!params.id.empty()) {
            publicTemplate.push_back({CKA_ID, const_cast<CK_BYTE*>(params.id.data()),
                                     params.id.size()});
            privateTemplate.push_back({CKA_ID, const_cast<CK_BYTE*>(params.id.data()),
                                      params.id.size()});
        }
    }
    
    bool isSecretKeyAlgorithm(KeyAlgorithm algorithm) const {
        return algorithm == KeyAlgorithm::AES_128 ||
               algorithm == KeyAlgorithm::AES_192 ||
               algorithm == KeyAlgorithm::AES_256 ||
               algorithm == KeyAlgorithm::DES3;
    }
};
