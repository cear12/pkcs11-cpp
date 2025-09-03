class PKCS11KeyDerivation {
public:
    enum class KDFType {
        ECDH1_DERIVE,
        SP800_108_COUNTER_KDF,
        PBKDF2,
        SCRYPT,
        CUSTOM_KDF
    };
    
    struct DerivationParams {
        KDFType kdfType;
        CK_OBJECT_HANDLE baseKey;
        
        // ECDH параметры
        std::vector<CK_BYTE> publicKeyData;
        CK_ULONG sharedDataLen = 0;
        CK_BYTE_PTR sharedData = nullptr;
        
        // SP800-108 параметры
        std::vector<CK_BYTE> label;
        std::vector<CK_BYTE> context;
        CK_ULONG counterLocation = 0; // 0 = before fixed data
        
        // PBKDF2 параметры
        std::vector<CK_BYTE> salt;
        CK_ULONG iterations = 100000;
        CK_MECHANISM_TYPE prf = CKM_SHA256_HMAC;
        
        // Параметры для производного ключа
        CK_KEY_TYPE derivedKeyType = CKK_AES;
        CK_ULONG derivedKeyLength = 32; // байт
        std::string derivedKeyLabel;
        std::vector<CK_BYTE> derivedKeyId;
        bool tokenKey = true;
        bool sensitive = true;
        bool extractable = false;
        
        // Функциональные возможности производного ключа
        bool canEncrypt = true;
        bool canDecrypt = true;
        bool canWrap = false;
        bool canUnwrap = false;
    };
    
    // ECDH деривация ключа
    CK_OBJECT_HANDLE deriveECDHKey(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        const DerivationParams& params) {
        
        if (params.kdfType != KDFType::ECDH1_DERIVE) {
            throw std::invalid_argument("Invalid KDF type for ECDH");
        }
        
        // Настраиваем параметры ECDH
        CK_ECDH1_DERIVE_PARAMS ecdhParams;
        ecdhParams.kdf = CKD_NULL; // Без дополнительной KDF
        ecdhParams.ulSharedDataLen = params.sharedDataLen;
        ecdhParams.pSharedData = params.sharedData;
        ecdhParams.ulPublicDataLen = params.publicKeyData.size();
        ecdhParams.pPublicData = const_cast<CK_BYTE*>(params.publicKeyData.data());
        
        CK_MECHANISM mechanism = {
            CKM_ECDH1_DERIVE,
            &ecdhParams,
            sizeof(ecdhParams)
        };
        
        // Подготавливаем шаблон для производного ключа
        auto keyTemplate = buildDerivedKeyTemplate(params);
        
        CK_OBJECT_HANDLE derivedKey;
        CK_RV rv = functions->C_DeriveKey(
            session, &mechanism, params.baseKey,
            keyTemplate.data(), keyTemplate.size(), &derivedKey);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("ECDH key derivation failed: " + std::to_string(rv));
        }
        
        return derivedKey;
    }
    
    // SP800-108 Counter KDF
    CK_OBJECT_HANDLE deriveSP800_108Key(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        const DerivationParams& params) {
        
        if (params.kdfType != KDFType::SP800_108_COUNTER_KDF) {
            throw std::invalid_argument("Invalid KDF type for SP800-108");
        }
        
        // Подготавливаем параметры SP800-108
        CK_SP800_108_COUNTER_FORMAT counterFormat;
        counterFormat.bLittleEndian = CK_FALSE;
        counterFormat.ulWidthInBits = 32;
        
        // Строим KDF data
        std::vector<CK_BYTE> kdfData;
        
        // Добавляем label
        if (!params.label.empty()) {
            kdfData.insert(kdfData.end(), params.label.begin(), params.label.end());
            kdfData.push_back(0x00); // Separator
        }
        
        // Добавляем context
        if (!params.context.empty()) {
            kdfData.insert(kdfData.end(), params.context.begin(), params.context.end());
        }
        
        // Добавляем длину ключа в битах (big-endian)
        CK_ULONG keyLenBits = params.derivedKeyLength * 8;
        kdfData.push_back((keyLenBits >> 24) & 0xFF);
        kdfData.push_back((keyLenBits >> 16) & 0xFF);
        kdfData.push_back((keyLenBits >> 8) & 0xFF);
        kdfData.push_back(keyLenBits & 0xFF);
        
        CK_SP800_108_KDF_PARAMS kdfParams;
        kdfParams.macType = CKM_AES_CMAC; // или CKM_SHA256_HMAC
        kdfParams.ulNumberOfDataParams = 1;
        
        CK_SP800_108_DKM_LENGTH_FORMAT dkmFormat;
        dkmFormat.dkmLengthMethod = CK_SP800_108_DKM_LENGTH_SL_METHOD;
        dkmFormat.bLittleEndian = CK_FALSE;
        dkmFormat.ulWidthInBits = 32;
        
        kdfParams.pDataParams = nullptr; // Упрощенная версия
        kdfParams.ulAdditionalDerivedKeys = 0;
        kdfParams.pAdditionalDerivedKeys = nullptr;
        
        CK_MECHANISM mechanism = {
            CKM_SP800_108_COUNTER_KDF,
            &kdfParams,
            sizeof(kdfParams)
        };
        
        auto keyTemplate = buildDerivedKeyTemplate(params);
        
        CK_OBJECT_HANDLE derivedKey;
        CK_RV rv = functions->C_DeriveKey(
            session, &mechanism, params.baseKey,
            keyTemplate.data(), keyTemplate.size(), &derivedKey);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("SP800-108 key derivation failed: " + std::to_string(rv));
        }
        
        return derivedKey;
    }
    
    // PBKDF2 деривация
    CK_OBJECT_HANDLE derivePBKDF2Key(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        const std::string& password,
        const DerivationParams& params) {
        
        if (params.kdfType != KDFType::PBKDF2) {
            throw std::invalid_argument("Invalid KDF type for PBKDF2");
        }
        
        // Настраиваем параметры PBKDF2
        CK_PKCS5_PBKD2_PARAMS pbkdf2Params;
        pbkdf2Params.saltSource = CKZ_SALT_SPECIFIED;
        pbkdf2Params.pSaltSourceData = const_cast<CK_BYTE*>(params.salt.data());
        pbkdf2Params.ulSaltSourceDataLen = params.salt.size();
        pbkdf2Params.iterations = params.iterations;
        pbkdf2Params.prf = params.prf;
        pbkdf2Params.pPrfData = nullptr;
        pbkdf2Params.ulPrfDataLen = 0;
        pbkdf2Params.pPassword = (CK_UTF8CHAR_PTR)password.c_str();
        pbkdf2Params.ulPasswordLen = password.length();
        
        CK_MECHANISM mechanism = {
            CKM_PKCS5_PBKD2,
            &pbkdf2Params,
            sizeof(pbkdf2Params)
        };
        
        auto keyTemplate = buildDerivedKeyTemplate(params);
        
        CK_OBJECT_HANDLE derivedKey;
        CK_RV rv = functions->C_DeriveKey(
            session, &mechanism, CK_INVALID_HANDLE, // Нет базового ключа для PBKDF2
            keyTemplate.data(), keyTemplate.size(), &derivedKey);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("PBKDF2 key derivation failed: " + std::to_string(rv));
        }
        
        return derivedKey;
    }
    
    // Построение цепочки деривации ключей
    std::vector<CK_OBJECT_HANDLE> deriveKeyChain(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        CK_OBJECT_HANDLE masterKey,
        const std::vector<DerivationParams>& derivationChain) {
        
        std::vector<CK_OBJECT_HANDLE> derivedKeys;
        CK_OBJECT_HANDLE currentKey = masterKey;
        
        for (const auto& params : derivationChain) {
            DerivationParams chainParams = params;
            chainParams.baseKey = currentKey;
            
            CK_OBJECT_HANDLE derivedKey;
            
            switch (params.kdfType) {
                case KDFType::ECDH1_DERIVE:
                    derivedKey = deriveECDHKey(session, functions, chainParams);
                    break;
                    
                case KDFType::SP800_108_COUNTER_KDF:
                    derivedKey = deriveSP800_108Key(session, functions, chainParams);
                    break;
                    
                default:
                    throw std::invalid_argument("Unsupported KDF type in chain");
            }
            
            derivedKeys.push_back(derivedKey);
            currentKey = derivedKey; // Используем производный ключ для следующей деривации
        }
        
        return derivedKeys;
    }
    
    // Взаимная ECDH деривация (для обеих сторон)
    struct ECDHKeyAgreement {
        CK_OBJECT_HANDLE localPrivateKey;
        CK_OBJECT_HANDLE localPublicKey;
        std::vector<CK_BYTE> remotePublicKey;
        CK_OBJECT_HANDLE sharedSecret;
        std::vector<CK_OBJECT_HANDLE> derivedKeys;
    };
    
    ECDHKeyAgreement performECDHKeyAgreement(
        CK_SESSION_HANDLE session,
        CK_FUNCTION_LIST_PTR functions,
        CK_OBJECT_HANDLE localPrivateKey,
        const std::vector<CK_BYTE>& remotePublicKey,
        const std::vector<DerivationParams>& keyDerivationChain) {
        
        ECDHKeyAgreement agreement;
        agreement.localPrivateKey = localPrivateKey;
        agreement.remotePublicKey = remotePublicKey;
        
        // Выполняем ECDH для получения общего секрета
        DerivationParams ecdhParams;
        ecdhParams.kdfType = KDFType::ECDH1_DERIVE;
        ecdhParams.baseKey = localPrivateKey;
        ecdhParams.publicKeyData = remotePublicKey;
        ecdhParams.derivedKeyType = CKK_GENERIC_SECRET;
        ecdhParams.derivedKeyLength = 32; // 256 бит
        ecdhParams.derivedKeyLabel = "ECDH_SHARED_SECRET";
        ecdhParams.sensitive = true;
        ecdhParams.extractable = false;
        ecdhParams.canEncrypt = false;
        ecdhParams.canDecrypt = false;
        
        agreement.sharedSecret = deriveECDHKey(session, functions, ecdhParams);
        
        // Производим дополнительные ключи из общего секрета
        if (!keyDerivationChain.empty()) {
            agreement.derivedKeys = deriveKeyChain(session, functions, 
                                                 agreement.sharedSecret, 
                                                 keyDerivationChain);
        }
        
        return agreement;
    }
    
private:
    std::vector<CK_ATTRIBUTE> buildDerivedKeyTemplate(const DerivationParams& params) {
        std::vector<CK_ATTRIBUTE> keyTemplate;
        std::vector<std::vector<CK_BYTE>> attributeBuffers;
        
        // Класс объекта
        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        keyTemplate.push_back({CKA_CLASS, &keyClass, sizeof(keyClass)});
        
        // Тип ключа
        keyTemplate.push_back({CKA_KEY_TYPE, const_cast<CK_KEY_TYPE*>(&params.derivedKeyType), 
                              sizeof(params.derivedKeyType)});
        
        // Длина ключа
        keyTemplate.push_back({CKA_VALUE_LEN, const_cast<CK_ULONG*>(&params.derivedKeyLength),
                              sizeof(params.derivedKeyLength)});
        
        // Флаги
        CK_BBOOL trueVal = CK_TRUE;
        CK_BBOOL falseVal = CK_FALSE;
        
        CK_BBOOL tokenVal = params.tokenKey ? CK_TRUE : CK_FALSE;
        keyTemplate.push_back({CKA_TOKEN, &tokenVal, sizeof(tokenVal)});
        
        CK_BBOOL sensitiveVal = params.sensitive ? CK_TRUE : CK_FALSE;
        keyTemplate.push_back({CKA_SENSITIVE, &sensitiveVal, sizeof(sensitiveVal)});
        
        CK_BBOOL extractableVal = params.extractable ? CK_TRUE : CK_FALSE;
        keyTemplate.push_back({CKA_EXTRACTABLE, &extractableVal, sizeof(extractableVal)});
        
        // Функциональные возможности
        if (params.canEncrypt) {
            keyTemplate.push_back({CKA_ENCRYPT, &trueVal, sizeof(trueVal)});
        }
        if (params.canDecrypt) {
            keyTemplate.push_back({CKA_DECRYPT, &trueVal, sizeof(trueVal)});
        }
        if (params.canWrap) {
            keyTemplate.push_back({CKA_WRAP, &trueVal, sizeof(trueVal)});
        }
        if (params.canUnwrap) {
            keyTemplate.push_back({CKA_UNWRAP, &trueVal, sizeof(trueVal)});
        }
        
        // Label
        if (!params.derivedKeyLabel.empty()) {
            attributeBuffers.push_back(std::vector<CK_BYTE>(
                params.derivedKeyLabel.begin(), params.derivedKeyLabel.end()));
            keyTemplate.push_back({CKA_LABEL, attributeBuffers.back().data(),
                                  attributeBuffers.back().size()});
        }
        
        // ID
        if (!params.derivedKeyId.empty()) {
            keyTemplate.push_back({CKA_ID, const_cast<CK_BYTE*>(params.derivedKeyId.data()),
                                  params.derivedKeyId.size()});
        }
        
        return keyTemplate;
    }
};
