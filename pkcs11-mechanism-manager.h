class PKCS11MechanismManager {
private:
    struct MechanismInfo {
        CK_MECHANISM_TYPE type;
        CK_MECHANISM_INFO info;
        std::string name;
        std::set<std::string> capabilities;
    };
    
    std::unordered_map<CK_SLOT_ID, std::vector<MechanismInfo>> slotMechanisms;
    
public:
    void discoverMechanisms(
        CK_FUNCTION_LIST_PTR functions,
        CK_SLOT_ID slotId) {
        
        // Получаем список механизмов
        CK_ULONG mechanismCount;
        CK_RV rv = functions->C_GetMechanismList(
            slotId, nullptr, &mechanismCount);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to get mechanism count");
        }
        
        std::vector<CK_MECHANISM_TYPE> mechanisms(mechanismCount);
        rv = functions->C_GetMechanismList(
            slotId, mechanisms.data(), &mechanismCount);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to get mechanism list");
        }
        
        // Получаем информацию о каждом механизме
        std::vector<MechanismInfo> mechanismInfos;
        for (auto mechType : mechanisms) {
            MechanismInfo mechInfo;
            mechInfo.type = mechType;
            
            rv = functions->C_GetMechanismInfo(
                slotId, mechType, &mechInfo.info);
            
            if (rv == CKR_OK) {
                mechInfo.name = getMechanismName(mechType);
                mechInfo.capabilities = analyzeMechanismCapabilities(mechInfo.info);
                mechanismInfos.push_back(mechInfo);
            }
        }
        
        slotMechanisms[slotId] = std::move(mechanismInfos);
    }
    
    // Выбор оптимального механизма для операции
    std::optional<CK_MECHANISM_TYPE> selectBestMechanism(
        CK_SLOT_ID slotId,
        const std::string& operation,
        CK_KEY_TYPE keyType,
        CK_ULONG keySize = 0) const {
        
        auto it = slotMechanisms.find(slotId);
        if (it == slotMechanisms.end()) {
            return std::nullopt;
        }
        
        std::vector<const MechanismInfo*> candidates;
        
        // Фильтруем механизмы по операции и типу ключа
        for (const auto& mech : it->second) {
            if (mech.capabilities.count(operation) &&
                isCompatibleWithKeyType(mech.type, keyType)) {
                
                // Проверяем размер ключа если указан
                if (keySize > 0) {
                    if (keySize < mech.info.ulMinKeySize ||
                        keySize > mech.info.ulMaxKeySize) {
                        continue;
                    }
                }
                
                candidates.push_back(&mech);
            }
        }
        
        if (candidates.empty()) {
            return std::nullopt;
        }
        
        // Выбираем наиболее предпочтительный механизм
        auto best = selectPreferredMechanism(operation, keyType, candidates);
        return best ? std::make_optional(best->type) : std::nullopt;
    }
    
    // Создание оптимизированного механизма с параметрами
    CK_MECHANISM createOptimizedMechanism(
        CK_MECHANISM_TYPE mechanismType,
        const std::map<std::string, std::any>& parameters = {}) const {
        
        CK_MECHANISM mechanism = { mechanismType, nullptr, 0 };
        
        // Настройка специфичных параметров для разных механизмов
        switch (mechanismType) {
            case CKM_RSA_PKCS_OAEP: {
                static CK_RSA_PKCS_OAEP_PARAMS oaepParams;
                
                // Устанавливаем параметры по умолчанию
                oaepParams.hashAlg = CKM_SHA256;
                oaepParams.mgf = CKG_MGF1_SHA256;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = nullptr;
                oaepParams.ulSourceDataLen = 0;
                
                // Перезаписываем параметрами из map если есть
                if (parameters.count("hashAlg")) {
                    oaepParams.hashAlg = std::any_cast<CK_MECHANISM_TYPE>(
                        parameters.at("hashAlg"));
                }
                
                mechanism.pParameter = &oaepParams;
                mechanism.ulParameterLen = sizeof(oaepParams);
                break;
            }
            
            case CKM_AES_GCM: {
                static CK_GCM_PARAMS gcmParams;
                
                // Устанавливаем значения по умолчанию
                gcmParams.ulIvLen = 12; // 96 бит
                gcmParams.ulAADLen = 0;
                gcmParams.ulTagBits = 128;
                
                if (parameters.count("iv")) {
                    auto iv = std::any_cast<std::vector<CK_BYTE>>(
                        parameters.at("iv"));
                    gcmParams.pIv = iv.data();
                    gcmParams.ulIvLen = iv.size();
                }
                
                mechanism.pParameter = &gcmParams;
                mechanism.ulParameterLen = sizeof(gcmParams);
                break;
            }
            
            case CKM_ECDH1_DERIVE: {
                static CK_ECDH1_DERIVE_PARAMS ecdhParams;
                
                ecdhParams.kdf = CKD_NULL;
                ecdhParams.ulSharedDataLen = 0;
                ecdhParams.pSharedData = nullptr;
                
                if (parameters.count("publicKey")) {
                    auto pubKey = std::any_cast<std::vector<CK_BYTE>>(
                        parameters.at("publicKey"));
                    ecdhParams.pPublicData = pubKey.data();
                    ecdhParams.ulPublicDataLen = pubKey.size();
                }
                
                mechanism.pParameter = &ecdhParams;
                mechanism.ulParameterLen = sizeof(ecdhParams);
                break;
            }
        }
        
        return mechanism;
    }
    
private:
    std::string getMechanismName(CK_MECHANISM_TYPE type) const {
        static const std::unordered_map<CK_MECHANISM_TYPE, std::string> nameMap = {
            {CKM_RSA_PKCS, "RSA_PKCS"},
            {CKM_RSA_PKCS_OAEP, "RSA_PKCS_OAEP"},
            {CKM_RSA_PSS, "RSA_PSS"},
            {CKM_AES_KEY_GEN, "AES_KEY_GEN"},
            {CKM_AES_ECB, "AES_ECB"},
            {CKM_AES_CBC, "AES_CBC"},
            {CKM_AES_CBC_PAD, "AES_CBC_PAD"},
            {CKM_AES_GCM, "AES_GCM"},
            {CKM_AES_KEY_WRAP, "AES_KEY_WRAP"},
            {CKM_SHA256, "SHA256"},
            {CKM_SHA256_RSA_PKCS, "SHA256_RSA_PKCS"},
            {CKM_ECDSA, "ECDSA"},
            {CKM_ECDH1_DERIVE, "ECDH1_DERIVE"}
        };
        
        auto it = nameMap.find(type);
        return it != nameMap.end() ? it->second : "UNKNOWN_" + std::to_string(type);
    }
    
    std::set<std::string> analyzeMechanismCapabilities(
        const CK_MECHANISM_INFO& info) const {
        
        std::set<std::string> capabilities;
        
        if (info.flags & CKF_ENCRYPT) capabilities.insert("encrypt");
        if (info.flags & CKF_DECRYPT) capabilities.insert("decrypt");
        if (info.flags & CKF_SIGN) capabilities.insert("sign");
        if (info.flags & CKF_VERIFY) capabilities.insert("verify");
        if (info.flags & CKF_WRAP) capabilities.insert("wrap");
        if (info.flags & CKF_UNWRAP) capabilities.insert("unwrap");
        if (info.flags & CKF_DERIVE) capabilities.insert("derive");
        if (info.flags & CKF_GENERATE) capabilities.insert("generate");
        if (info.flags & CKF_GENERATE_KEY_PAIR) capabilities.insert("generate_keypair");
        
        return capabilities;
    }
};
