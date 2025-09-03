class PKCS11HealthMonitor {
private:
    struct SlotInfo {
        CK_SLOT_ID slotId;
        CK_SLOT_INFO slotInfo;
        CK_TOKEN_INFO tokenInfo;
        std::vector<CK_MECHANISM_TYPE> mechanisms;
        std::chrono::steady_clock::time_point lastCheck;
        bool isHealthy;
        std::vector<std::string> issues;
    };
    
    mutable std::mutex monitorMutex;
    std::map<CK_SLOT_ID, SlotInfo> slots;
    std::thread monitorThread;
    std::atomic<bool> monitoring{false};
    
public:
    struct HealthReport {
        std::chrono::steady_clock::time_point timestamp;
        bool overallHealth;
        std::map<CK_SLOT_ID, SlotInfo> slotStatus;
        std::vector<std::string> criticalIssues;
        std::vector<std::string> warnings;
        
        // Метрики производительности
        struct PerformanceMetrics {
            double avgSessionOpenTime;
            double avgSigningTime;
            double avgEncryptionTime;
            size_t totalOperations;
            size_t failedOperations;
        } performance;
    };
    
    void startMonitoring(
        CK_FUNCTION_LIST_PTR functions,
        std::chrono::seconds interval = std::chrono::seconds(30)) {
        
        if (monitoring.load()) {
            return; // Уже запущен
        }
        
        monitoring.store(true);
        
        monitorThread = std::thread([this, functions, interval]() {
            while (monitoring.load()) {
                try {
                    performHealthCheck(functions);
                } catch (const std::exception& e) {
                    logError("Health check failed: " + std::string(e.what()));
                }
                
                std::this_thread::sleep_for(interval);
            }
        });
    }
    
    void stopMonitoring() {
        monitoring.store(false);
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }
    
    HealthReport getHealthReport() const {
        std::lock_guard<std::mutex> lock(monitorMutex);
        
        HealthReport report;
        report.timestamp = std::chrono::steady_clock::now();
        report.slotStatus = slots;
        report.overallHealth = true;
        
        for (const auto& [slotId, slotInfo] : slots) {
            if (!slotInfo.isHealthy) {
                report.overallHealth = false;
                
                // Классифицируем проблемы
                for (const auto& issue : slotInfo.issues) {
                    if (issue.find("CRITICAL") != std::string::npos) {
                        report.criticalIssues.push_back(
                            "Slot " + std::to_string(slotId) + ": " + issue);
                    } else {
                        report.warnings.push_back(
                            "Slot " + std::to_string(slotId) + ": " + issue);
                    }
                }
            }
        }
        
        return report;
    }
    
    // Выполнение комплексного теста HSM
    bool performComprehensiveTest(
        CK_FUNCTION_LIST_PTR functions,
        CK_SLOT_ID slotId,
        const std::string& userPin) {
        
        try {
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // Тест 1: Открытие сессии
            CK_SESSION_HANDLE session;
            auto sessionStart = std::chrono::high_resolution_clock::now();
            
            CK_RV rv = functions->C_OpenSession(
                slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                nullptr, nullptr, &session);
            
            if (rv != CKR_OK) {
                logError("Session open failed: " + std::to_string(rv));
                return false;
            }
            
            auto sessionTime = std::chrono::high_resolution_clock::now() - sessionStart;
            
            // Тест 2: Аутентификация
            rv = functions->C_Login(session, CKU_USER, 
                                  (CK_UTF8CHAR_PTR)userPin.c_str(), 
                                  userPin.length());
            
            if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
                functions->C_CloseSession(session);
                logError("Login failed: " + std::to_string(rv));
                return false;
            }
            
            // Тест 3: Генерация случайных данных
            std::vector<CK_BYTE> randomData(32);
            rv = functions->C_GenerateRandom(session, randomData.data(), 32);
            if (rv != CKR_OK) {
                logError("Random generation failed: " + std::to_string(rv));
            }
            
            // Тест 4: Генерация временного AES ключа
            CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
            CK_KEY_TYPE keyType = CKK_AES;
            CK_ULONG keyLength = 32; // 256 бит
            CK_BBOOL trueValue = CK_TRUE;
            CK_BBOOL falseValue = CK_FALSE;
            
            CK_ATTRIBUTE keyTemplate[] = {
                {CKA_CLASS, &keyClass, sizeof(keyClass)},
                {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                {CKA_VALUE_LEN, &keyLength, sizeof(keyLength)},
                {CKA_TOKEN, &falseValue, sizeof(falseValue)}, // Session key
                {CKA_ENCRYPT, &trueValue, sizeof(trueValue)},
                {CKA_DECRYPT, &trueValue, sizeof(trueValue)}
            };
            
            CK_OBJECT_HANDLE testKey;
            CK_MECHANISM keyGenMech = {CKM_AES_KEY_GEN, nullptr, 0};
            
            auto keyGenStart = std::chrono::high_resolution_clock::now();
            rv = functions->C_GenerateKey(
                session, &keyGenMech, keyTemplate, 
                sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &testKey);
            
            if (rv != CKR_OK) {
                logError("Key generation failed: " + std::to_string(rv));
            } else {
                auto keyGenTime = std::chrono::high_resolution_clock::now() - keyGenStart;
                
                // Тест 5: Шифрование/расшифрование
                std::vector<CK_BYTE> plaintext = {
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
                };
                
                CK_MECHANISM encMech = {CKM_AES_ECB, nullptr, 0};
                
                auto encStart = std::chrono::high_resolution_clock::now();
                
                // Инициализация шифрования
                rv = functions->C_EncryptInit(session, &encMech, testKey);
                if (rv == CKR_OK) {
                    CK_ULONG ciphertextLen;
                    
                    // Получаем размер зашифрованных данных
                    rv = functions->C_Encrypt(session, plaintext.data(), 
                                            plaintext.size(), nullptr, &ciphertextLen);
                    
                    if (rv == CKR_OK) {
                        std::vector<CK_BYTE> ciphertext(ciphertextLen);
                        rv = functions->C_Encrypt(session, plaintext.data(), 
                                                plaintext.size(), ciphertext.data(), 
                                                &ciphertextLen);
                        
                        if (rv == CKR_OK) {
                            auto encTime = std::chrono::high_resolution_clock::now() - encStart;
                            
                            // Тест расшифрования
                            rv = functions->C_DecryptInit(session, &encMech, testKey);
                            if (rv == CKR_OK) {
                                CK_ULONG decryptedLen = plaintext.size();
                                std::vector<CK_BYTE> decrypted(decryptedLen);
                                
                                rv = functions->C_Decrypt(session, ciphertext.data(),
                                                        ciphertext.size(), 
                                                        decrypted.data(), &decryptedLen);
                                
                                if (rv == CKR_OK) {
                                    // Проверяем корректность расшифровки
                                    if (decrypted != plaintext) {
                                        logError("Decryption verification failed");
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Удаляем тестовый ключ
                functions->C_DestroyObject(session, testKey);
            }
            
            functions->C_CloseSession(session);
            
            auto totalTime = std::chrono::high_resolution_clock::now() - startTime;
            
            logInfo("Comprehensive test completed in " + 
                   std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(totalTime).count()) + 
                   "ms");
            
            return true;
            
        } catch (const std::exception& e) {
            logError("Comprehensive test exception: " + std::string(e.what()));
            return false;
        }
    }
    
private:
    void performHealthCheck(CK_FUNCTION_LIST_PTR functions) {
        std::lock_guard<std::mutex> lock(monitorMutex);
        
        // Получаем список слотов
        CK_ULONG slotCount;
        CK_RV rv = functions->C_GetSlotList(CK_TRUE, nullptr, &slotCount);
        
        if (rv != CKR_OK) {
            logError("Failed to get slot count: " + std::to_string(rv));
            return;
        }
        
        std::vector<CK_SLOT_ID> slotIds(slotCount);
        rv = functions->C_GetSlotList(CK_TRUE, slotIds.data(), &slotCount);
        
        if (rv != CKR_OK) {
            logError("Failed to get slot list: " + std::to_string(rv));
            return;
        }
        
        // Проверяем каждый слот
        for (CK_SLOT_ID slotId : slotIds) {
            checkSlotHealth(functions, slotId);
        }
    }
    
    void checkSlotHealth(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slotId) {
        SlotInfo& slotInfo = slots[slotId];
        slotInfo.slotId = slotId;
        slotInfo.lastCheck = std::chrono::steady_clock::now();
        slotInfo.issues.clear();
        slotInfo.isHealthy = true;
        
        // Получаем информацию о слоте
        CK_RV rv = functions->C_GetSlotInfo(slotId, &slotInfo.slotInfo);
        if (rv != CKR_OK) {
            slotInfo.issues.push_back("CRITICAL: Cannot get slot info");
            slotInfo.isHealthy = false;
            return;
        }
        
        // Проверяем наличие токена
        if (!(slotInfo.slotInfo.flags & CKF_TOKEN_PRESENT)) {
            slotInfo.issues.push_back("WARNING: No token present");
            return;
        }
        
        // Получаем информацию о токене
        rv = functions->C_GetTokenInfo(slotId, &slotInfo.tokenInfo);
        if (rv != CKR_OK) {
            slotInfo.issues.push_back("CRITICAL: Cannot get token info");
            slotInfo.isHealthy = false;
            return;
        }
        
        // Проверяем состояние токена
        if (slotInfo.tokenInfo.flags & CKF_ERROR_STATE) {
            slotInfo.issues.push_back("CRITICAL: Token in error state");
            slotInfo.isHealthy = false;
        }
        
        if (slotInfo.tokenInfo.flags & CKF_DEVICE_ERROR) {
            slotInfo.issues.push_back("CRITICAL: Device error");
            slotInfo.isHealthy = false;
        }
        
        // Проверяем свободное место
        if (slotInfo.tokenInfo.ulFreePrivateMemory != CK_UNAVAILABLE_INFORMATION &&
            slotInfo.tokenInfo.ulFreePrivateMemory < 1024) { // Меньше 1KB
            slotInfo.issues.push_back("WARNING: Low free private memory");
        }
        
        if (slotInfo.tokenInfo.ulFreePublicMemory != CK_UNAVAILABLE_INFORMATION &&
            slotInfo.tokenInfo.ulFreePublicMemory < 1024) { // Меньше 1KB
            slotInfo.issues.push_back("WARNING: Low free public memory");
        }
    }
    
    void logError(const std::string& message) {
        std::cerr << "[ERROR] " << message << std::endl;
    }
    
    void logInfo(const std::string& message) {
        std::cout << "[INFO] " << message << std::endl;
    }
};
