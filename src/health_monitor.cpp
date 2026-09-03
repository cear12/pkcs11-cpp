#include "pkcs11cpp/health_monitor.h"

#include <cstring>

#include "pkcs11cpp/logging.h"

namespace pkcs11cpp {

HealthMonitor::~HealthMonitor() { stopMonitoring(); }

void HealthMonitor::startMonitoring(CK_FUNCTION_LIST_PTR functions, std::chrono::seconds interval) {
    if (monitoring_.exchange(true)) return;  // already running

    monitorThread_ = std::thread([this, functions, interval] {
        while (monitoring_.load()) {
            try {
                performHealthCheck(functions);
            } catch (const std::exception& e) {
                log::error(std::string("Health check failed: ") + e.what());
            }

            // Sleep for `interval`, but wake up immediately if
            // stopMonitoring() signals shutdown -- a plain sleep_for()
            // here would make stopMonitoring()'s join() block for up to
            // a full interval (or effectively forever, for the long
            // intervals a real deployment would use).
            std::unique_lock<std::mutex> lock(shutdownMutex_);
            shutdownSignal_.wait_for(lock, interval, [this] { return !monitoring_.load(); });
        }
    });
}

void HealthMonitor::stopMonitoring() {
    if (!monitoring_.exchange(false)) return;
    shutdownSignal_.notify_all();
    if (monitorThread_.joinable()) monitorThread_.join();
}

HealthMonitor::HealthReport HealthMonitor::getHealthReport() const {
    std::lock_guard<std::mutex> lock(monitorMutex_);

    HealthReport report;
    report.timestamp = std::chrono::steady_clock::now();
    report.slotStatus = slots_;
    report.overallHealthy = true;

    for (const auto& [slotId, slotInfo] : slots_) {
        // A slot can have WARNING-level issues (e.g. low free memory)
        // without being marked unhealthy -- surface those too, not just
        // the issues attached to slots that failed outright.
        if (!slotInfo.healthy) report.overallHealthy = false;
        for (const auto& issue : slotInfo.issues) {
            auto& bucket = (issue.rfind("CRITICAL", 0) == 0) ? report.criticalIssues : report.warnings;
            bucket.push_back("Slot " + std::to_string(slotId) + ": " + issue);
        }
    }
    return report;
}

void HealthMonitor::performHealthCheck(CK_FUNCTION_LIST_PTR functions) {
    CK_ULONG slotCount = 0;
    CK_RV rv = functions->C_GetSlotList(CK_TRUE, nullptr, &slotCount);
    if (rv != CKR_OK) {
        log::error("C_GetSlotList (sizing) failed: " + std::to_string(rv));
        return;
    }

    std::vector<CK_ULONG> slotIds(slotCount);
    rv = functions->C_GetSlotList(CK_TRUE, slotIds.data(), &slotCount);
    if (rv != CKR_OK) {
        log::error("C_GetSlotList failed: " + std::to_string(rv));
        return;
    }

    for (auto slotId : slotIds) checkSlotHealth(functions, slotId);
}

void HealthMonitor::checkSlotHealth(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slotId) {
    std::lock_guard<std::mutex> lock(monitorMutex_);
    SlotInfo& slot = slots_[slotId];
    slot.slotId = slotId;
    slot.lastCheck = std::chrono::steady_clock::now();
    slot.issues.clear();
    slot.healthy = true;

    CK_RV rv = functions->C_GetSlotInfo(slotId, &slot.slotInfo);
    if (rv != CKR_OK) {
        slot.issues.push_back("CRITICAL: cannot get slot info (rv=" + std::to_string(rv) + ")");
        slot.healthy = false;
        return;
    }

    if (!(slot.slotInfo.flags & CKF_TOKEN_PRESENT)) {
        slot.issues.push_back("WARNING: no token present");
        return;
    }

    rv = functions->C_GetTokenInfo(slotId, &slot.tokenInfo);
    if (rv != CKR_OK) {
        slot.issues.push_back("CRITICAL: cannot get token info (rv=" + std::to_string(rv) + ")");
        slot.healthy = false;
        return;
    }

    if (slot.tokenInfo.flags & CKF_ERROR_STATE) {
        slot.issues.push_back("CRITICAL: token is in an error state");
        slot.healthy = false;
    }
    if (slot.tokenInfo.flags & CKF_DEVICE_ERROR) {
        slot.issues.push_back("CRITICAL: device error reported");
        slot.healthy = false;
    }
    if (slot.tokenInfo.ulFreePrivateMemory != CK_UNAVAILABLE_INFORMATION &&
        slot.tokenInfo.ulFreePrivateMemory < 1024) {
        slot.issues.push_back("WARNING: low free private memory (" +
                               std::to_string(slot.tokenInfo.ulFreePrivateMemory) + " bytes)");
    }
    if (slot.tokenInfo.ulFreePublicMemory != CK_UNAVAILABLE_INFORMATION &&
        slot.tokenInfo.ulFreePublicMemory < 1024) {
        slot.issues.push_back("WARNING: low free public memory (" +
                               std::to_string(slot.tokenInfo.ulFreePublicMemory) + " bytes)");
    }
}

bool HealthMonitor::performComprehensiveTest(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slotId,
                                              const std::string& userPin) {
    try {
        auto startTime = std::chrono::high_resolution_clock::now();

        CK_SESSION_HANDLE session;
        CK_RV rv = functions->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session);
        if (rv != CKR_OK) {
            log::error("performComprehensiveTest: C_OpenSession failed: " + std::to_string(rv));
            return false;
        }

        rv = functions->C_Login(session, CKU_USER,
                                 reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin.c_str())),
                                 static_cast<CK_ULONG>(userPin.length()));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            functions->C_CloseSession(session);
            log::error("performComprehensiveTest: C_Login failed: " + std::to_string(rv));
            return false;
        }

        std::vector<CK_BYTE> randomData(32);
        rv = functions->C_GenerateRandom(session, randomData.data(), 32);
        if (rv != CKR_OK) {
            log::error("performComprehensiveTest: C_GenerateRandom failed: " + std::to_string(rv));
        }

        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_KEY_TYPE keyType = CKK_AES;
        CK_ULONG keyLength = 32;
        CK_BBOOL trueValue = CK_TRUE;
        CK_BBOOL falseValue = CK_FALSE;
        CK_ATTRIBUTE keyTemplate[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},       {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_VALUE_LEN, &keyLength, sizeof(keyLength)}, {CKA_TOKEN, &falseValue, sizeof(falseValue)},
            {CKA_ENCRYPT, &trueValue, sizeof(trueValue)},   {CKA_DECRYPT, &trueValue, sizeof(trueValue)},
        };

        CK_OBJECT_HANDLE testKey;
        CK_MECHANISM keyGenMech = {CKM_AES_KEY_GEN, nullptr, 0};
        bool ok = true;

        rv = functions->C_GenerateKey(session, &keyGenMech, keyTemplate,
                                       sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE), &testKey);
        if (rv != CKR_OK) {
            log::error("performComprehensiveTest: C_GenerateKey failed: " + std::to_string(rv));
            ok = false;
        } else {
            std::vector<CK_BYTE> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
            CK_MECHANISM encMech = {CKM_AES_ECB, nullptr, 0};

            rv = functions->C_EncryptInit(session, &encMech, testKey);
            if (rv == CKR_OK) {
                CK_ULONG ciphertextLen = 0;
                rv = functions->C_Encrypt(session, plaintext.data(), static_cast<CK_ULONG>(plaintext.size()), nullptr,
                                           &ciphertextLen);
                if (rv == CKR_OK) {
                    std::vector<CK_BYTE> ciphertext(ciphertextLen);
                    rv = functions->C_Encrypt(session, plaintext.data(), static_cast<CK_ULONG>(plaintext.size()),
                                               ciphertext.data(), &ciphertextLen);
                    if (rv == CKR_OK) {
                        rv = functions->C_DecryptInit(session, &encMech, testKey);
                        if (rv == CKR_OK) {
                            CK_ULONG decryptedLen = static_cast<CK_ULONG>(plaintext.size());
                            std::vector<CK_BYTE> decrypted(decryptedLen);
                            rv = functions->C_Decrypt(session, ciphertext.data(), ciphertextLen, decrypted.data(),
                                                       &decryptedLen);
                            decrypted.resize(decryptedLen);
                            if (rv != CKR_OK || decrypted != plaintext) {
                                log::error("performComprehensiveTest: decrypt round-trip mismatch");
                                ok = false;
                            }
                        }
                    }
                }
            }
            functions->C_DestroyObject(session, testKey);
        }

        functions->C_CloseSession(session);

        auto totalTime = std::chrono::high_resolution_clock::now() - startTime;
        log::info("performComprehensiveTest completed in " +
                  std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(totalTime).count()) + "ms" +
                  (ok ? " (PASS)" : " (FAIL)"));
        return ok;

    } catch (const std::exception& e) {
        log::error(std::string("performComprehensiveTest threw: ") + e.what());
        return false;
    }
}

}  // namespace pkcs11cpp
