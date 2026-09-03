#include "pkcs11cpp/health_monitor.h"

#include <cstring>

#include "pkcs11cpp/logging.h"

namespace pkcs11cpp {

HealthMonitor::~HealthMonitor() { StopMonitoring(); }

void HealthMonitor::StartMonitoring(CK_FUNCTION_LIST_PTR functions,
                                    std::chrono::seconds interval) {
  if (monitoring_.exchange(true)) return;  // already running

  monitor_thread_ = std::thread([this, functions, interval] {
    while (monitoring_.load()) {
      try {
        PerformHealthCheck(functions);
      } catch (const std::exception& e) {
        log::Error(std::string("Health check failed: ") + e.what());
      }

      // Sleep for `interval`, but wake up immediately if
      // StopMonitoring() signals shutdown -- a plain sleep_for()
      // here would make StopMonitoring()'s join() block for up to
      // a full interval (or effectively forever, for the long
      // intervals a real deployment would use).
      std::unique_lock<std::mutex> lock(shutdown_mutex_);
      shutdown_signal_.wait_for(lock, interval,
                                [this] { return !monitoring_.load(); });
    }
  });
}

void HealthMonitor::StopMonitoring() {
  if (!monitoring_.exchange(false)) return;
  shutdown_signal_.notify_all();
  if (monitor_thread_.joinable()) monitor_thread_.join();
}

HealthMonitor::HealthReport HealthMonitor::GetHealthReport() const {
  std::lock_guard<std::mutex> lock(monitor_mutex_);

  HealthReport report;
  report.timestamp_ = std::chrono::steady_clock::now();
  report.slot_status_ = slots_;
  report.overall_healthy_ = true;

  for (const auto& [slotId, slotInfo] : slots_) {
    // A slot can have WARNING-level issues (e.g. low free memory)
    // without being marked unhealthy -- surface those too, not just
    // the issues attached to slots that failed outright.
    if (!slotInfo.healthy_) report.overall_healthy_ = false;
    for (const auto& issue : slotInfo.issues_) {
      auto& bucket = (issue.rfind("CRITICAL", 0) == 0) ? report.critical_issues_
                                                       : report.warnings_;
      bucket.push_back("Slot " + std::to_string(slotId) + ": " + issue);
    }
  }
  return report;
}

void HealthMonitor::PerformHealthCheck(CK_FUNCTION_LIST_PTR functions) {
  CK_ULONG slot_count = 0;
  CK_RV rv = functions->C_GetSlotList(CK_TRUE, nullptr, &slot_count);
  if (rv != CKR_OK) {
    log::Error("C_GetSlotList (sizing) failed: " + std::to_string(rv));
    return;
  }

  std::vector<CK_ULONG> slot_ids(slot_count);
  rv = functions->C_GetSlotList(CK_TRUE, slot_ids.data(), &slot_count);
  if (rv != CKR_OK) {
    log::Error("C_GetSlotList failed: " + std::to_string(rv));
    return;
  }

  for (auto slot_id : slot_ids) CheckSlotHealth(functions, slot_id);
}

void HealthMonitor::CheckSlotHealth(CK_FUNCTION_LIST_PTR functions,
                                    CK_SLOT_ID slot_id) {
  std::lock_guard<std::mutex> lock(monitor_mutex_);
  SlotInfo& slot = slots_[slot_id];
  slot.slot_id_ = slot_id;
  slot.last_check_ = std::chrono::steady_clock::now();
  slot.issues_.clear();
  slot.healthy_ = true;

  CK_RV rv = functions->C_GetSlotInfo(slot_id, &slot.slot_info_);
  if (rv != CKR_OK) {
    slot.issues_.push_back(
        "CRITICAL: cannot get slot info (rv=" + std::to_string(rv) + ")");
    slot.healthy_ = false;
    return;
  }

  if (!(slot.slot_info_.flags & CKF_TOKEN_PRESENT)) {
    slot.issues_.push_back("WARNING: no token present");
    return;
  }

  rv = functions->C_GetTokenInfo(slot_id, &slot.token_info_);
  if (rv != CKR_OK) {
    slot.issues_.push_back(
        "CRITICAL: cannot get token info (rv=" + std::to_string(rv) + ")");
    slot.healthy_ = false;
    return;
  }

  if (slot.token_info_.flags & CKF_ERROR_STATE) {
    slot.issues_.push_back("CRITICAL: token is in an error state");
    slot.healthy_ = false;
  }
  if (slot.token_info_.flags & CKF_DEVICE_ERROR) {
    slot.issues_.push_back("CRITICAL: device error reported");
    slot.healthy_ = false;
  }
  if (slot.token_info_.ulFreePrivateMemory != CK_UNAVAILABLE_INFORMATION &&
      slot.token_info_.ulFreePrivateMemory < 1024) {
    slot.issues_.push_back(
        "WARNING: low free private memory (" +
        std::to_string(slot.token_info_.ulFreePrivateMemory) + " bytes)");
  }
  if (slot.token_info_.ulFreePublicMemory != CK_UNAVAILABLE_INFORMATION &&
      slot.token_info_.ulFreePublicMemory < 1024) {
    slot.issues_.push_back("WARNING: low free public memory (" +
                           std::to_string(slot.token_info_.ulFreePublicMemory) +
                           " bytes)");
  }
}

bool HealthMonitor::PerformComprehensiveTest(CK_FUNCTION_LIST_PTR functions,
                                             CK_SLOT_ID slot_id,
                                             const std::string& user_pin) {
  try {
    auto start_time = std::chrono::high_resolution_clock::now();

    CK_SESSION_HANDLE session;
    CK_RV rv =
        functions->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                 nullptr, nullptr, &session);
    if (rv != CKR_OK) {
      log::Error("PerformComprehensiveTest: C_OpenSession failed: " +
                 std::to_string(rv));
      return false;
    }

    rv = functions->C_Login(
        session, CKU_USER,
        reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(user_pin.c_str())),
        static_cast<CK_ULONG>(user_pin.length()));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
      functions->C_CloseSession(session);
      log::Error("PerformComprehensiveTest: C_Login failed: " +
                 std::to_string(rv));
      return false;
    }

    std::vector<CK_BYTE> random_data(32);
    rv = functions->C_GenerateRandom(session, random_data.data(), 32);
    if (rv != CKR_OK) {
      log::Error("PerformComprehensiveTest: C_GenerateRandom failed: " +
                 std::to_string(rv));
    }

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_AES;
    CK_ULONG key_length = 32;
    CK_BBOOL true_value = CK_TRUE;
    CK_BBOOL false_value = CK_FALSE;
    CK_ATTRIBUTE key_template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_VALUE_LEN, &key_length, sizeof(key_length)},
        {CKA_TOKEN, &false_value, sizeof(false_value)},
        {CKA_ENCRYPT, &true_value, sizeof(true_value)},
        {CKA_DECRYPT, &true_value, sizeof(true_value)},
    };

    CK_OBJECT_HANDLE test_key;
    CK_MECHANISM key_gen_mech = {CKM_AES_KEY_GEN, nullptr, 0};
    bool ok = true;

    rv = functions->C_GenerateKey(session, &key_gen_mech, key_template,
                                  sizeof(key_template) / sizeof(CK_ATTRIBUTE),
                                  &test_key);
    if (rv != CKR_OK) {
      log::Error("PerformComprehensiveTest: C_GenerateKey failed: " +
                 std::to_string(rv));
      ok = false;
    } else {
      std::vector<CK_BYTE> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                        0x0D, 0x0E, 0x0F, 0x10};
      CK_MECHANISM enc_mech = {CKM_AES_ECB, nullptr, 0};

      rv = functions->C_EncryptInit(session, &enc_mech, test_key);
      if (rv == CKR_OK) {
        CK_ULONG ciphertext_len = 0;
        rv = functions->C_Encrypt(session, plaintext.data(),
                                  static_cast<CK_ULONG>(plaintext.size()),
                                  nullptr, &ciphertext_len);
        if (rv == CKR_OK) {
          std::vector<CK_BYTE> ciphertext(ciphertext_len);
          rv = functions->C_Encrypt(session, plaintext.data(),
                                    static_cast<CK_ULONG>(plaintext.size()),
                                    ciphertext.data(), &ciphertext_len);
          if (rv == CKR_OK) {
            rv = functions->C_DecryptInit(session, &enc_mech, test_key);
            if (rv == CKR_OK) {
              CK_ULONG decrypted_len = static_cast<CK_ULONG>(plaintext.size());
              std::vector<CK_BYTE> decrypted(decrypted_len);
              rv = functions->C_Decrypt(session, ciphertext.data(),
                                        ciphertext_len, decrypted.data(),
                                        &decrypted_len);
              decrypted.resize(decrypted_len);
              if (rv != CKR_OK || decrypted != plaintext) {
                log::Error(
                    "PerformComprehensiveTest: decrypt round-trip mismatch");
                ok = false;
              }
            }
          }
        }
      }
      functions->C_DestroyObject(session, test_key);
    }

    functions->C_CloseSession(session);

    auto total_time = std::chrono::high_resolution_clock::now() - start_time;
    log::Info(
        "PerformComprehensiveTest completed in " +
        std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(total_time)
                .count()) +
        "ms" + (ok ? " (PASS)" : " (FAIL)"));
    return ok;

  } catch (const std::exception& e) {
    log::Error(std::string("PerformComprehensiveTest threw: ") + e.what());
    return false;
  }
}

}  // namespace pkcs11cpp
