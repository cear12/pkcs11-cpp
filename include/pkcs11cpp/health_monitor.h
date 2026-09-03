#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Periodically polls slot/token status (CKF_TOKEN_PRESENT, error/device
// flags, free memory) on a background thread, and offers a one-shot
// end-to-end "comprehensive test" (open session, generate an AES key,
// round-trip encrypt/decrypt, clean up) for smoke-testing a token before
// putting it into service.
class HealthMonitor {
public:
    struct SlotInfo {
        CK_SLOT_ID slot_id_ = 0;
        CK_SLOT_INFO slot_info_{};
        CK_TOKEN_INFO token_info_{};
        std::chrono::steady_clock::time_point last_check_;
        bool healthy_ = true;
        std::vector<std::string> issues_;  // each prefixed "CRITICAL: " or "WARNING: "
    };

    struct HealthReport {
        std::chrono::steady_clock::time_point timestamp_;
        bool overall_healthy_ = true;
        std::map<CK_SLOT_ID, SlotInfo> slot_status_;
        std::vector<std::string> critical_issues_;
        std::vector<std::string> warnings_;
    };

    ~HealthMonitor();

    void StartMonitoring(CK_FUNCTION_LIST_PTR functions, std::chrono::seconds interval = std::chrono::seconds(30));
    void StopMonitoring();

    HealthReport GetHealthReport() const;

    // Opens its own session (independent of any SessionManager), runs a
    // handful of representative operations against `slotId`, and reports
    // pass/fail with per-step timings. Cleans up any objects it creates.
    bool PerformComprehensiveTest(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slot_id, const std::string& user_pin);

private:
    void PerformHealthCheck(CK_FUNCTION_LIST_PTR functions);
    void CheckSlotHealth(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slot_id);

    mutable std::mutex monitor_mutex_;
    std::map<CK_SLOT_ID, SlotInfo> slots_;

    std::thread monitor_thread_;
    std::atomic<bool> monitoring_{false};
    // Lets StopMonitoring() wake the background thread immediately instead
    // of leaving it stuck in a multi-second sleep -- see StartMonitoring().
    std::mutex shutdown_mutex_;
    std::condition_variable shutdown_signal_;
};

}  // namespace pkcs11cpp
