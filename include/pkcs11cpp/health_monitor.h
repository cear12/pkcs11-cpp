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
        CK_SLOT_ID slotId = 0;
        CK_SLOT_INFO slotInfo{};
        CK_TOKEN_INFO tokenInfo{};
        std::chrono::steady_clock::time_point lastCheck;
        bool healthy = true;
        std::vector<std::string> issues;  // each prefixed "CRITICAL: " or "WARNING: "
    };

    struct HealthReport {
        std::chrono::steady_clock::time_point timestamp;
        bool overallHealthy = true;
        std::map<CK_SLOT_ID, SlotInfo> slotStatus;
        std::vector<std::string> criticalIssues;
        std::vector<std::string> warnings;
    };

    ~HealthMonitor();

    void startMonitoring(CK_FUNCTION_LIST_PTR functions, std::chrono::seconds interval = std::chrono::seconds(30));
    void stopMonitoring();

    HealthReport getHealthReport() const;

    // Opens its own session (independent of any SessionManager), runs a
    // handful of representative operations against `slotId`, and reports
    // pass/fail with per-step timings. Cleans up any objects it creates.
    bool performComprehensiveTest(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slotId, const std::string& userPin);

private:
    void performHealthCheck(CK_FUNCTION_LIST_PTR functions);
    void checkSlotHealth(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slotId);

    mutable std::mutex monitorMutex_;
    std::map<CK_SLOT_ID, SlotInfo> slots_;

    std::thread monitorThread_;
    std::atomic<bool> monitoring_{false};
    // Lets stopMonitoring() wake the background thread immediately instead
    // of leaving it stuck in a multi-second sleep -- see startMonitoring().
    std::mutex shutdownMutex_;
    std::condition_variable shutdownSignal_;
};

}  // namespace pkcs11cpp
