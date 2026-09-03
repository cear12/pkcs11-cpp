#include "catch.hpp"
#include "pkcs11cpp/health_monitor.h"
#include "pkcs11cpp/mock_module.h"

using namespace pkcs11cpp;

TEST_CASE("HealthMonitor::PerformComprehensiveTest passes against a healthy mock token", "[health_monitor]") {
    mock::Reset();
    HealthMonitor monitor;
    REQUIRE(monitor.PerformComprehensiveTest(mock::GetFunctionList(), 0, "1234"));
}

TEST_CASE("HealthMonitor::GetHealthReport flags low free memory as a warning", "[health_monitor]") {
    mock::Reset();
    mock::SimulateLowMemory(true);

    HealthMonitor monitor;
    monitor.StartMonitoring(mock::GetFunctionList(), std::chrono::seconds(3600));
    // StartMonitoring's background thread runs its first check almost
    // immediately; give it a moment before reading the report.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto report = monitor.GetHealthReport();
    monitor.StopMonitoring();
    mock::SimulateLowMemory(false);

    REQUIRE_FALSE(report.warnings_.empty());
}

TEST_CASE("HealthMonitor starts and stops cleanly without a health check ever having run", "[health_monitor]") {
    HealthMonitor monitor;
    auto report = monitor.GetHealthReport();
    REQUIRE(report.overall_healthy_);  // no slots checked yet => nothing unhealthy
    REQUIRE(report.slot_status_.empty());
}
