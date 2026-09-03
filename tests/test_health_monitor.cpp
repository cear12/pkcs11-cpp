#include "catch.hpp"
#include "pkcs11cpp/health_monitor.h"
#include "pkcs11cpp/mock_module.h"

using namespace pkcs11cpp;

TEST_CASE("HealthMonitor::performComprehensiveTest passes against a healthy mock token", "[health_monitor]") {
    mock::reset();
    HealthMonitor monitor;
    REQUIRE(monitor.performComprehensiveTest(mock::getFunctionList(), 0, "1234"));
}

TEST_CASE("HealthMonitor::getHealthReport flags low free memory as a warning", "[health_monitor]") {
    mock::reset();
    mock::simulateLowMemory(true);

    HealthMonitor monitor;
    monitor.startMonitoring(mock::getFunctionList(), std::chrono::seconds(3600));
    // startMonitoring's background thread runs its first check almost
    // immediately; give it a moment before reading the report.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    auto report = monitor.getHealthReport();
    monitor.stopMonitoring();
    mock::simulateLowMemory(false);

    REQUIRE_FALSE(report.warnings.empty());
}

TEST_CASE("HealthMonitor starts and stops cleanly without a health check ever having run", "[health_monitor]") {
    HealthMonitor monitor;
    auto report = monitor.getHealthReport();
    REQUIRE(report.overallHealthy);  // no slots checked yet => nothing unhealthy
    REQUIRE(report.slotStatus.empty());
}
