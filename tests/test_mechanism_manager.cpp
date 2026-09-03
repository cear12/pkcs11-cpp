#include "catch.hpp"
#include "pkcs11cpp/mechanism_manager.h"
#include "pkcs11cpp/mock_module.h"

using namespace pkcs11cpp;

TEST_CASE("MechanismManager discovers the mock module's mechanism table", "[mechanism_manager]") {
    mock::reset();
    MechanismManager mm;
    mm.discoverMechanisms(mock::getFunctionList(), 0);

    auto* mechs = mm.mechanismsForSlot(0);
    REQUIRE(mechs != nullptr);
    REQUIRE_FALSE(mechs->empty());
}

TEST_CASE("MechanismManager::selectBestMechanism respects operation + key type", "[mechanism_manager]") {
    mock::reset();
    MechanismManager mm;
    mm.discoverMechanisms(mock::getFunctionList(), 0);

    auto aesEncrypt = mm.selectBestMechanism(0, "encrypt", CKK_AES, 256);
    REQUIRE(aesEncrypt.has_value());

    // No mechanism in the table both signs AND is compatible with a
    // generic-secret key type restricted to derive/generate.
    auto impossible = mm.selectBestMechanism(0, "sign", CKK_GENERIC_SECRET, 256);
    REQUIRE_FALSE(impossible.has_value());
}

TEST_CASE("MechanismManager::selectBestMechanism returns nullopt for an unknown slot", "[mechanism_manager]") {
    MechanismManager mm;  // discoverMechanisms() never called
    REQUIRE_FALSE(mm.selectBestMechanism(0, "encrypt", CKK_AES).has_value());
}

TEST_CASE("createOptimizedMechanism fills in OAEP defaults", "[mechanism_manager]") {
    MechanismManager mm;
    CK_MECHANISM mech = mm.createOptimizedMechanism(CKM_RSA_PKCS_OAEP);
    REQUIRE(mech.mechanism == CKM_RSA_PKCS_OAEP);
    REQUIRE(mech.pParameter != nullptr);
    REQUIRE(mech.ulParameterLen == sizeof(CK_RSA_PKCS_OAEP_PARAMS));

    auto* params = static_cast<CK_RSA_PKCS_OAEP_PARAMS*>(mech.pParameter);
    REQUIRE(params->hashAlg == CKM_SHA256);
}
