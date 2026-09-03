#include "catch.hpp"
#include "pkcs11cpp/mechanism_manager.h"
#include "pkcs11cpp/mock_module.h"

using namespace pkcs11cpp;

TEST_CASE("MechanismManager discovers the mock module's mechanism table", "[mechanism_manager]") {
    mock::Reset();
    MechanismManager mm;
    mm.DiscoverMechanisms(mock::GetFunctionList(), 0);

    auto* mechs = mm.MechanismsForSlot(0);
    REQUIRE(mechs != nullptr);
    REQUIRE_FALSE(mechs->empty());
}

TEST_CASE("MechanismManager::SelectBestMechanism respects operation + key type", "[mechanism_manager]") {
    mock::Reset();
    MechanismManager mm;
    mm.DiscoverMechanisms(mock::GetFunctionList(), 0);

    auto aes_encrypt = mm.SelectBestMechanism(0, "encrypt", CKK_AES, 256);
    REQUIRE(aes_encrypt.has_value());

    // No mechanism in the table both signs AND is compatible with a
    // generic-secret key type restricted to derive/generate.
    auto impossible = mm.SelectBestMechanism(0, "sign", CKK_GENERIC_SECRET, 256);
    REQUIRE_FALSE(impossible.has_value());
}

TEST_CASE("MechanismManager::SelectBestMechanism returns nullopt for an unknown slot", "[mechanism_manager]") {
    MechanismManager mm;  // DiscoverMechanisms() never called
    REQUIRE_FALSE(mm.SelectBestMechanism(0, "encrypt", CKK_AES).has_value());
}

TEST_CASE("CreateOptimizedMechanism fills in OAEP defaults", "[mechanism_manager]") {
    MechanismManager mm;
    CK_MECHANISM mech = mm.CreateOptimizedMechanism(CKM_RSA_PKCS_OAEP);
    REQUIRE(mech.mechanism == CKM_RSA_PKCS_OAEP);
    REQUIRE(mech.pParameter != nullptr);
    REQUIRE(mech.ulParameterLen == sizeof(CK_RSA_PKCS_OAEP_PARAMS));

    auto* params = static_cast<CK_RSA_PKCS_OAEP_PARAMS*>(mech.pParameter);
    REQUIRE(params->hashAlg == CKM_SHA256);
}
