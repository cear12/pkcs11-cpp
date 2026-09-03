#include "catch.hpp"
#include "pkcs11cpp/key_manager.h"
#include "pkcs11cpp/mock_module.h"
#include "pkcs11cpp/session_manager.h"

using namespace pkcs11cpp;

TEST_CASE("KeyManager generates a distinct RSA key pair each call", "[key_manager]") {
    mock::reset();
    SessionManager sm(mock::getFunctionList(), 0);
    auto guard = sm.createSessionGuard();

    KeyManager km;
    KeyManager::KeyGenerationParams params;
    params.algorithm = KeyManager::KeyAlgorithm::RSA_2048;
    params.label = "rsa-key";
    params.canSign = params.canVerify = true;

    auto pair1 = km.generateKeyPair(guard.handle(), guard.functions(), params);
    auto pair2 = km.generateKeyPair(guard.handle(), guard.functions(), params);

    REQUIRE(pair1.publicKey != pair2.publicKey);
    REQUIRE(pair1.privateKey != pair2.privateKey);
    REQUIRE(pair1.publicKey != pair1.privateKey);
}

TEST_CASE("KeyManager generates AES secret keys of the requested size", "[key_manager]") {
    mock::reset();
    SessionManager sm(mock::getFunctionList(), 0);
    auto guard = sm.createSessionGuard();

    KeyManager km;
    KeyManager::KeyGenerationParams params;
    params.algorithm = KeyManager::KeyAlgorithm::AES_128;
    params.canEncrypt = true;

    CK_OBJECT_HANDLE key = km.generateSecretKey(guard.handle(), guard.functions(), params);
    REQUIRE(key != CK_INVALID_HANDLE);
}

TEST_CASE("KeyManager rejects mismatched algorithm/operation combinations", "[key_manager]") {
    mock::reset();
    SessionManager sm(mock::getFunctionList(), 0);
    auto guard = sm.createSessionGuard();
    KeyManager km;

    KeyManager::KeyGenerationParams aesParams;
    aesParams.algorithm = KeyManager::KeyAlgorithm::AES_256;
    REQUIRE_THROWS_AS(km.generateKeyPair(guard.handle(), guard.functions(), aesParams), std::invalid_argument);

    KeyManager::KeyGenerationParams rsaParams;
    rsaParams.algorithm = KeyManager::KeyAlgorithm::RSA_2048;
    REQUIRE_THROWS_AS(km.generateSecretKey(guard.handle(), guard.functions(), rsaParams), std::invalid_argument);
}

TEST_CASE("isSecretKeyAlgorithm / isKeyPairAlgorithm classify every algorithm consistently", "[key_manager]") {
    using Alg = KeyManager::KeyAlgorithm;
    for (auto alg : {Alg::RSA_2048, Alg::RSA_3072, Alg::RSA_4096, Alg::ECDSA_P256, Alg::ECDSA_P384, Alg::ECDSA_P521,
                      Alg::AES_128, Alg::AES_192, Alg::AES_256, Alg::DES3}) {
        // Every algorithm is exactly one of "key pair" or "secret key", never both, never neither.
        REQUIRE(KeyManager::isKeyPairAlgorithm(alg) != KeyManager::isSecretKeyAlgorithm(alg));
    }
}
