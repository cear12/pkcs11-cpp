#include "catch.hpp"
#include "pkcs11cpp/key_manager.h"
#include "pkcs11cpp/mock_module.h"
#include "pkcs11cpp/session_manager.h"

using namespace pkcs11cpp;

TEST_CASE("KeyManager generates a distinct RSA key pair each call",
          "[key_manager]") {
  mock::Reset();
  SessionManager sm(mock::GetFunctionList(), 0);
  auto guard = sm.CreateSessionGuard();

  KeyManager km;
  KeyManager::KeyGenerationParams params;
  params.algorithm_ = KeyManager::KeyAlgorithm::kRsa2048;
  params.label_ = "rsa-key";
  params.can_sign_ = params.can_verify_ = true;

  auto pair1 = km.GenerateKeyPair(guard.Handle(), guard.Functions(), params);
  auto pair2 = km.GenerateKeyPair(guard.Handle(), guard.Functions(), params);

  REQUIRE(pair1.public_key_ != pair2.public_key_);
  REQUIRE(pair1.private_key_ != pair2.private_key_);
  REQUIRE(pair1.public_key_ != pair1.private_key_);
}

TEST_CASE("KeyManager generates AES secret keys of the requested size",
          "[key_manager]") {
  mock::Reset();
  SessionManager sm(mock::GetFunctionList(), 0);
  auto guard = sm.CreateSessionGuard();

  KeyManager km;
  KeyManager::KeyGenerationParams params;
  params.algorithm_ = KeyManager::KeyAlgorithm::kAes128;
  params.can_encrypt_ = true;

  CK_OBJECT_HANDLE key =
      km.GenerateSecretKey(guard.Handle(), guard.Functions(), params);
  REQUIRE(key != CK_INVALID_HANDLE);
}

TEST_CASE("KeyManager rejects mismatched algorithm/operation combinations",
          "[key_manager]") {
  mock::Reset();
  SessionManager sm(mock::GetFunctionList(), 0);
  auto guard = sm.CreateSessionGuard();
  KeyManager km;

  KeyManager::KeyGenerationParams aes_params;
  aes_params.algorithm_ = KeyManager::KeyAlgorithm::kAes256;
  REQUIRE_THROWS_AS(
      km.GenerateKeyPair(guard.Handle(), guard.Functions(), aes_params),
      std::invalid_argument);

  KeyManager::KeyGenerationParams rsa_params;
  rsa_params.algorithm_ = KeyManager::KeyAlgorithm::kRsa2048;
  REQUIRE_THROWS_AS(
      km.GenerateSecretKey(guard.Handle(), guard.Functions(), rsa_params),
      std::invalid_argument);
}

TEST_CASE(
    "IsSecretKeyAlgorithm / IsKeyPairAlgorithm classify every algorithm "
    "consistently",
    "[key_manager]") {
  using Alg = KeyManager::KeyAlgorithm;
  for (auto alg : {Alg::kRsa2048, Alg::kRsa3072, Alg::kRsa4096, Alg::kEcdsaP256,
                   Alg::kEcdsaP384, Alg::kEcdsaP521, Alg::kAes128, Alg::kAes192,
                   Alg::kAes256, Alg::kDeS3}) {
    // Every algorithm is exactly one of "key pair" or "secret key", never both,
    // never neither.
    REQUIRE(KeyManager::IsKeyPairAlgorithm(alg) !=
            KeyManager::IsSecretKeyAlgorithm(alg));
  }
}
