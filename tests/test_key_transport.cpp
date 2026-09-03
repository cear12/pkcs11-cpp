#include "catch.hpp"
#include "pkcs11cpp/key_manager.h"
#include "pkcs11cpp/key_transport.h"
#include "pkcs11cpp/mock_module.h"
#include "pkcs11cpp/session_manager.h"

using namespace pkcs11cpp;

TEST_CASE("KeyTransport wrap/unwrap round-trips a key's usable attributes", "[key_transport]") {
    mock::Reset();
    SessionManager sm(mock::GetFunctionList(), 0);
    auto guard = sm.CreateSessionGuard();

    KeyManager km;
    KeyManager::KeyGenerationParams key_params;
    key_params.algorithm_ = KeyManager::KeyAlgorithm::kAes128;
    key_params.label_ = "payload-key";
    key_params.can_encrypt_ = key_params.can_decrypt_ = true;
    CK_OBJECT_HANDLE payload_key = km.GenerateSecretKey(guard.Handle(), guard.Functions(), key_params);

    KeyManager::KeyGenerationParams wrapper_params;
    wrapper_params.algorithm_ = KeyManager::KeyAlgorithm::kAes256;
    wrapper_params.can_wrap_ = wrapper_params.can_unwrap_ = true;
    CK_OBJECT_HANDLE wrapping_key = km.GenerateSecretKey(guard.Handle(), guard.Functions(), wrapper_params);

    KeyTransport transport;
    auto wrapped = transport.WrapKey(guard.Handle(), guard.Functions(), payload_key, wrapping_key,
                                      KeyTransport::WrapMechanism::kAesKeyWrap);
    REQUIRE_FALSE(wrapped.wrapped_key_.empty());

    CK_OBJECT_HANDLE restored = transport.UnwrapKey(guard.Handle(), guard.Functions(), wrapped, wrapping_key);
    REQUIRE(restored != CK_INVALID_HANDLE);
    REQUIRE(restored != payload_key);  // unwrap always produces a fresh object
}

TEST_CASE("KeyTransport::UnwrapKey applies a new label when one is given", "[key_transport]") {
    mock::Reset();
    SessionManager sm(mock::GetFunctionList(), 0);
    auto guard = sm.CreateSessionGuard();

    KeyManager km;
    KeyManager::KeyGenerationParams key_params;
    key_params.algorithm_ = KeyManager::KeyAlgorithm::kAes128;
    key_params.label_ = "original-label";
    CK_OBJECT_HANDLE payload_key = km.GenerateSecretKey(guard.Handle(), guard.Functions(), key_params);

    KeyManager::KeyGenerationParams wrapper_params;
    wrapper_params.algorithm_ = KeyManager::KeyAlgorithm::kAes256;
    CK_OBJECT_HANDLE wrapping_key = km.GenerateSecretKey(guard.Handle(), guard.Functions(), wrapper_params);

    KeyTransport transport;
    auto wrapped = transport.WrapKey(guard.Handle(), guard.Functions(), payload_key, wrapping_key);
    CK_OBJECT_HANDLE restored =
        transport.UnwrapKey(guard.Handle(), guard.Functions(), wrapped, wrapping_key, "renamed-label");

    AttributeManager attrs;
    auto read_back = attrs.ReadObjectAttributes(guard.Handle(), guard.Functions(), restored);
    auto label = read_back.GetAttribute(CKA_LABEL);
    REQUIRE(label.has_value());
    REQUIRE(std::string(label->begin(), label->end()) == "renamed-label");
}
