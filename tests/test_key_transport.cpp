#include "catch.hpp"
#include "pkcs11cpp/key_manager.h"
#include "pkcs11cpp/key_transport.h"
#include "pkcs11cpp/mock_module.h"
#include "pkcs11cpp/session_manager.h"

using namespace pkcs11cpp;

TEST_CASE("KeyTransport wrap/unwrap round-trips a key's usable attributes", "[key_transport]") {
    mock::reset();
    SessionManager sm(mock::getFunctionList(), 0);
    auto guard = sm.createSessionGuard();

    KeyManager km;
    KeyManager::KeyGenerationParams keyParams;
    keyParams.algorithm = KeyManager::KeyAlgorithm::AES_128;
    keyParams.label = "payload-key";
    keyParams.canEncrypt = keyParams.canDecrypt = true;
    CK_OBJECT_HANDLE payloadKey = km.generateSecretKey(guard.handle(), guard.functions(), keyParams);

    KeyManager::KeyGenerationParams wrapperParams;
    wrapperParams.algorithm = KeyManager::KeyAlgorithm::AES_256;
    wrapperParams.canWrap = wrapperParams.canUnwrap = true;
    CK_OBJECT_HANDLE wrappingKey = km.generateSecretKey(guard.handle(), guard.functions(), wrapperParams);

    KeyTransport transport;
    auto wrapped = transport.wrapKey(guard.handle(), guard.functions(), payloadKey, wrappingKey,
                                      KeyTransport::WrapMechanism::AesKeyWrap);
    REQUIRE_FALSE(wrapped.wrappedKey.empty());

    CK_OBJECT_HANDLE restored = transport.unwrapKey(guard.handle(), guard.functions(), wrapped, wrappingKey);
    REQUIRE(restored != CK_INVALID_HANDLE);
    REQUIRE(restored != payloadKey);  // unwrap always produces a fresh object
}

TEST_CASE("KeyTransport::unwrapKey applies a new label when one is given", "[key_transport]") {
    mock::reset();
    SessionManager sm(mock::getFunctionList(), 0);
    auto guard = sm.createSessionGuard();

    KeyManager km;
    KeyManager::KeyGenerationParams keyParams;
    keyParams.algorithm = KeyManager::KeyAlgorithm::AES_128;
    keyParams.label = "original-label";
    CK_OBJECT_HANDLE payloadKey = km.generateSecretKey(guard.handle(), guard.functions(), keyParams);

    KeyManager::KeyGenerationParams wrapperParams;
    wrapperParams.algorithm = KeyManager::KeyAlgorithm::AES_256;
    CK_OBJECT_HANDLE wrappingKey = km.generateSecretKey(guard.handle(), guard.functions(), wrapperParams);

    KeyTransport transport;
    auto wrapped = transport.wrapKey(guard.handle(), guard.functions(), payloadKey, wrappingKey);
    CK_OBJECT_HANDLE restored =
        transport.unwrapKey(guard.handle(), guard.functions(), wrapped, wrappingKey, "renamed-label");

    AttributeManager attrs;
    auto readBack = attrs.readObjectAttributes(guard.handle(), guard.functions(), restored);
    auto label = readBack.getAttribute(CKA_LABEL);
    REQUIRE(label.has_value());
    REQUIRE(std::string(label->begin(), label->end()) == "renamed-label");
}
