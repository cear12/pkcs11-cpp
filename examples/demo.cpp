// End-to-end walkthrough of pkcs11-cpp against the in-process mock PKCS#11
// backend (pkcs11cpp::mock) -- no hardware token or SoftHSM2 required.
//
// Build & run:
//   cmake -B build -DCMAKE_BUILD_TYPE=Release
//   cmake --build build
//   ./build/examples/pkcs11cpp_demo
//
// Point SessionManager at a real module instead (see main() below) to run
// the exact same workflow against actual hardware.

#include <iomanip>
#include <iostream>

#include "pkcs11cpp/attribute_manager.h"
#include "pkcs11cpp/crypto_processor.h"
#include "pkcs11cpp/health_monitor.h"
#include "pkcs11cpp/key_derivation.h"
#include "pkcs11cpp/key_manager.h"
#include "pkcs11cpp/key_transport.h"
#include "pkcs11cpp/mechanism_manager.h"
#include "pkcs11cpp/mock_module.h"
#include "pkcs11cpp/object_finder.h"
#include "pkcs11cpp/session_manager.h"

using namespace pkcs11cpp;

namespace {

void printHeader(const std::string& title) {
    std::cout << "\n=== " << title << " ===\n";
}

std::string toHex(const std::vector<CK_BYTE>& bytes, std::size_t maxBytes = 16) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < std::min(bytes.size(), maxBytes); ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    if (bytes.size() > maxBytes) oss << "...";
    return oss.str();
}

}  // namespace

int main() {
    // Swap this block for `SessionManager sm("/path/to/vendor-pkcs11.so", slotId, pin);`
    // to run the identical demo against a real token.
    mock::reset();
    SessionManager sessions(mock::getFunctionList(), /*slot=*/0, /*pin=*/"1234");
    auto guard = sessions.createSessionGuard();
    CK_SESSION_HANDLE session = guard.handle();
    CK_FUNCTION_LIST_PTR functions = guard.functions();

    printHeader("Mechanism discovery");
    MechanismManager mechanisms;
    mechanisms.discoverMechanisms(functions, /*slotId=*/0);
    if (auto best = mechanisms.selectBestMechanism(0, "encrypt", CKK_AES, 256)) {
        std::cout << "Best AES-256 encrypt mechanism: 0x" << std::hex << *best << std::dec << "\n";
    }

    printHeader("Key generation");
    KeyManager keyManager;
    KeyManager::KeyGenerationParams aesParams;
    aesParams.algorithm = KeyManager::KeyAlgorithm::AES_256;
    aesParams.label = "demo-aes-key";
    aesParams.canEncrypt = aesParams.canDecrypt = aesParams.canWrap = aesParams.canUnwrap = true;
    CK_OBJECT_HANDLE aesKey = keyManager.generateSecretKey(session, functions, aesParams);
    std::cout << "Generated AES-256 key, handle=" << aesKey << "\n";

    KeyManager::KeyGenerationParams rsaParams;
    rsaParams.algorithm = KeyManager::KeyAlgorithm::RSA_2048;
    rsaParams.label = "demo-rsa-signing-key";
    rsaParams.canSign = rsaParams.canVerify = true;
    auto rsaPair = keyManager.generateKeyPair(session, functions, rsaParams);
    std::cout << "Generated RSA-2048 key pair, public=" << rsaPair.publicKey
              << " private=" << rsaPair.privateKey << "\n";

    printHeader("Attribute introspection");
    AttributeManager attrs;
    auto readBack = attrs.readObjectAttributes(session, functions, aesKey);
    std::cout << "AES key has " << readBack.size() << " readable attributes:\n";
    for (std::size_t i = 0; i < readBack.size(); ++i) {
        std::cout << "  " << AttributeManager::describeAttribute(readBack.data()[i].type) << "\n";
    }

    printHeader("Sign + verify (batched via CryptoProcessor)");
    CryptoProcessor processor(session, functions, /*threadCount=*/2);
    processor.start();

    std::vector<CK_BYTE> message = {'h', 'e', 'l', 'l', 'o', ' ', 'p', 'k', 'c', 's', '1', '1'};
    auto signIds = processor.submitSigningBatch({message}, rsaPair.privateKey, CKM_SHA256_RSA_PKCS);

    // A tiny synchronous wait loop -- fine for a demo; a real application
    // would use onComplete callbacks instead of polling.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    processor.stop();
    std::cout << "Submitted " << signIds.size() << " signing operation(s): " << signIds.front() << "\n";

    printHeader("Encrypt / decrypt round-trip");
    CK_MECHANISM encMech = {CKM_AES_ECB, nullptr, 0};
    functions->C_EncryptInit(session, &encMech, aesKey);
    CK_ULONG encLen = 0;
    functions->C_Encrypt(session, message.data(), static_cast<CK_ULONG>(message.size()), nullptr, &encLen);
    std::vector<CK_BYTE> ciphertext(encLen);
    functions->C_Encrypt(session, message.data(), static_cast<CK_ULONG>(message.size()), ciphertext.data(), &encLen);
    std::cout << "Ciphertext: " << toHex(ciphertext) << "\n";

    functions->C_DecryptInit(session, &encMech, aesKey);
    CK_ULONG decLen = static_cast<CK_ULONG>(message.size());
    std::vector<CK_BYTE> plaintext(decLen);
    functions->C_Decrypt(session, ciphertext.data(), encLen, plaintext.data(), &decLen);
    plaintext.resize(decLen);
    std::cout << "Decrypted:  " << std::string(plaintext.begin(), plaintext.end())
              << (plaintext == message ? "  (matches original)" : "  (MISMATCH!)") << "\n";

    printHeader("Key wrap / unwrap");
    KeyTransport transport;
    KeyManager::KeyGenerationParams wrappingParams;
    wrappingParams.algorithm = KeyManager::KeyAlgorithm::AES_256;
    wrappingParams.label = "demo-wrapping-key";
    wrappingParams.canWrap = wrappingParams.canUnwrap = true;
    CK_OBJECT_HANDLE wrappingKey = keyManager.generateSecretKey(session, functions, wrappingParams);

    auto wrapped = transport.wrapKey(session, functions, aesKey, wrappingKey, KeyTransport::WrapMechanism::AesKeyWrap);
    std::cout << "Wrapped key (" << wrapped.wrappedKey.size() << " bytes): " << toHex(wrapped.wrappedKey) << "\n";
    CK_OBJECT_HANDLE unwrapped = transport.unwrapKey(session, functions, wrapped, wrappingKey, "demo-aes-key-restored");
    std::cout << "Unwrapped into new object, handle=" << unwrapped << "\n";

    printHeader("Key derivation (SP800-108 counter KDF)");
    KeyDerivation derivation;
    KeyDerivation::DerivationParams kdfParams;
    kdfParams.kdfType = KeyDerivation::KdfType::Sp800_108CounterKdf;
    kdfParams.baseKey = aesKey;
    kdfParams.label = {'s', 'e', 's', 's', 'i', 'o', 'n'};
    kdfParams.derivedKeyLabel = "demo-derived-key";
    kdfParams.derivedKeyLengthBytes = 16;
    CK_OBJECT_HANDLE derivedKey = derivation.deriveSp800_108Key(session, functions, kdfParams);
    std::cout << "Derived key handle=" << derivedKey << "\n";

    printHeader("Object search");
    ObjectFinder finder;
    auto matches = finder.findObjects(session, functions,
                                       ObjectFinder::SearchCriteria().withLabel("demo-aes-key"));
    std::cout << "Found " << matches.size() << " object(s) labeled \"demo-aes-key\"\n";

    printHeader("Health monitor");
    HealthMonitor health;
    bool passed = health.performComprehensiveTest(functions, /*slotId=*/0, "1234");
    std::cout << "Comprehensive token self-test: " << (passed ? "PASS" : "FAIL") << "\n";

    std::cout << "\nAll steps completed.\n";
    return passed ? 0 : 1;
}
