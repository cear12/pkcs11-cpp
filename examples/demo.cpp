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

void PrintHeader(const std::string& title) {
    std::cout << "\n=== " << title << " ===\n";
}

std::string ToHex(const std::vector<CK_BYTE>& bytes, std::size_t max_bytes = 16) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < std::min(bytes.size(), max_bytes); ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    if (bytes.size() > max_bytes) oss << "...";
    return oss.str();
}

}  // namespace

int main() {
    // Swap this block for `SessionManager sm("/path/to/vendor-pkcs11.so", slotId, pin);`
    // to run the identical demo against a real token.
    mock::Reset();
    SessionManager sessions(mock::GetFunctionList(), /*slot=*/0, /*pin=*/"1234");
    auto guard = sessions.CreateSessionGuard();
    CK_SESSION_HANDLE session = guard.Handle();
    CK_FUNCTION_LIST_PTR functions = guard.Functions();

    PrintHeader("Mechanism discovery");
    MechanismManager mechanisms;
    mechanisms.DiscoverMechanisms(functions, /*slotId=*/0);
    if (auto best = mechanisms.SelectBestMechanism(0, "encrypt", CKK_AES, 256)) {
        std::cout << "Best AES-256 encrypt mechanism: 0x" << std::hex << *best << std::dec << "\n";
    }

    PrintHeader("Key generation");
    KeyManager key_manager;
    KeyManager::KeyGenerationParams aes_params;
    aes_params.algorithm_ = KeyManager::KeyAlgorithm::kAes256;
    aes_params.label_ = "demo-aes-key";
    aes_params.can_encrypt_ = aes_params.can_decrypt_ = aes_params.can_wrap_ = aes_params.can_unwrap_ = true;
    CK_OBJECT_HANDLE aes_key = key_manager.GenerateSecretKey(session, functions, aes_params);
    std::cout << "Generated AES-256 key, handle=" << aes_key << "\n";

    KeyManager::KeyGenerationParams rsa_params;
    rsa_params.algorithm_ = KeyManager::KeyAlgorithm::kRsa2048;
    rsa_params.label_ = "demo-rsa-signing-key";
    rsa_params.can_sign_ = rsa_params.can_verify_ = true;
    auto rsa_pair = key_manager.GenerateKeyPair(session, functions, rsa_params);
    std::cout << "Generated RSA-2048 key pair, public=" << rsa_pair.public_key_
              << " private=" << rsa_pair.private_key_ << "\n";

    PrintHeader("Attribute introspection");
    AttributeManager attrs;
    auto read_back = attrs.ReadObjectAttributes(session, functions, aes_key);
    std::cout << "AES key has " << read_back.Size() << " readable attributes:\n";
    for (std::size_t i = 0; i < read_back.Size(); ++i) {
        std::cout << "  " << AttributeManager::DescribeAttribute(read_back.Data()[i].type) << "\n";
    }

    PrintHeader("Sign + verify (batched via CryptoProcessor)");
    CryptoProcessor processor(session, functions, /*threadCount=*/2);
    processor.Start();

    std::vector<CK_BYTE> message = {'h', 'e', 'l', 'l', 'o', ' ', 'p', 'k', 'c', 's', '1', '1'};
    auto sign_ids = processor.SubmitSigningBatch({message}, rsa_pair.private_key_, CKM_SHA256_RSA_PKCS);

    // A tiny synchronous wait loop -- fine for a demo; a real application
    // would use onComplete callbacks instead of polling.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    processor.Stop();
    std::cout << "Submitted " << sign_ids.size() << " signing operation(s): " << sign_ids.front() << "\n";

    PrintHeader("Encrypt / decrypt round-trip");
    CK_MECHANISM enc_mech = {CKM_AES_ECB, nullptr, 0};
    functions->C_EncryptInit(session, &enc_mech, aes_key);
    CK_ULONG enc_len = 0;
    functions->C_Encrypt(session, message.data(), static_cast<CK_ULONG>(message.size()), nullptr, &enc_len);
    std::vector<CK_BYTE> ciphertext(enc_len);
    functions->C_Encrypt(session, message.data(), static_cast<CK_ULONG>(message.size()), ciphertext.data(), &enc_len);
    std::cout << "Ciphertext: " << ToHex(ciphertext) << "\n";

    functions->C_DecryptInit(session, &enc_mech, aes_key);
    CK_ULONG dec_len = static_cast<CK_ULONG>(message.size());
    std::vector<CK_BYTE> plaintext(dec_len);
    functions->C_Decrypt(session, ciphertext.data(), enc_len, plaintext.data(), &dec_len);
    plaintext.resize(dec_len);
    std::cout << "Decrypted:  " << std::string(plaintext.begin(), plaintext.end())
              << (plaintext == message ? "  (matches original)" : "  (MISMATCH!)") << "\n";

    PrintHeader("Key wrap / unwrap");
    KeyTransport transport;
    KeyManager::KeyGenerationParams wrapping_params;
    wrapping_params.algorithm_ = KeyManager::KeyAlgorithm::kAes256;
    wrapping_params.label_ = "demo-wrapping-key";
    wrapping_params.can_wrap_ = wrapping_params.can_unwrap_ = true;
    CK_OBJECT_HANDLE wrapping_key = key_manager.GenerateSecretKey(session, functions, wrapping_params);

    auto wrapped = transport.WrapKey(session, functions, aes_key, wrapping_key, KeyTransport::WrapMechanism::kAesKeyWrap);
    std::cout << "Wrapped key (" << wrapped.wrapped_key_.size() << " bytes): " << ToHex(wrapped.wrapped_key_) << "\n";
    CK_OBJECT_HANDLE unwrapped = transport.UnwrapKey(session, functions, wrapped, wrapping_key, "demo-aes-key-restored");
    std::cout << "Unwrapped into new object, handle=" << unwrapped << "\n";

    PrintHeader("Key derivation (SP800-108 counter KDF)");
    KeyDerivation derivation;
    KeyDerivation::DerivationParams kdf_params;
    kdf_params.kdf_type_ = KeyDerivation::KdfType::kSp800108CounterKdf;
    kdf_params.base_key_ = aes_key;
    kdf_params.label_ = {'s', 'e', 's', 's', 'i', 'o', 'n'};
    kdf_params.derived_key_label_ = "demo-derived-key";
    kdf_params.derived_key_length_bytes_ = 16;
    CK_OBJECT_HANDLE derived_key = derivation.DeriveSp800108Key(session, functions, kdf_params);
    std::cout << "Derived key handle=" << derived_key << "\n";

    PrintHeader("Object search");
    ObjectFinder finder;
    auto matches = finder.FindObjects(session, functions,
                                       ObjectFinder::SearchCriteria().WithLabel("demo-aes-key"));
    std::cout << "Found " << matches.size() << " object(s) labeled \"demo-aes-key\"\n";

    PrintHeader("Health monitor");
    HealthMonitor health;
    bool passed = health.PerformComprehensiveTest(functions, /*slotId=*/0, "1234");
    std::cout << "Comprehensive token self-test: " << (passed ? "PASS" : "FAIL") << "\n";

    std::cout << "\nAll steps completed.\n";
    return passed ? 0 : 1;
}
