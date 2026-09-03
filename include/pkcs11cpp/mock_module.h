#pragma once

#include "pkcs11cpp/types.h"

namespace pkcs11cpp::mock {

// A tiny in-process software implementation of the PKCS#11 C_FUNCTION_LIST
// vtable: one virtual slot, one always-present "token", objects held in
// memory, and simplified-but-real cryptographic primitives (SHA-256,
// HMAC-SHA256) standing in for what a hardware token would normally do.
//
// This exists so the rest of pkcs11-cpp -- SessionManager, KeyManager,
// CryptoProcessor, and friends -- can be exercised end-to-end (unit tests,
// the examples/demo.cpp walkthrough) without a real HSM or SoftHSM2
// installed. It is a test double, not a cryptographic provider:
//
//   * Encrypt/Decrypt XOR the input against a keystream derived from the
//     key material via HMAC-SHA256. This is NOT AES and provides no real
//     confidentiality -- swap in a real PKCS#11 module for anything that
//     touches actual secrets.
//   * Sign/Verify compute/check an HMAC-SHA256 rather than a real
//     RSA/ECDSA signature.
//   * Key "generation" fills the requested byte length with output from a
//     seeded PRNG, it does not produce structurally valid RSA/EC keys.
//
// Swap this module for a real one (SoftHSM2, a vendor's PKCS#11 driver)
// by pointing SessionManager at that library's C_GetFunctionList instead
// of GetFunctionList() below -- every class above this layer only depends
// on the CK_FUNCTION_LIST_PTR interface.
CK_FUNCTION_LIST_PTR GetFunctionList();

// Clears all sessions and objects. Call between test cases so each test
// starts from a known-empty token.
void Reset();

// Test hook: makes the next C_GetTokenInfo report low free memory, so
// HealthMonitor's warning path can be exercised deterministically.
void SimulateLowMemory(bool enabled);

}  // namespace pkcs11cpp::mock
