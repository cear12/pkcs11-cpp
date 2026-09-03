# pkcs11-cpp

![CI](https://github.com/cear12/pkcs11-cpp/actions/workflows/ci.yml/badge.svg)

A modern C++20 wrapper library around the [PKCS#11](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.1/os/pkcs11-base-v3.1-os.html)
cryptographic-token API (HSMs, smart cards, software tokens). PKCS#11's raw
C interface is powerful but low-level: manual two-pass attribute buffers,
per-thread session bookkeeping, and a function-pointer vtable you fetch by
hand from a shared library. This project wraps that surface in RAII types
and small, composable classes so application code reads like intent
("generate an AES-256 key, wrap it, derive a session key from it") instead
of PKCS#11 plumbing.

## Contents

- [Modules](#modules)
- [Architecture](#architecture)
- [Building](#building)
- [Running the demo](#running-the-demo)
- [Testing](#testing)
- [Using it against a real token](#using-it-against-a-real-token)
- [Status / limitations](#status--limitations)

## Modules

| Module | Header | Responsibility |
|---|---|---|
| `SessionManager` | `session_manager.h` | Loads a PKCS#11 module (or attaches to an existing function list), opens one session per calling thread, logs in, and cleans up in its destructor. |
| `AttributeManager` | `attribute_manager.h` | Builds `CK_ATTRIBUTE` templates without manual pointer/length bookkeeping; reads an object's attributes via the standard two-pass protocol. |
| `MechanismManager` | `mechanism_manager.h` | Discovers what a slot supports and picks the best mechanism for an operation + key type instead of hardcoding one. |
| `KeyManager` | `key_manager.h` | Generates RSA/EC key pairs and AES secret keys from a small, friendly `KeyAlgorithm` enum. |
| `KeyDerivation` | `key_derivation.h` | ECDH key agreement, SP 800-108 counter-mode KDF, PBKDF2, and chained derivation. |
| `KeyTransport` | `key_transport.h` | Wraps/unwraps keys for export, carrying along enough of the original template that the round trip preserves usage flags. |
| `CryptoProcessor` | `crypto_processor.h` | Thread-pool batch processor for sign/verify/encrypt/decrypt/digest, with per-operation completion callbacks. |
| `ObjectFinder` | `object_finder.h` | `C_FindObjects*` behind one call, with a small time-based cache. |
| `HealthMonitor` | `health_monitor.h` | Background slot/token polling (error state, low memory) plus a one-shot end-to-end self-test. |

## Architecture

Every class above depends only on a `CK_FUNCTION_LIST_PTR` -- the standard
PKCS#11 vtable of C function pointers -- never on a specific module. That
makes the whole library testable without hardware:
[`pkcs11cpp::mock`](include/pkcs11cpp/mock_module.h) is a small in-process
software implementation of that vtable (one virtual slot, objects held in
memory, HMAC-SHA256 standing in for real signing). Swap it for a real
module -- SoftHSM2, a vendor's HSM driver -- by pointing `SessionManager`
at that library's path instead; every other class is unaffected.

```
 SessionManager ─┐
                 ├─> CK_FUNCTION_LIST_PTR ──> pkcs11cpp::mock   (tests / demo, this repo)
 KeyManager      │                        └─> a real .so/.dll  (production, bring your own)
 CryptoProcessor │
 ObjectFinder   ─┘
```

`types.h` defines the minimal PKCS#11 type/constant subset the library
actually uses, so the whole thing builds without vendoring the full OASIS
`pkcs11.h` header family. Point it at the real headers instead if you need
100% spec coverage.

The library has **zero third-party runtime dependencies** -- `sha256.h`
vendors a small from-scratch SHA-256/HMAC-SHA256 implementation rather
than linking OpenSSL, so `cmake && cmake --build` works out of the box.
[Catch2](https://github.com/catchorg/Catch2) (single-header, v2.13, BSL-1.0
license) is vendored under `tests/third_party/` for the test suite only.

## Building

Requires a C++20 compiler and CMake >= 3.16.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Useful options: `-DPKCS11CPP_BUILD_TESTS=OFF`, `-DPKCS11CPP_BUILD_EXAMPLES=OFF`.

## Running the demo

`examples/demo.cpp` walks through the whole library against the mock
backend -- session setup, RSA + AES key generation, attribute
introspection, batched signing, encrypt/decrypt, wrap/unwrap, key
derivation, object search, and a health check -- printing what each step
produced:

```bash
./build/examples/pkcs11cpp_demo
```

## Testing

```bash
cmake --build build
ctest --test-dir build --output-on-failure
```

30 Catch2 test cases (67 assertions) cover the modules with real,
non-trivial logic: template building/validation, mechanism selection,
object search/caching, key-pair generation, KDF chaining, wrap/unwrap
round-trips, batched crypto, and health-check reporting. Thin
pass-through wrappers around a single PKCS#11 call are exercised via the
demo instead of duplicating hand-written tests for them.

## Using it against a real token

```cpp
#include "pkcs11cpp/session_manager.h"

// Loads a real PKCS#11 module from disk instead of the mock backend.
pkcs11cpp::SessionManager sessions("/usr/lib/softhsm/libsofthsm2.so", /*slot=*/0, /*pin=*/"1234");
auto guard = sessions.createSessionGuard();
// guard.handle() / guard.functions() work with every other class exactly
// as they do in examples/demo.cpp.
```

## Status / limitations

This is a portfolio/learning project, not an audited security library:

- The mock backend's "encryption" is an HMAC-derived XOR keystream and its
  "signatures" are HMAC-SHA256 -- realistic enough to exercise the wrapper
  API end-to-end, not a substitute for real AES/RSA/ECDSA. See the class
  comment in [`mock_module.h`](include/pkcs11cpp/mock_module.h).
- `types.h` covers the mechanisms/attributes this repo uses, not the full
  PKCS#11 v3.1 surface.
- 3DES key generation is intentionally left unimplemented (deprecated
  algorithm; see `KeyManager::generateDes3Key`).
