#pragma once

// ---------------------------------------------------------------------------
// Minimal PKCS#11 (Cryptoki) type subset.
//
// This header defines only the types, constants and the C_FUNCTION_LIST
// entry points that pkcs11-cpp actually uses. It exists so the library
// builds standalone, without vendoring the full official OASIS pkcs11.h /
// pkcs11t.h / pkcs11f.h headers (which pull in platform-specific packing
// pragmas and a much larger surface than this project needs).
//
// If you link this code against a real PKCS#11 module (SoftHSM2, a
// hardware token driver, etc.), replace this header with the vendor's
// official pkcs11.h family instead -- the names below are chosen to match
// the standard 1:1 so that swap is a drop-in replacement.
// ---------------------------------------------------------------------------

#include <cstdint>

namespace pkcs11cpp {

// --- Base scalar types -----------------------------------------------------
using CK_BYTE = std::uint8_t;
using CK_BYTE_PTR = CK_BYTE*;
using CK_ULONG = unsigned long;
using CK_ULONG_PTR = CK_ULONG*;
using CK_BBOOL = std::uint8_t;
using CK_UTF8CHAR = std::uint8_t;
using CK_UTF8CHAR_PTR = CK_UTF8CHAR*;
using CK_VOID_PTR = void*;

using CK_FLAGS = CK_ULONG;
using CK_RV = CK_ULONG;
using CK_NOTIFICATION = CK_ULONG;
using CK_SLOT_ID = CK_ULONG;
using CK_SESSION_HANDLE = CK_ULONG;
using CK_SESSION_HANDLE_PTR = CK_SESSION_HANDLE*;
using CK_OBJECT_HANDLE = CK_ULONG;
using CK_OBJECT_HANDLE_PTR = CK_OBJECT_HANDLE*;
using CK_OBJECT_CLASS = CK_ULONG;
using CK_KEY_TYPE = CK_ULONG;
using CK_USER_TYPE = CK_ULONG;
using CK_ATTRIBUTE_TYPE = CK_ULONG;
using CK_MECHANISM_TYPE = CK_ULONG;
using CK_MECHANISM_TYPE_PTR = CK_MECHANISM_TYPE*;

// --- Universal constants ----------------------------------------------------
inline constexpr CK_BBOOL CK_TRUE = 1;
inline constexpr CK_BBOOL CK_FALSE = 0;
inline constexpr CK_OBJECT_HANDLE CK_INVALID_HANDLE = 0;
inline constexpr CK_ULONG CK_UNAVAILABLE_INFORMATION =
    static_cast<CK_ULONG>(-1);

// --- Return codes (CKR_*) ---------------------------------------------------
inline constexpr CK_RV CKR_OK = 0x00000000;
inline constexpr CK_RV CKR_GENERAL_ERROR = 0x00000005;
inline constexpr CK_RV CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012;
inline constexpr CK_RV CKR_USER_ALREADY_LOGGED_IN = 0x00000100;
inline constexpr CK_RV CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191;

// --- User types (CKU_*) -----------------------------------------------------
inline constexpr CK_USER_TYPE CKU_USER = 1;

// --- Session flags (CKF_*) --------------------------------------------------
inline constexpr CK_FLAGS CKF_RW_SESSION = 0x00000002;
inline constexpr CK_FLAGS CKF_SERIAL_SESSION = 0x00000004;

// --- Slot / token info flags (CKF_*) ----------------------------------------
inline constexpr CK_FLAGS CKF_TOKEN_PRESENT = 0x00000001;
inline constexpr CK_FLAGS CKF_ERROR_STATE = 0x01000000;
inline constexpr CK_FLAGS CKF_DEVICE_ERROR = 0x00000020;

// --- Mechanism info flags (CKF_*) ------------------------------------------
inline constexpr CK_FLAGS CKF_ENCRYPT = 0x00000100;
inline constexpr CK_FLAGS CKF_DECRYPT = 0x00000200;
inline constexpr CK_FLAGS CKF_SIGN = 0x00000800;
inline constexpr CK_FLAGS CKF_VERIFY = 0x00002000;
inline constexpr CK_FLAGS CKF_WRAP = 0x00020000;
inline constexpr CK_FLAGS CKF_UNWRAP = 0x00040000;
inline constexpr CK_FLAGS CKF_DERIVE = 0x00080000;
inline constexpr CK_FLAGS CKF_GENERATE = 0x00008000;
inline constexpr CK_FLAGS CKF_GENERATE_KEY_PAIR = 0x00010000;

// --- Object classes (CKO_*) -------------------------------------------------
inline constexpr CK_OBJECT_CLASS CKO_PUBLIC_KEY = 0x00000002;
inline constexpr CK_OBJECT_CLASS CKO_PRIVATE_KEY = 0x00000003;
inline constexpr CK_OBJECT_CLASS CKO_SECRET_KEY = 0x00000004;

// --- Key types (CKK_*) -------------------------------------------------------
// NOTE: the real standard calls the elliptic-curve key type CKK_EC; this
// project's call sites use the more descriptive CKK_ECDSA alias.
inline constexpr CK_KEY_TYPE CKK_RSA = 0x00000000;
inline constexpr CK_KEY_TYPE CKK_ECDSA = 0x00000003;
inline constexpr CK_KEY_TYPE CKK_AES = 0x0000001F;
inline constexpr CK_KEY_TYPE CKK_GENERIC_SECRET = 0x00000010;

// --- Object attributes (CKA_*) ----------------------------------------------
inline constexpr CK_ATTRIBUTE_TYPE CKA_CLASS = 0x00000000;
inline constexpr CK_ATTRIBUTE_TYPE CKA_TOKEN = 0x00000001;
inline constexpr CK_ATTRIBUTE_TYPE CKA_PRIVATE = 0x00000002;
inline constexpr CK_ATTRIBUTE_TYPE CKA_LABEL = 0x00000003;
inline constexpr CK_ATTRIBUTE_TYPE CKA_VALUE = 0x00000011;
inline constexpr CK_ATTRIBUTE_TYPE CKA_VALUE_LEN = 0x00000161;
inline constexpr CK_ATTRIBUTE_TYPE CKA_EXTRACTABLE = 0x00000162;
inline constexpr CK_ATTRIBUTE_TYPE CKA_SENSITIVE = 0x00000164;
inline constexpr CK_ATTRIBUTE_TYPE CKA_ID = 0x00000102;
inline constexpr CK_ATTRIBUTE_TYPE CKA_KEY_TYPE = 0x00000100;
inline constexpr CK_ATTRIBUTE_TYPE CKA_DERIVE = 0x0000010C;
inline constexpr CK_ATTRIBUTE_TYPE CKA_ENCRYPT = 0x00000104;
inline constexpr CK_ATTRIBUTE_TYPE CKA_DECRYPT = 0x00000105;
inline constexpr CK_ATTRIBUTE_TYPE CKA_WRAP = 0x00000106;
inline constexpr CK_ATTRIBUTE_TYPE CKA_UNWRAP = 0x00000107;
inline constexpr CK_ATTRIBUTE_TYPE CKA_SIGN = 0x00000108;
inline constexpr CK_ATTRIBUTE_TYPE CKA_VERIFY = 0x0000010A;
inline constexpr CK_ATTRIBUTE_TYPE CKA_MODULUS_BITS = 0x00000121;
inline constexpr CK_ATTRIBUTE_TYPE CKA_PUBLIC_EXPONENT = 0x00000122;
inline constexpr CK_ATTRIBUTE_TYPE CKA_EC_PARAMS = 0x00000180;
inline constexpr CK_ATTRIBUTE_TYPE CKA_VENDOR_DEFINED = 0x80000000;

// --- Mechanism types (CKM_*) -------------------------------------------------
inline constexpr CK_MECHANISM_TYPE CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000;
inline constexpr CK_MECHANISM_TYPE CKM_RSA_PKCS = 0x00000001;
inline constexpr CK_MECHANISM_TYPE CKM_RSA_PKCS_OAEP = 0x00000009;
inline constexpr CK_MECHANISM_TYPE CKM_RSA_PSS = 0x0000000D;
inline constexpr CK_MECHANISM_TYPE CKM_EC_KEY_PAIR_GEN = 0x00001040;
inline constexpr CK_MECHANISM_TYPE CKM_ECDSA = 0x00001041;
inline constexpr CK_MECHANISM_TYPE CKM_ECDH1_DERIVE = 0x00001050;
inline constexpr CK_MECHANISM_TYPE CKM_SHA256 = 0x00000250;
inline constexpr CK_MECHANISM_TYPE CKM_SHA256_HMAC = 0x00000251;
inline constexpr CK_MECHANISM_TYPE CKM_SHA256_RSA_PKCS = 0x00000040;
inline constexpr CK_MECHANISM_TYPE CKM_AES_KEY_GEN = 0x00001080;
inline constexpr CK_MECHANISM_TYPE CKM_AES_ECB = 0x00001081;
inline constexpr CK_MECHANISM_TYPE CKM_AES_CBC = 0x00001082;
inline constexpr CK_MECHANISM_TYPE CKM_AES_CBC_PAD = 0x00001085;
inline constexpr CK_MECHANISM_TYPE CKM_AES_CMAC = 0x0000108A;
inline constexpr CK_MECHANISM_TYPE CKM_AES_GCM = 0x00001087;
inline constexpr CK_MECHANISM_TYPE CKM_AES_KEY_WRAP = 0x00002109;
inline constexpr CK_MECHANISM_TYPE CKM_PKCS5_PBKD2 = 0x000001A2;
inline constexpr CK_MECHANISM_TYPE CKM_SP800_108_COUNTER_KDF = 0x000003AC;

// --- Key-derivation / wrap helper enums -------------------------------------
inline constexpr CK_ULONG CKD_NULL = 0x00000001;
inline constexpr CK_ULONG CKG_MGF1_SHA256 = 0x00000003;
inline constexpr CK_ULONG CKZ_DATA_SPECIFIED = 0x00000001;
inline constexpr CK_ULONG CKZ_SALT_SPECIFIED = 0x00000001;
inline constexpr CK_ULONG CK_SP800_108_DKM_LENGTH_SL_METHOD = 0x00000001;

// --- Structures --------------------------------------------------------------
struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR pValue;
  CK_ULONG ulValueLen;
};
using CK_ATTRIBUTE_PTR = CK_ATTRIBUTE*;

struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR pParameter;
  CK_ULONG ulParameterLen;
};
using CK_MECHANISM_PTR = CK_MECHANISM*;

struct CK_MECHANISM_INFO {
  CK_ULONG ulMinKeySize;
  CK_ULONG ulMaxKeySize;
  CK_FLAGS flags;
};
using CK_MECHANISM_INFO_PTR = CK_MECHANISM_INFO*;

struct CK_SLOT_INFO {
  char slotDescription[64];
  CK_FLAGS flags;
};

struct CK_TOKEN_INFO {
  char label[32];
  CK_FLAGS flags;
  CK_ULONG ulFreePrivateMemory;
  CK_ULONG ulFreePublicMemory;
};

struct CK_ECDH1_DERIVE_PARAMS {
  CK_ULONG kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
};

struct CK_GCM_PARAMS {
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
};

struct CK_RSA_PKCS_OAEP_PARAMS {
  CK_MECHANISM_TYPE hashAlg;
  CK_ULONG mgf;
  CK_ULONG source;
  CK_VOID_PTR pSourceData;
  CK_ULONG ulSourceDataLen;
};

struct CK_PKCS5_PBKD2_PARAMS {
  CK_ULONG saltSource;
  CK_BYTE_PTR pSaltSourceData;
  CK_ULONG ulSaltSourceDataLen;
  CK_ULONG iterations;
  CK_MECHANISM_TYPE prf;
  CK_VOID_PTR pPrfData;
  CK_ULONG ulPrfDataLen;
  CK_UTF8CHAR_PTR pPassword;
  CK_ULONG ulPasswordLen;
};

struct CK_SP800_108_COUNTER_FORMAT {
  CK_BBOOL bLittleEndian;
  CK_ULONG ulWidthInBits;
};

struct CK_SP800_108_DKM_LENGTH_FORMAT {
  CK_ULONG dkmLengthMethod;
  CK_BBOOL bLittleEndian;
  CK_ULONG ulWidthInBits;
};

struct CK_SP800_108_KDF_PARAMS {
  CK_MECHANISM_TYPE macType;
  CK_ULONG ulNumberOfDataParams;
  CK_VOID_PTR pDataParams;
  CK_ULONG ulAdditionalDerivedKeys;
  CK_VOID_PTR pAdditionalDerivedKeys;
};

// --- Function-table (C_FUNCTION_LIST) ---------------------------------------
// A real PKCS#11 module (softHSM2, a vendor's HSM driver, ...) hands the
// application a pointer to a struct shaped like this via C_GetFunctionList.
// pkcs11cpp only depends on this vtable, never on a specific module, which
// is what makes MockModule (see mock_module.h) a drop-in stand-in for tests.
using CK_NOTIFY = CK_RV (*)(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR);

struct CK_FUNCTION_LIST {
  CK_RV (*C_Initialize)(CK_VOID_PTR);
  CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY,
                         CK_SESSION_HANDLE_PTR);
  CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
  CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG);
  CK_RV (*C_GenerateRandom)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
  CK_RV (*C_GenerateKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR,
                         CK_ULONG, CK_OBJECT_HANDLE_PTR);
  CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                             CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR,
                             CK_ULONG, CK_OBJECT_HANDLE_PTR,
                             CK_OBJECT_HANDLE_PTR);
  CK_RV (*C_DeriveKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                       CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);
  CK_RV (*C_WrapKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                     CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
  CK_RV (*C_UnwrapKey)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                       CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG,
                       CK_OBJECT_HANDLE_PTR);
  CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
  CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                  CK_ULONG_PTR);
  CK_RV (*C_VerifyInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
  CK_RV (*C_Verify)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                    CK_ULONG);
  CK_RV (*C_EncryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
  CK_RV (*C_Encrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                     CK_ULONG_PTR);
  CK_RV (*C_DecryptInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
  CK_RV (*C_Decrypt)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                     CK_ULONG_PTR);
  CK_RV (*C_DigestInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR);
  CK_RV (*C_Digest)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                    CK_ULONG_PTR);
  CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                               CK_ATTRIBUTE_PTR, CK_ULONG);
  CK_RV (*C_SetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                               CK_ATTRIBUTE_PTR, CK_ULONG);
  CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
  CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG,
                         CK_ULONG_PTR);
  CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
  CK_RV (*C_DestroyObject)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
  CK_RV (*C_GetSlotList)(CK_BBOOL, CK_ULONG*, CK_ULONG_PTR);
  CK_RV (*C_GetSlotInfo)(CK_SLOT_ID, CK_SLOT_INFO*);
  CK_RV (*C_GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO*);
  CK_RV (*C_GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
  CK_RV (*C_GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE,
                              CK_MECHANISM_INFO_PTR);
};
using CK_FUNCTION_LIST_PTR = CK_FUNCTION_LIST*;
using CK_C_GetFunctionList = CK_RV (*)(CK_FUNCTION_LIST_PTR*);

}  // namespace pkcs11cpp
