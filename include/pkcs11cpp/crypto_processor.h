#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// A thread-pool batch processor for PKCS#11 sign/verify/encrypt/decrypt
// operations: submit work from any thread, get an operation id back
// immediately, and optionally register a completion callback. Useful when
// signing/encrypting many small items (e.g. a batch of documents) where
// issuing them one C_Sign call at a time, serially, leaves the token's
// parallelism (and the round-trip latency to a network HSM) on the table.
class CryptoProcessor {
public:
    struct Operation {
        enum class Type { kSign, kVerify, kEncrypt, kDecrypt, kDigest };

        Type type_;
        CK_OBJECT_HANDLE key_handle_ = CK_INVALID_HANDLE;
        CK_MECHANISM mechanism_{};
        std::vector<CK_BYTE> input_data_;
        std::vector<CK_BYTE> output_data_;
        std::vector<CK_BYTE> signature_;  // input to Verify
        bool completed_ = false;
        CK_RV result_ = CKR_OK;
        std::string operation_id_;
        std::function<void(const Operation&)> on_complete_;
    };

    CryptoProcessor(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                     std::size_t thread_count = std::thread::hardware_concurrency());
    ~CryptoProcessor();

    CryptoProcessor(const CryptoProcessor&) = delete;
    CryptoProcessor& operator=(const CryptoProcessor&) = delete;

    void Start();
    void Stop();

    std::string Submit(std::unique_ptr<Operation> operation);

    std::vector<std::string> SubmitSigningBatch(const std::vector<std::vector<CK_BYTE>>& data_to_sign,
                                                 CK_OBJECT_HANDLE signing_key,
                                                 CK_MECHANISM_TYPE mechanism_type = CKM_SHA256_RSA_PKCS);

    std::vector<std::string> SubmitEncryptionBatch(const std::vector<std::vector<CK_BYTE>>& data_to_encrypt,
                                                     CK_OBJECT_HANDLE encryption_key,
                                                     CK_MECHANISM_TYPE mechanism_type = CKM_AES_CBC_PAD,
                                                     const std::vector<CK_BYTE>& iv = {});

private:
    void WorkerLoop();
    void ProcessOperation(Operation& operation);
    void ProcessSigning(Operation& operation);
    void ProcessVerification(Operation& operation);
    void ProcessEncryption(Operation& operation);
    void ProcessDecryption(Operation& operation);
    void ProcessDigest(Operation& operation);
    static std::string GenerateOperationId();

    CK_SESSION_HANDLE session_;
    CK_FUNCTION_LIST_PTR functions_;
    std::size_t max_threads_;

    std::queue<std::unique_ptr<Operation>> queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_condition_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
};

}  // namespace pkcs11cpp
