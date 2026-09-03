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
        enum class Type { Sign, Verify, Encrypt, Decrypt, Digest };

        Type type;
        CK_OBJECT_HANDLE keyHandle = CK_INVALID_HANDLE;
        CK_MECHANISM mechanism{};
        std::vector<CK_BYTE> inputData;
        std::vector<CK_BYTE> outputData;
        std::vector<CK_BYTE> signature;  // input to Verify
        bool completed = false;
        CK_RV result = CKR_OK;
        std::string operationId;
        std::function<void(const Operation&)> onComplete;
    };

    CryptoProcessor(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                     std::size_t threadCount = std::thread::hardware_concurrency());
    ~CryptoProcessor();

    CryptoProcessor(const CryptoProcessor&) = delete;
    CryptoProcessor& operator=(const CryptoProcessor&) = delete;

    void start();
    void stop();

    std::string submit(std::unique_ptr<Operation> operation);

    std::vector<std::string> submitSigningBatch(const std::vector<std::vector<CK_BYTE>>& dataToSign,
                                                 CK_OBJECT_HANDLE signingKey,
                                                 CK_MECHANISM_TYPE mechanismType = CKM_SHA256_RSA_PKCS);

    std::vector<std::string> submitEncryptionBatch(const std::vector<std::vector<CK_BYTE>>& dataToEncrypt,
                                                     CK_OBJECT_HANDLE encryptionKey,
                                                     CK_MECHANISM_TYPE mechanismType = CKM_AES_CBC_PAD,
                                                     const std::vector<CK_BYTE>& iv = {});

private:
    void workerLoop();
    void processOperation(Operation& operation);
    void processSigning(Operation& operation);
    void processVerification(Operation& operation);
    void processEncryption(Operation& operation);
    void processDecryption(Operation& operation);
    void processDigest(Operation& operation);
    static std::string generateOperationId();

    CK_SESSION_HANDLE session_;
    CK_FUNCTION_LIST_PTR functions_;
    std::size_t maxThreads_;

    std::queue<std::unique_ptr<Operation>> queue_;
    std::mutex queueMutex_;
    std::condition_variable queueCondition_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
};

}  // namespace pkcs11cpp
