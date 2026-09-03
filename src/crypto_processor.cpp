#include "pkcs11cpp/crypto_processor.h"

#include <atomic>
#include <chrono>

namespace pkcs11cpp {

CryptoProcessor::CryptoProcessor(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions,
                                  std::size_t threadCount)
    : session_(session), functions_(functions), maxThreads_(threadCount == 0 ? 1 : threadCount) {}

CryptoProcessor::~CryptoProcessor() { stop(); }

void CryptoProcessor::start() {
    if (running_.exchange(true)) return;  // already running
    workers_.reserve(maxThreads_);
    for (std::size_t i = 0; i < maxThreads_; ++i) {
        workers_.emplace_back([this] { workerLoop(); });
    }
}

void CryptoProcessor::stop() {
    if (!running_.exchange(false)) return;  // already stopped
    queueCondition_.notify_all();
    for (auto& thread : workers_) {
        if (thread.joinable()) thread.join();
    }
    workers_.clear();
}

std::string CryptoProcessor::submit(std::unique_ptr<Operation> operation) {
    std::string id = generateOperationId();
    operation->operationId = id;
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        queue_.push(std::move(operation));
    }
    queueCondition_.notify_one();
    return id;
}

std::vector<std::string> CryptoProcessor::submitSigningBatch(const std::vector<std::vector<CK_BYTE>>& dataToSign,
                                                               CK_OBJECT_HANDLE signingKey,
                                                               CK_MECHANISM_TYPE mechanismType) {
    std::vector<std::string> ids;
    ids.reserve(dataToSign.size());
    for (const auto& data : dataToSign) {
        auto op = std::make_unique<Operation>();
        op->type = Operation::Type::Sign;
        op->keyHandle = signingKey;
        op->mechanism = {mechanismType, nullptr, 0};
        op->inputData = data;
        ids.push_back(submit(std::move(op)));
    }
    return ids;
}

std::vector<std::string> CryptoProcessor::submitEncryptionBatch(const std::vector<std::vector<CK_BYTE>>& dataToEncrypt,
                                                                  CK_OBJECT_HANDLE encryptionKey,
                                                                  CK_MECHANISM_TYPE mechanismType,
                                                                  const std::vector<CK_BYTE>& iv) {
    std::vector<std::string> ids;
    ids.reserve(dataToEncrypt.size());
    for (const auto& data : dataToEncrypt) {
        auto op = std::make_unique<Operation>();
        op->type = Operation::Type::Encrypt;
        op->keyHandle = encryptionKey;
        // iv is copied into the operation (not just referenced) so it
        // stays alive for however long this op sits in the queue.
        op->outputData.clear();
        if (!iv.empty()) {
            op->signature = iv;  // reuse the otherwise-unused `signature` slot to carry the IV bytes
            op->mechanism = {mechanismType, op->signature.data(), static_cast<CK_ULONG>(op->signature.size())};
        } else {
            op->mechanism = {mechanismType, nullptr, 0};
        }
        op->inputData = data;
        ids.push_back(submit(std::move(op)));
    }
    return ids;
}

void CryptoProcessor::workerLoop() {
    while (running_.load()) {
        std::unique_ptr<Operation> operation;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCondition_.wait(lock, [this] { return !queue_.empty() || !running_.load(); });
            if (!running_.load()) break;
            if (!queue_.empty()) {
                operation = std::move(queue_.front());
                queue_.pop();
            }
        }
        if (operation) {
            processOperation(*operation);
            if (operation->onComplete) operation->onComplete(*operation);
        }
    }
}

void CryptoProcessor::processOperation(Operation& operation) {
    try {
        switch (operation.type) {
            case Operation::Type::Sign: processSigning(operation); break;
            case Operation::Type::Verify: processVerification(operation); break;
            case Operation::Type::Encrypt: processEncryption(operation); break;
            case Operation::Type::Decrypt: processDecryption(operation); break;
            case Operation::Type::Digest: processDigest(operation); break;
        }
        operation.completed = true;
    } catch (const std::exception&) {
        operation.result = CKR_GENERAL_ERROR;
        operation.completed = true;
    }
}

void CryptoProcessor::processSigning(Operation& operation) {
    CK_RV rv = functions_->C_SignInit(session_, &operation.mechanism, operation.keyHandle);
    if (rv != CKR_OK) { operation.result = rv; return; }

    CK_ULONG signatureLen = 0;
    rv = functions_->C_Sign(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                             nullptr, &signatureLen);
    if (rv != CKR_OK) { operation.result = rv; return; }

    operation.outputData.resize(signatureLen);
    rv = functions_->C_Sign(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                             operation.outputData.data(), &signatureLen);
    operation.outputData.resize(signatureLen);
    operation.result = rv;
}

void CryptoProcessor::processVerification(Operation& operation) {
    CK_RV rv = functions_->C_VerifyInit(session_, &operation.mechanism, operation.keyHandle);
    if (rv != CKR_OK) { operation.result = rv; return; }

    rv = functions_->C_Verify(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                               operation.signature.data(), static_cast<CK_ULONG>(operation.signature.size()));
    operation.result = rv;
}

void CryptoProcessor::processEncryption(Operation& operation) {
    CK_RV rv = functions_->C_EncryptInit(session_, &operation.mechanism, operation.keyHandle);
    if (rv != CKR_OK) { operation.result = rv; return; }

    CK_ULONG encryptedLen = 0;
    rv = functions_->C_Encrypt(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                                nullptr, &encryptedLen);
    if (rv != CKR_OK) { operation.result = rv; return; }

    operation.outputData.resize(encryptedLen);
    rv = functions_->C_Encrypt(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                                operation.outputData.data(), &encryptedLen);
    operation.outputData.resize(encryptedLen);
    operation.result = rv;
}

void CryptoProcessor::processDecryption(Operation& operation) {
    CK_RV rv = functions_->C_DecryptInit(session_, &operation.mechanism, operation.keyHandle);
    if (rv != CKR_OK) { operation.result = rv; return; }

    CK_ULONG decryptedLen = 0;
    rv = functions_->C_Decrypt(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                                nullptr, &decryptedLen);
    if (rv != CKR_OK) { operation.result = rv; return; }

    operation.outputData.resize(decryptedLen);
    rv = functions_->C_Decrypt(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                                operation.outputData.data(), &decryptedLen);
    operation.outputData.resize(decryptedLen);
    operation.result = rv;
}

void CryptoProcessor::processDigest(Operation& operation) {
    CK_RV rv = functions_->C_DigestInit(session_, &operation.mechanism);
    if (rv != CKR_OK) { operation.result = rv; return; }

    CK_ULONG digestLen = 0;
    rv = functions_->C_Digest(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                               nullptr, &digestLen);
    if (rv != CKR_OK) { operation.result = rv; return; }

    operation.outputData.resize(digestLen);
    rv = functions_->C_Digest(session_, operation.inputData.data(), static_cast<CK_ULONG>(operation.inputData.size()),
                               operation.outputData.data(), &digestLen);
    operation.outputData.resize(digestLen);
    operation.result = rv;
}

std::string CryptoProcessor::generateOperationId() {
    static std::atomic<std::uint64_t> counter{0};
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::to_string(counter.fetch_add(1)) + "_" + std::to_string(now);
}

}  // namespace pkcs11cpp
