#include "pkcs11cpp/crypto_processor.h"

#include <atomic>
#include <chrono>

namespace pkcs11cpp {

CryptoProcessor::CryptoProcessor(CK_SESSION_HANDLE session,
                                 CK_FUNCTION_LIST_PTR functions,
                                 std::size_t thread_count)
    : session_(session),
      functions_(functions),
      max_threads_(thread_count == 0 ? 1 : thread_count) {}

CryptoProcessor::~CryptoProcessor() { Stop(); }

void CryptoProcessor::Start() {
  if (running_.exchange(true)) return;  // already running
  workers_.reserve(max_threads_);
  for (std::size_t i = 0; i < max_threads_; ++i) {
    workers_.emplace_back([this] { WorkerLoop(); });
  }
}

void CryptoProcessor::Stop() {
  if (!running_.exchange(false)) return;  // already stopped
  queue_condition_.notify_all();
  for (auto& thread : workers_) {
    if (thread.joinable()) thread.join();
  }
  workers_.clear();
}

std::string CryptoProcessor::Submit(std::unique_ptr<Operation> operation) {
  std::string id = GenerateOperationId();
  operation->operation_id_ = id;
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    queue_.push(std::move(operation));
  }
  queue_condition_.notify_one();
  return id;
}

std::vector<std::string> CryptoProcessor::SubmitSigningBatch(
    const std::vector<std::vector<CK_BYTE>>& data_to_sign,
    CK_OBJECT_HANDLE signing_key, CK_MECHANISM_TYPE mechanism_type) {
  std::vector<std::string> ids;
  ids.reserve(data_to_sign.size());
  for (const auto& data : data_to_sign) {
    auto op = std::make_unique<Operation>();
    op->type_ = Operation::Type::kSign;
    op->key_handle_ = signing_key;
    op->mechanism_ = {mechanism_type, nullptr, 0};
    op->input_data_ = data;
    ids.push_back(Submit(std::move(op)));
  }
  return ids;
}

std::vector<std::string> CryptoProcessor::SubmitEncryptionBatch(
    const std::vector<std::vector<CK_BYTE>>& data_to_encrypt,
    CK_OBJECT_HANDLE encryption_key, CK_MECHANISM_TYPE mechanism_type,
    const std::vector<CK_BYTE>& iv) {
  std::vector<std::string> ids;
  ids.reserve(data_to_encrypt.size());
  for (const auto& data : data_to_encrypt) {
    auto op = std::make_unique<Operation>();
    op->type_ = Operation::Type::kEncrypt;
    op->key_handle_ = encryption_key;
    // iv is copied into the operation (not just referenced) so it
    // stays alive for however long this op sits in the queue.
    op->output_data_.clear();
    if (!iv.empty()) {
      op->signature_ = iv;  // reuse the otherwise-unused `signature` slot to
                            // carry the IV bytes
      op->mechanism_ = {mechanism_type, op->signature_.data(),
                        static_cast<CK_ULONG>(op->signature_.size())};
    } else {
      op->mechanism_ = {mechanism_type, nullptr, 0};
    }
    op->input_data_ = data;
    ids.push_back(Submit(std::move(op)));
  }
  return ids;
}

void CryptoProcessor::WorkerLoop() {
  while (running_.load()) {
    std::unique_ptr<Operation> operation;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_condition_.wait(
          lock, [this] { return !queue_.empty() || !running_.load(); });
      if (!running_.load()) break;
      if (!queue_.empty()) {
        operation = std::move(queue_.front());
        queue_.pop();
      }
    }
    if (operation) {
      ProcessOperation(*operation);
      if (operation->on_complete_) operation->on_complete_(*operation);
    }
  }
}

void CryptoProcessor::ProcessOperation(Operation& operation) {
  try {
    switch (operation.type_) {
      case Operation::Type::kSign:
        ProcessSigning(operation);
        break;
      case Operation::Type::kVerify:
        ProcessVerification(operation);
        break;
      case Operation::Type::kEncrypt:
        ProcessEncryption(operation);
        break;
      case Operation::Type::kDecrypt:
        ProcessDecryption(operation);
        break;
      case Operation::Type::kDigest:
        ProcessDigest(operation);
        break;
    }
    operation.completed_ = true;
  } catch (const std::exception&) {
    operation.result_ = CKR_GENERAL_ERROR;
    operation.completed_ = true;
  }
}

void CryptoProcessor::ProcessSigning(Operation& operation) {
  CK_RV rv = functions_->C_SignInit(session_, &operation.mechanism_,
                                    operation.key_handle_);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  CK_ULONG signature_len = 0;
  rv = functions_->C_Sign(session_, operation.input_data_.data(),
                          static_cast<CK_ULONG>(operation.input_data_.size()),
                          nullptr, &signature_len);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  operation.output_data_.resize(signature_len);
  rv = functions_->C_Sign(session_, operation.input_data_.data(),
                          static_cast<CK_ULONG>(operation.input_data_.size()),
                          operation.output_data_.data(), &signature_len);
  operation.output_data_.resize(signature_len);
  operation.result_ = rv;
}

void CryptoProcessor::ProcessVerification(Operation& operation) {
  CK_RV rv = functions_->C_VerifyInit(session_, &operation.mechanism_,
                                      operation.key_handle_);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  rv = functions_->C_Verify(session_, operation.input_data_.data(),
                            static_cast<CK_ULONG>(operation.input_data_.size()),
                            operation.signature_.data(),
                            static_cast<CK_ULONG>(operation.signature_.size()));
  operation.result_ = rv;
}

void CryptoProcessor::ProcessEncryption(Operation& operation) {
  CK_RV rv = functions_->C_EncryptInit(session_, &operation.mechanism_,
                                       operation.key_handle_);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  CK_ULONG encrypted_len = 0;
  rv =
      functions_->C_Encrypt(session_, operation.input_data_.data(),
                            static_cast<CK_ULONG>(operation.input_data_.size()),
                            nullptr, &encrypted_len);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  operation.output_data_.resize(encrypted_len);
  rv =
      functions_->C_Encrypt(session_, operation.input_data_.data(),
                            static_cast<CK_ULONG>(operation.input_data_.size()),
                            operation.output_data_.data(), &encrypted_len);
  operation.output_data_.resize(encrypted_len);
  operation.result_ = rv;
}

void CryptoProcessor::ProcessDecryption(Operation& operation) {
  CK_RV rv = functions_->C_DecryptInit(session_, &operation.mechanism_,
                                       operation.key_handle_);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  CK_ULONG decrypted_len = 0;
  rv =
      functions_->C_Decrypt(session_, operation.input_data_.data(),
                            static_cast<CK_ULONG>(operation.input_data_.size()),
                            nullptr, &decrypted_len);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  operation.output_data_.resize(decrypted_len);
  rv =
      functions_->C_Decrypt(session_, operation.input_data_.data(),
                            static_cast<CK_ULONG>(operation.input_data_.size()),
                            operation.output_data_.data(), &decrypted_len);
  operation.output_data_.resize(decrypted_len);
  operation.result_ = rv;
}

void CryptoProcessor::ProcessDigest(Operation& operation) {
  CK_RV rv = functions_->C_DigestInit(session_, &operation.mechanism_);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  CK_ULONG digest_len = 0;
  rv = functions_->C_Digest(session_, operation.input_data_.data(),
                            static_cast<CK_ULONG>(operation.input_data_.size()),
                            nullptr, &digest_len);
  if (rv != CKR_OK) {
    operation.result_ = rv;
    return;
  }

  operation.output_data_.resize(digest_len);
  rv = functions_->C_Digest(session_, operation.input_data_.data(),
                            static_cast<CK_ULONG>(operation.input_data_.size()),
                            operation.output_data_.data(), &digest_len);
  operation.output_data_.resize(digest_len);
  operation.result_ = rv;
}

std::string CryptoProcessor::GenerateOperationId() {
  static std::atomic<std::uint64_t> counter{0};
  auto now = std::chrono::steady_clock::now().time_since_epoch().count();
  return std::to_string(counter.fetch_add(1)) + "_" + std::to_string(now);
}

}  // namespace pkcs11cpp
