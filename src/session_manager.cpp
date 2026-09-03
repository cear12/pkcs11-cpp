#include "pkcs11cpp/session_manager.h"

#include <dlfcn.h>

#include <stdexcept>

namespace pkcs11cpp {

SessionManager::SessionManager(const std::string& libraryPath, CK_SLOT_ID slot, std::string userPin)
    : slotId_(slot), userPin_(std::move(userPin)) {
    libraryHandle_ = dlopen(libraryPath.c_str(), RTLD_NOW);
    if (libraryHandle_ == nullptr) {
        throw std::runtime_error("Failed to load PKCS#11 library: " + libraryPath);
    }

    auto getFunctionList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(libraryHandle_, "C_GetFunctionList"));
    if (getFunctionList == nullptr) {
        dlclose(libraryHandle_);
        throw std::runtime_error("PKCS#11 library is missing C_GetFunctionList: " + libraryPath);
    }

    CK_RV rv = getFunctionList(&functions_);
    if (rv != CKR_OK || functions_ == nullptr) {
        dlclose(libraryHandle_);
        throw std::runtime_error("C_GetFunctionList failed, rv=" + std::to_string(rv));
    }

    rv = functions_->C_Initialize(nullptr);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        dlclose(libraryHandle_);
        throw std::runtime_error("C_Initialize failed, rv=" + std::to_string(rv));
    }
}

SessionManager::SessionManager(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slot, std::string userPin)
    : functions_(functions), slotId_(slot), userPin_(std::move(userPin)) {
    if (functions_ == nullptr) {
        throw std::invalid_argument("SessionManager: functions must not be null");
    }
    CK_RV rv = functions_->C_Initialize(nullptr);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        throw std::runtime_error("C_Initialize failed, rv=" + std::to_string(rv));
    }
}

SessionManager::~SessionManager() {
    if (functions_ != nullptr) {
        for (const auto& [threadId, session] : threadSessions_) {
            functions_->C_CloseSession(session);
        }
    }
    if (libraryHandle_ != nullptr) {
        dlclose(libraryHandle_);
    }
}

CK_SESSION_HANDLE SessionManager::getOrOpenSession() {
    std::lock_guard<std::mutex> lock(sessionMutex_);

    auto threadId = std::this_thread::get_id();
    auto it = threadSessions_.find(threadId);
    if (it != threadSessions_.end()) {
        return it->second;
    }

    CK_SESSION_HANDLE session;
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_RV rv = functions_->C_OpenSession(slotId_, flags, nullptr, nullptr, &session);
    if (rv != CKR_OK) {
        throw std::runtime_error("C_OpenSession failed, rv=" + std::to_string(rv));
    }

    if (!userPin_.empty()) {
        rv = functions_->C_Login(session, CKU_USER,
                                  reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(userPin_.c_str())),
                                  static_cast<CK_ULONG>(userPin_.length()));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            functions_->C_CloseSession(session);
            throw std::runtime_error("C_Login failed, rv=" + std::to_string(rv));
        }
    }

    threadSessions_[threadId] = session;
    return session;
}

SessionManager::SessionGuard SessionManager::createSessionGuard() {
    return SessionGuard(this, getOrOpenSession());
}

}  // namespace pkcs11cpp
