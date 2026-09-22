#include "pkcs11cpp/session_manager.h"

#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace pkcs11cpp {

namespace {

// Thin portability layer over the platform's dynamic loader: dlopen/dlsym
// on Linux and macOS, LoadLibrary/GetProcAddress on Windows. Everything
// else in this file is platform-neutral.
void* OpenLibrary(const std::string& path) {
#ifdef _WIN32
  return reinterpret_cast<void*>(::LoadLibraryA(path.c_str()));
#else
  return ::dlopen(path.c_str(), RTLD_NOW);
#endif
}

void* FindSymbol(void* library, const char* name) {
#ifdef _WIN32
  return reinterpret_cast<void*>(
      ::GetProcAddress(static_cast<HMODULE>(library), name));
#else
  return ::dlsym(library, name);
#endif
}

void CloseLibrary(void* library) {
#ifdef _WIN32
  ::FreeLibrary(static_cast<HMODULE>(library));
#else
  ::dlclose(library);
#endif
}

}  // namespace

SessionManager::SessionManager(const std::string& library_path, CK_SLOT_ID slot,
                               std::string user_pin)
    : slot_id_(slot), user_pin_(std::move(user_pin)) {
  library_handle_ = OpenLibrary(library_path);
  if (library_handle_ == nullptr) {
    throw std::runtime_error("Failed to load PKCS#11 library: " + library_path);
  }

  auto get_function_list = reinterpret_cast<CK_C_GetFunctionList>(
      FindSymbol(library_handle_, "C_GetFunctionList"));
  if (get_function_list == nullptr) {
    CloseLibrary(library_handle_);
    throw std::runtime_error("PKCS#11 library is missing C_GetFunctionList: " +
                             library_path);
  }

  CK_RV rv = get_function_list(&functions_);
  if (rv != CKR_OK || functions_ == nullptr) {
    CloseLibrary(library_handle_);
    throw std::runtime_error("C_GetFunctionList failed, rv=" +
                             std::to_string(rv));
  }

  rv = functions_->C_Initialize(nullptr);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    CloseLibrary(library_handle_);
    throw std::runtime_error("C_Initialize failed, rv=" + std::to_string(rv));
  }
}

SessionManager::SessionManager(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slot,
                               std::string user_pin)
    : functions_(functions), slot_id_(slot), user_pin_(std::move(user_pin)) {
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
    for (const auto& [threadId, session] : thread_sessions_) {
      functions_->C_CloseSession(session);
    }
  }
  if (library_handle_ != nullptr) {
    CloseLibrary(library_handle_);
  }
}

CK_SESSION_HANDLE SessionManager::GetOrOpenSession() {
  std::lock_guard<std::mutex> lock(session_mutex_);

  auto thread_id = std::this_thread::get_id();
  auto it = thread_sessions_.find(thread_id);
  if (it != thread_sessions_.end()) {
    return it->second;
  }

  CK_SESSION_HANDLE session;
  CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  CK_RV rv =
      functions_->C_OpenSession(slot_id_, flags, nullptr, nullptr, &session);
  if (rv != CKR_OK) {
    throw std::runtime_error("C_OpenSession failed, rv=" + std::to_string(rv));
  }

  if (!user_pin_.empty()) {
    rv = functions_->C_Login(
        session, CKU_USER,
        reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(user_pin_.c_str())),
        static_cast<CK_ULONG>(user_pin_.length()));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
      functions_->C_CloseSession(session);
      throw std::runtime_error("C_Login failed, rv=" + std::to_string(rv));
    }
  }

  thread_sessions_[thread_id] = session;
  return session;
}

SessionManager::SessionGuard SessionManager::CreateSessionGuard() {
  return SessionGuard(this, GetOrOpenSession());
}

}  // namespace pkcs11cpp
