#pragma once

#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "pkcs11cpp/types.h"

namespace pkcs11cpp {

// Owns a PKCS#11 module handle (or an already-obtained function list) and
// hands out per-thread sessions, logging in once per thread and reusing
// the session for subsequent calls from that thread.
//
// A session is not thread-safe to share concurrently in the PKCS#11
// model, so rather than one shared session this class keeps a
// std::thread::id -> CK_SESSION_HANDLE map and lazily opens one session
// per calling thread the first time it asks for one.
class SessionManager {
public:
    // Loads a real PKCS#11 module from disk (a vendor's .so/.dll) via
    // dlopen/C_GetFunctionList. Linux/macOS only as written; on Windows,
    // swap dlopen/dlsym for LoadLibrary/GetProcAddress.
    SessionManager(const std::string& libraryPath, CK_SLOT_ID slot, std::string userPin = "");

    // Attaches to an already-obtained function list -- the constructor
    // used with pkcs11cpp::mock::getFunctionList() in tests and the demo,
    // or with any function list obtained by the caller's own means.
    SessionManager(CK_FUNCTION_LIST_PTR functions, CK_SLOT_ID slot, std::string userPin = "");

    ~SessionManager();

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    // RAII handle to a session: releases nothing on destruction (the
    // owning SessionManager keeps sessions open for reuse by the same
    // thread) but gives callers a scoped, self-documenting way to grab a
    // session + function-list pair for one PKCS#11 call sequence.
    class SessionGuard {
    public:
        CK_SESSION_HANDLE handle() const { return session_; }
        CK_FUNCTION_LIST_PTR functions() const { return manager_->functions_; }

    private:
        friend class SessionManager;
        SessionGuard(SessionManager* manager, CK_SESSION_HANDLE session)
            : manager_(manager), session_(session) {}

        SessionManager* manager_;
        CK_SESSION_HANDLE session_;
    };

    SessionGuard createSessionGuard();
    CK_FUNCTION_LIST_PTR functions() const { return functions_; }

private:
    CK_SESSION_HANDLE getOrOpenSession();

    void* libraryHandle_ = nullptr;  // non-null only when we dlopen'd it ourselves
    CK_FUNCTION_LIST_PTR functions_ = nullptr;
    CK_SLOT_ID slotId_;
    std::string userPin_;

    mutable std::mutex sessionMutex_;
    std::unordered_map<std::thread::id, CK_SESSION_HANDLE> threadSessions_;
};

}  // namespace pkcs11cpp
