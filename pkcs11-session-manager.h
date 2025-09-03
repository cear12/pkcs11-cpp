class PKCS11SessionManager {
private:
    CK_FUNCTION_LIST_PTR pkcs11Functions;
    CK_SLOT_ID slotId;
    mutable std::mutex sessionMutex;
    std::unordered_map<std::thread::id, CK_SESSION_HANDLE> threadSessions;
    std::string userPin;
    
public:
    PKCS11SessionManager(const std::string& libraryPath, CK_SLOT_ID slot)
        : slotId(slot), userPin("") {
        
        // Загружаем PKCS#11 библиотеку
        void* library = dlopen(libraryPath.c_str(), RTLD_NOW);
        if (!library) {
            throw std::runtime_error("Failed to load PKCS#11 library");
        }
        
        CK_C_GetFunctionList getFunctionList = 
            (CK_C_GetFunctionList)dlsym(library, "C_GetFunctionList");
        
        CK_RV rv = getFunctionList(&pkcs11Functions);
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to get function list");
        }
        
        // Инициализируем PKCS#11
        rv = pkcs11Functions->C_Initialize(nullptr);
        if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
            throw std::runtime_error("Failed to initialize PKCS#11");
        }
    }
    
    class SessionGuard {
    private:
        PKCS11SessionManager* manager;
        CK_SESSION_HANDLE session;
        
    public:
        SessionGuard(PKCS11SessionManager* mgr) : manager(mgr) {
            session = manager->getSession();
        }
        
        ~SessionGuard() {
            manager->releaseSession(session);
        }
        
        CK_SESSION_HANDLE getHandle() const { return session; }
        CK_FUNCTION_LIST_PTR getFunctions() const { 
            return manager->pkcs11Functions; 
        }
    };
    
    SessionGuard createSessionGuard() {
        return SessionGuard(this);
    }
    
private:
    CK_SESSION_HANDLE getSession() {
        std::lock_guard<std::mutex> lock(sessionMutex);
        
        auto threadId = std::this_thread::get_id();
        auto it = threadSessions.find(threadId);
        
        if (it != threadSessions.end()) {
            return it->second;
        }
        
        // Создаем новую сессию для потока
        CK_SESSION_HANDLE session;
        CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        
        CK_RV rv = pkcs11Functions->C_OpenSession(
            slotId, flags, nullptr, nullptr, &session);
        
        if (rv != CKR_OK) {
            throw std::runtime_error("Failed to open session");
        }
        
        // Логинимся если установлен PIN
        if (!userPin.empty()) {
            rv = pkcs11Functions->C_Login(
                session, CKU_USER, 
                (CK_UTF8CHAR_PTR)userPin.c_str(), userPin.length());
            
            if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
                pkcs11Functions->C_CloseSession(session);
                throw std::runtime_error("Failed to login");
            }
        }
        
        threadSessions[threadId] = session;
        return session;
    }
    
    void releaseSession(CK_SESSION_HANDLE session) {
        // Сессия остается открытой для переиспользования
        // Закроется в деструкторе
    }
};
