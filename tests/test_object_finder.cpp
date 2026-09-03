#include "catch.hpp"
#include "pkcs11cpp/key_manager.h"
#include "pkcs11cpp/mock_module.h"
#include "pkcs11cpp/object_finder.h"
#include "pkcs11cpp/session_manager.h"

using namespace pkcs11cpp;

namespace {
CK_OBJECT_HANDLE makeAesKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions, const std::string& label) {
    KeyManager km;
    KeyManager::KeyGenerationParams params;
    params.algorithm = KeyManager::KeyAlgorithm::AES_128;
    params.label = label;
    params.canEncrypt = true;
    return km.generateSecretKey(session, functions, params);
}
}  // namespace

TEST_CASE("ObjectFinder finds objects by label", "[object_finder]") {
    mock::reset();
    SessionManager sm(mock::getFunctionList(), 0);
    auto guard = sm.createSessionGuard();

    makeAesKey(guard.handle(), guard.functions(), "alpha");
    makeAesKey(guard.handle(), guard.functions(), "beta");

    ObjectFinder finder;
    auto matches = finder.findObjects(guard.handle(), guard.functions(),
                                       ObjectFinder::SearchCriteria().withLabel("alpha"));
    REQUIRE(matches.size() == 1);
}

TEST_CASE("ObjectFinder returns nothing for a label that doesn't exist", "[object_finder]") {
    mock::reset();
    SessionManager sm(mock::getFunctionList(), 0);
    auto guard = sm.createSessionGuard();
    makeAesKey(guard.handle(), guard.functions(), "alpha");

    ObjectFinder finder;
    auto matches = finder.findObjects(guard.handle(), guard.functions(),
                                       ObjectFinder::SearchCriteria().withLabel("does-not-exist"));
    REQUIRE(matches.empty());
}

TEST_CASE("ObjectFinder caches results and clearCache forces a re-search", "[object_finder]") {
    mock::reset();
    SessionManager sm(mock::getFunctionList(), 0);
    auto guard = sm.createSessionGuard();
    makeAesKey(guard.handle(), guard.functions(), "cached-key");

    ObjectFinder finder(std::chrono::seconds(60));
    auto criteria = ObjectFinder::SearchCriteria().withLabel("cached-key");

    auto first = finder.findObjects(guard.handle(), guard.functions(), criteria);
    makeAesKey(guard.handle(), guard.functions(), "cached-key");  // a second match, added after caching
    auto second = finder.findObjects(guard.handle(), guard.functions(), criteria);
    REQUIRE(second.size() == first.size());  // still cached, doesn't see the new object yet

    finder.clearCache();
    auto third = finder.findObjects(guard.handle(), guard.functions(), criteria);
    REQUIRE(third.size() == first.size() + 1);
}
