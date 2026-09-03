#include "catch.hpp"
#include "pkcs11cpp/key_manager.h"
#include "pkcs11cpp/mock_module.h"
#include "pkcs11cpp/object_finder.h"
#include "pkcs11cpp/session_manager.h"

using namespace pkcs11cpp;

namespace {
CK_OBJECT_HANDLE MakeAesKey(CK_SESSION_HANDLE session, CK_FUNCTION_LIST_PTR functions, const std::string& label) {
    KeyManager km;
    KeyManager::KeyGenerationParams params;
    params.algorithm_ = KeyManager::KeyAlgorithm::kAes128;
    params.label_ = label;
    params.can_encrypt_ = true;
    return km.GenerateSecretKey(session, functions, params);
}
}  // namespace

TEST_CASE("ObjectFinder finds objects by label", "[object_finder]") {
    mock::Reset();
    SessionManager sm(mock::GetFunctionList(), 0);
    auto guard = sm.CreateSessionGuard();

    MakeAesKey(guard.Handle(), guard.Functions(), "alpha");
    MakeAesKey(guard.Handle(), guard.Functions(), "beta");

    ObjectFinder finder;
    auto matches = finder.FindObjects(guard.Handle(), guard.Functions(),
                                       ObjectFinder::SearchCriteria().WithLabel("alpha"));
    REQUIRE(matches.size() == 1);
}

TEST_CASE("ObjectFinder returns nothing for a label that doesn't exist", "[object_finder]") {
    mock::Reset();
    SessionManager sm(mock::GetFunctionList(), 0);
    auto guard = sm.CreateSessionGuard();
    MakeAesKey(guard.Handle(), guard.Functions(), "alpha");

    ObjectFinder finder;
    auto matches = finder.FindObjects(guard.Handle(), guard.Functions(),
                                       ObjectFinder::SearchCriteria().WithLabel("does-not-exist"));
    REQUIRE(matches.empty());
}

TEST_CASE("ObjectFinder caches results and ClearCache forces a re-search", "[object_finder]") {
    mock::Reset();
    SessionManager sm(mock::GetFunctionList(), 0);
    auto guard = sm.CreateSessionGuard();
    MakeAesKey(guard.Handle(), guard.Functions(), "cached-key");

    ObjectFinder finder(std::chrono::seconds(60));
    auto criteria = ObjectFinder::SearchCriteria().WithLabel("cached-key");

    auto first = finder.FindObjects(guard.Handle(), guard.Functions(), criteria);
    MakeAesKey(guard.Handle(), guard.Functions(), "cached-key");  // a second match, added after caching
    auto second = finder.FindObjects(guard.Handle(), guard.Functions(), criteria);
    REQUIRE(second.size() == first.size());  // still cached, doesn't see the new object yet

    finder.ClearCache();
    auto third = finder.FindObjects(guard.Handle(), guard.Functions(), criteria);
    REQUIRE(third.size() == first.size() + 1);
}
