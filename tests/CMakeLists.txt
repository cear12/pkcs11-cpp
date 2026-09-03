add_library(catch2_main STATIC test_main.cpp)
target_include_directories(catch2_main PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/catch2)

add_executable(pkcs11cpp_tests
    test_attribute_manager.cpp
    test_mechanism_manager.cpp
    test_object_finder.cpp
    test_key_manager.cpp
    test_key_derivation.cpp
    test_key_transport.cpp
    test_crypto_processor.cpp
    test_health_monitor.cpp
    test_sha256.cpp
)
target_link_libraries(pkcs11cpp_tests PRIVATE pkcs11cpp catch2_main)
target_include_directories(pkcs11cpp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/catch2)

include(CTest)
add_test(NAME pkcs11cpp_tests COMMAND pkcs11cpp_tests)
