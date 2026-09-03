cmake_minimum_required(VERSION 3.16)
project(pkcs11cpp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(PKCS11CPP_BUILD_TESTS "Build the Catch2 unit test suite" ON)
option(PKCS11CPP_BUILD_EXAMPLES "Build examples/demo.cpp" ON)

find_package(Threads REQUIRED)

add_library(pkcs11cpp STATIC
    src/sha256.cpp
    src/mock_module.cpp
    src/session_manager.cpp
    src/attribute_manager.cpp
    src/mechanism_manager.cpp
    src/object_finder.cpp
    src/key_manager.cpp
    src/key_derivation.cpp
    src/key_transport.cpp
    src/crypto_processor.cpp
    src/health_monitor.cpp
)
target_include_directories(pkcs11cpp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(pkcs11cpp PUBLIC Threads::Threads)
if(UNIX)
    target_link_libraries(pkcs11cpp PUBLIC ${CMAKE_DL_LIBS})
endif()
target_compile_options(pkcs11cpp PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
)

if(PKCS11CPP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(PKCS11CPP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
