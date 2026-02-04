# ==============================================================================
# CMakeLists.txt for Cryptographic Experiment
# Author: Juraj Sýkora <juraj.sykora@studio.unibo.it>
# ==============================================================================

cmake_minimum_required(VERSION 3.10)
project(CryptographicAlgorithms C CXX)
set(PROJECT_VERSION 1.0.0)

# ==============================================================================
# Project Options
# ==============================================================================

option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_BENCHMARKS "Build benchmarks" ON)
option(BUILD_EXAMPLES "Build examples" ON)
option(ENABLE_WARNINGS "Enable compiler warnings" ON)

# ==============================================================================
# C/C++ Standards
# ==============================================================================

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ==============================================================================
# Build Type
# ==============================================================================

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING 
        "Choose the type of build (Debug or Release)" FORCE)
endif()

# ==============================================================================
# Compiler Flags
# ==============================================================================

if(ENABLE_WARNINGS)
    if(MSVC)
        add_compile_options(/W4)
    else()
        add_compile_options(-Wall -Wextra)
    endif()
endif()

# Optimization flags
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(NOT MSVC)
        add_compile_options(-O3)
    endif()
    add_definitions(-DNDEBUG)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(NOT MSVC)
        add_compile_options(-g -O0)
    endif()
    add_definitions(-DDEBUG)
endif()

# ==============================================================================
# Directories
# ==============================================================================

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(TEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests")
set(BENCH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/benchmarks")
set(EXAMPLE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/examples")
set(RESULTS_DIR "${CMAKE_CURRENT_BINARY_DIR}/results")

# Create results directory
file(MAKE_DIRECTORY ${RESULTS_DIR})

# ==============================================================================
# Include Directories
# ==============================================================================

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# ==============================================================================
# Source Files
# ==============================================================================

# Utilities
set(UTILS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/utils.c
)

set(UTILS_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/utils.h
)

# AES Sources
set(AES_SOURCES
    ${SRC_DIR}/symmetric/aes.c
)

set(AES_HEADERS
    ${SRC_DIR}/symmetric/aes.h
)

# RSA Sources
set(RSA_SOURCES
    ${SRC_DIR}/asymmetric/rsa.c
)

set(RSA_HEADERS
    ${SRC_DIR}/asymmetric/rsa.h
)

# PHF (Perfect Hash Function) Sources
set(PHF_SOURCES
    ${SRC_DIR}/hash/phf_api.c
    ${SRC_DIR}/hash/phf_bdz.c
    ${SRC_DIR}/hash/phf_chd.c
    ${SRC_DIR}/hash/phf_elias_fano.c
    ${SRC_DIR}/hash/phf_hash.c
    ${SRC_DIR}/hash/phf_rank_select.c
)

set(PHF_HEADERS
    ${SRC_DIR}/hash/phf.h
)

# ==============================================================================
# AES Library
# ==============================================================================

add_library(aes STATIC
    ${AES_SOURCES}
    ${AES_HEADERS}
)

target_include_directories(aes PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ==============================================================================
# RSA Library
# ==============================================================================

add_library(rsa STATIC
    ${RSA_SOURCES}
    ${RSA_HEADERS}
)

target_include_directories(rsa PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ==============================================================================
# PHF Library
# ==============================================================================

add_library(phf STATIC
    ${PHF_SOURCES}
    ${PHF_HEADERS}
)

target_include_directories(phf PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link math library for PHF (needed for sqrt, etc.)
target_link_libraries(phf m)

# ==============================================================================
# Utils Library
# ==============================================================================

add_library(utils STATIC
    ${UTILS_SOURCES}
    ${UTILS_HEADERS}
)

target_include_directories(utils PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ==============================================================================
# Examples
# ==============================================================================

if(BUILD_EXAMPLES)
    add_executable(example_aes
        ${EXAMPLE_DIR}/example_aes.c
    )
    
    target_link_libraries(example_aes
        aes
        utils
    )
    
    # PHF example (if exists)
    if(EXISTS ${EXAMPLE_DIR}/example_phf.c)
        add_executable(example_phf
            ${EXAMPLE_DIR}/example_phf.c
        )
        
        target_link_libraries(example_phf
            phf
            utils
        )
    endif()
    
    message(STATUS "Examples will be built")
endif()

# ==============================================================================
# Tests
# ==============================================================================

if(BUILD_TESTS)
    # Find Google Test
    find_package(GTest QUIET)
    
    if(GTest_FOUND)
        enable_testing()
        
        add_executable(test_aes
            ${TEST_DIR}/test_aes.cpp
        )
        
        target_link_libraries(test_aes
            aes
            GTest::gtest
            GTest::gtest_main
            pthread
        )
        
        add_test(NAME AESTests COMMAND test_aes)
        
        # Add RSA test executable
        add_executable(test_rsa
            ${TEST_DIR}/test_rsa.cpp
        )
        
        target_link_libraries(test_rsa
            rsa
            utils
            GTest::gtest
            GTest::gtest_main
            pthread
        )
        
        add_test(NAME RSATests COMMAND test_rsa)
        
        # Add PHF test executable
        add_executable(test_phf
            ${TEST_DIR}/test_phf.cpp
        )
        
        target_link_libraries(test_phf
            phf
            GTest::gtest
            GTest::gtest_main
            pthread
        )
        
        add_test(NAME PHFTests COMMAND test_phf)
        
        message(STATUS "Tests will be built with Google Test")
    else()
        message(WARNING "Google Test not found. Tests will not be built.")
        message(WARNING "Install with: sudo apt-get install libgtest-dev (Ubuntu/Debian)")
        set(BUILD_TESTS OFF)
    endif()
endif()

# ==============================================================================
# Benchmarks
# ==============================================================================

if(BUILD_BENCHMARKS)
    add_executable(bench_aes
        ${BENCH_DIR}/bench_aes.c
    )
    
    target_link_libraries(bench_aes
        utils
        aes
    )
    
    # PHF benchmark (if exists)
    if(EXISTS ${BENCH_DIR}/bench_phf.c)
        add_executable(bench_phf
            ${BENCH_DIR}/bench_phf.c
        )
        
        target_link_libraries(bench_phf
            utils
            phf
        )
    endif()
    
    message(STATUS "Benchmarks will be built")
endif()

# ==============================================================================
# Custom Targets
# ==============================================================================

# Run examples
if(BUILD_EXAMPLES)
    add_custom_target(run-examples
        COMMAND example_aes
        DEPENDS example_aes
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running AES examples..."
    )
endif()

# Run tests
if(BUILD_TESTS AND GTest_FOUND)
    add_custom_target(run-tests
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        DEPENDS test_aes test_rsa test_phf
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running unit tests..."
    )
    
    # Add individual test targets
    add_custom_target(run-test-aes
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R AESTests
        DEPENDS test_aes
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running AES tests..."
    )
    
    add_custom_target(run-test-rsa
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R RSATests
        DEPENDS test_rsa
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running RSA tests..."
    )
    
    add_custom_target(run-test-phf
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -R PHFTests
        DEPENDS test_phf
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running PHF tests..."
    )
endif()

# Run benchmarks
if(BUILD_BENCHMARKS)
    add_custom_target(run-benchmarks
        COMMAND bench_aes
        DEPENDS bench_aes
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running benchmarks..."
    )
endif()

# Run all
if(BUILD_EXAMPLES AND BUILD_TESTS AND BUILD_BENCHMARKS AND GTest_FOUND)
    add_custom_target(run-all
        COMMAND example_aes
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        COMMAND bench_aes
        DEPENDS example_aes test_aes test_rsa test_phf bench_aes
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running all examples, tests, and benchmarks..."
    )
endif()

# Plot results
add_custom_target(plot
    COMMAND ${CMAKE_COMMAND} -E echo "Generating benchmark visualizations..."
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/scripts/plot_results.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating plots from benchmark results..."
)

# Clean results
add_custom_target(clean-results
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${RESULTS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${RESULTS_DIR}
    COMMENT "Cleaning benchmark results..."
)

# ==============================================================================
# Installation
# ==============================================================================

include(GNUInstallDirs)

# Install binaries
if(BUILD_EXAMPLES)
    install(TARGETS example_aes
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        RENAME aes-example
    )
endif()

if(BUILD_TESTS AND GTest_FOUND)
    install(TARGETS test_aes test_rsa test_phf
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

if(BUILD_BENCHMARKS)
    install(TARGETS bench_aes
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        RENAME aes-bench
    )
endif()

# Install headers
install(FILES ${AES_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/crypto
)

install(FILES ${RSA_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/crypto
)

install(FILES ${PHF_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/crypto
)

# ==============================================================================
# Development Tools Integration
# ==============================================================================

# Static analysis with cppcheck
find_program(CPPCHECK cppcheck)
if(CPPCHECK)
    add_custom_target(check
        COMMAND ${CPPCHECK} --enable=all --suppress=missingIncludeSystem 
                ${SRC_DIR} 2>&1 | grep -v "^Checking" || true
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Running static analysis with cppcheck..."
    )
endif()

# Memory leak detection with valgrind
find_program(VALGRIND valgrind)
if(VALGRIND AND BUILD_TESTS AND GTest_FOUND)
    add_custom_target(valgrind
        COMMAND ${VALGRIND} --leak-check=full --show-leak-kinds=all 
                --track-origins=yes --verbose 
                --log-file=valgrind-out.txt 
                $<TARGET_FILE:test_aes>
        DEPENDS test_aes
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running memory leak detection with valgrind..."
    )
    
    add_custom_target(valgrind-rsa
        COMMAND ${VALGRIND} --leak-check=full --show-leak-kinds=all 
                --track-origins=yes --verbose 
                --log-file=valgrind-rsa-out.txt 
                $<TARGET_FILE:test_rsa>
        DEPENDS test_rsa
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running memory leak detection on RSA tests with valgrind..."
    )
    
    add_custom_target(valgrind-phf
        COMMAND ${VALGRIND} --leak-check=full --show-leak-kinds=all 
                --track-origins=yes --verbose 
                --log-file=valgrind-phf-out.txt 
                $<TARGET_FILE:test_phf>
        DEPENDS test_phf
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Running memory leak detection on PHF tests with valgrind..."
    )
endif()

# Code formatting with clang-format
find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
    file(GLOB_RECURSE ALL_SOURCE_FILES
        ${SRC_DIR}/*.c ${SRC_DIR}/*.h
        ${TEST_DIR}/*.cpp ${TEST_DIR}/*.h
        ${BENCH_DIR}/*.c ${BENCH_DIR}/*.h
        ${EXAMPLE_DIR}/*.c ${EXAMPLE_DIR}/*.h
    )
    
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i -style=file ${ALL_SOURCE_FILES}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Formatting source code with clang-format..."
    )
endif()

# Linting with clang-tidy
find_program(CLANG_TIDY clang-tidy)
if(CLANG_TIDY)
    add_custom_target(lint
        COMMAND ${CLANG_TIDY} ${AES_SOURCES} ${RSA_SOURCES} ${PHF_SOURCES} -- -I${CMAKE_CURRENT_SOURCE_DIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Running linter with clang-tidy..."
    )
endif()

# ==============================================================================
# Documentation with Doxygen
# ==============================================================================

find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating documentation with Doxygen..."
    )
endif()

# ==============================================================================
# Print Configuration Summary
# ==============================================================================

message(STATUS "")
message(STATUS "╔════════════════════════════════════════════════════════════╗")
message(STATUS "║          Cryptographic Algorithms - Configuration          ║")
message(STATUS "╚════════════════════════════════════════════════════════════╝")
message(STATUS "")
message(STATUS "Build type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler:        ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "C++ Compiler:      ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "")
message(STATUS "Build options:")
message(STATUS "  Examples:        ${BUILD_EXAMPLES}")
message(STATUS "  Tests:           ${BUILD_TESTS}")
message(STATUS "  Benchmarks:      ${BUILD_BENCHMARKS}")
message(STATUS "")
message(STATUS "Libraries:")
message(STATUS "  AES:             YES")
message(STATUS "  RSA:             YES")
message(STATUS "  PHF:             YES")
message(STATUS "")
message(STATUS "Tools found:")
if(GTest_FOUND)
    message(STATUS "  Google Test:     YES")
else()
    message(STATUS "  Google Test:     NO")
endif()
if(CPPCHECK)
    message(STATUS "  cppcheck:        YES")
else()
    message(STATUS "  cppcheck:        NO")
endif()
if(VALGRIND)
    message(STATUS "  valgrind:        YES")
else()
    message(STATUS "  valgrind:        NO")
endif()
if(CLANG_FORMAT)
    message(STATUS "  clang-format:    YES")
else()
    message(STATUS "  clang-format:    NO")
endif()
if(CLANG_TIDY)
    message(STATUS "  clang-tidy:      YES")
else()
    message(STATUS "  clang-tidy:      NO")
endif()
if(DOXYGEN_FOUND)
    message(STATUS "  Doxygen:         YES")
else()
    message(STATUS "  Doxygen:         NO")
endif()
message(STATUS "")
message(STATUS "Install prefix:    ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")

# ==============================================================================
# End of CMakeLists.txt
# ==============================================================================