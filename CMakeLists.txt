cmake_minimum_required(VERSION 3.16)

# Read version from a version file or set defaults
set(NWEP_VERSION_MAJOR 0)
set(NWEP_VERSION_MINOR 1)
set(NWEP_VERSION_PATCH 0)
set(NWEP_VERSION "${NWEP_VERSION_MAJOR}.${NWEP_VERSION_MINOR}.${NWEP_VERSION_PATCH}")

project(nwep VERSION ${NWEP_VERSION} LANGUAGES C)

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(NWEP_BUILD_TESTS "Build tests" ON)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Generate compile_commands.json for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
  if(NOT BUILD_SHARED_LIBS)
    add_compile_options(-fvisibility=hidden)
  endif()
endif()

# Generate version.h from template
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/nwep/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/nwep/version.h"
  @ONLY
)

# Third-party paths
set(QUICTLS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/quictls-install")
set(NGTCP2_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/ngtcp2")
set(NGTCP2_BUILD "${CMAKE_CURRENT_SOURCE_DIR}/third_party/ngtcp2-build")
set(BLST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/blst")

# Find OpenSSL (quictls)
set(OPENSSL_ROOT_DIR "${QUICTLS_ROOT}")
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

# ngtcp2 library paths
set(NGTCP2_INCLUDE_DIR "${NGTCP2_ROOT}/lib/includes")
set(NGTCP2_CRYPTO_INCLUDE_DIR "${NGTCP2_ROOT}/crypto/includes")
set(NGTCP2_LIBRARY "${NGTCP2_BUILD}/lib/libngtcp2.a")
set(NGTCP2_CRYPTO_LIBRARY "${NGTCP2_BUILD}/crypto/quictls/libngtcp2_crypto_quictls.a")

# Check that ngtcp2 is built
if(NOT EXISTS "${NGTCP2_LIBRARY}")
  message(FATAL_ERROR "ngtcp2 library not found at ${NGTCP2_LIBRARY}. Run build.sh first.")
endif()
if(NOT EXISTS "${NGTCP2_CRYPTO_LIBRARY}")
  message(FATAL_ERROR "ngtcp2_crypto_quictls library not found at ${NGTCP2_CRYPTO_LIBRARY}. Run build.sh first.")
endif()

# Create imported targets for ngtcp2
add_library(ngtcp2::ngtcp2 STATIC IMPORTED)
set_target_properties(ngtcp2::ngtcp2 PROPERTIES
  IMPORTED_LOCATION "${NGTCP2_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${NGTCP2_INCLUDE_DIR}"
)

add_library(ngtcp2::ngtcp2_crypto_quictls STATIC IMPORTED)
set_target_properties(ngtcp2::ngtcp2_crypto_quictls PROPERTIES
  IMPORTED_LOCATION "${NGTCP2_CRYPTO_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${NGTCP2_CRYPTO_INCLUDE_DIR}"
)

# blst library paths
set(BLST_INCLUDE_DIR "${BLST_ROOT}/bindings")
set(BLST_LIBRARY "${BLST_ROOT}/libblst.a")

# Check that blst is built
if(NOT EXISTS "${BLST_LIBRARY}")
  message(FATAL_ERROR "blst library not found at ${BLST_LIBRARY}. Run third_party/blst/build.sh first.")
endif()

# Create imported target for blst
add_library(blst::blst STATIC IMPORTED)
set_target_properties(blst::blst PROPERTIES
  IMPORTED_LOCATION "${BLST_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${BLST_INCLUDE_DIR}"
)

# Source files
set(NWEP_SOURCES
  src/nwep_err.c
  src/nwep_version.c
  src/nwep_base58.c
  src/nwep_crypto.c
  src/nwep_addr.c
  src/nwep_msg.c
  src/nwep_base64.c
  src/nwep_handshake.c
  src/nwep_conn.c
  src/nwep_server.c
  src/nwep_client.c
  src/nwep_stream.c
  src/nwep_reqresp.c
  src/nwep_tls.c
  src/nwep_quic.c
  src/nwep_log.c
  src/nwep_key_lifecycle.c
  src/nwep_merkle.c
  src/nwep_anchor.c
  src/nwep_trust.c
  src/nwep_role.c
  src/nwep_cache.c
)

# Create the library
add_library(nwep ${NWEP_SOURCES})

# Define BUILDING_NWEP for visibility macros
target_compile_definitions(nwep PRIVATE BUILDING_NWEP)

# Static lib definition
if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(nwep PUBLIC NWEP_STATICLIB)
endif()

# Include directories
target_include_directories(nwep
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link dependencies
target_link_libraries(nwep
  PRIVATE
    ngtcp2::ngtcp2
    ngtcp2::ngtcp2_crypto_quictls
    OpenSSL::SSL
    OpenSSL::Crypto
    blst::blst
)

# Set library properties
set_target_properties(nwep PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  OUTPUT_NAME nwep
)

# Install rules
include(GNUInstallDirs)

install(TARGETS nwep
  EXPORT nwepTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES
  include/nwep/nwep.h
  ${CMAKE_CURRENT_BINARY_DIR}/include/nwep/version.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nwep
)

# Export targets
install(EXPORT nwepTargets
  FILE nwepTargets.cmake
  NAMESPACE nwep::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nwep
)

# Package config
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/nwepConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/nwepConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/nwepConfig.cmake"
  @ONLY
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/nwepConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/nwepConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nwep
)

# Tests
if(NWEP_BUILD_TESTS)
  # Find libuv using pkg-config
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBUV REQUIRED libuv)

  # Test harness library
  add_library(nwep_test_harness STATIC
    tests/test_harness.c
  )
  target_include_directories(nwep_test_harness
    PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/tests
      ${LIBUV_INCLUDE_DIRS}
  )
  target_link_libraries(nwep_test_harness
    PUBLIC
      nwep
      ${LIBUV_LIBRARIES}
  )
  target_link_directories(nwep_test_harness
    PUBLIC
      ${LIBUV_LIBRARY_DIRS}
  )

  # QUIC handshake test (requires network)
  add_executable(test_handshake tests/test_handshake.c)
  target_link_libraries(test_handshake
    PRIVATE
      nwep_test_harness
  )

  # WEB/1 CONNECT/AUTHENTICATE handshake unit test (no network)
  add_executable(test_web1_handshake tests/test_web1_handshake.c)
  target_link_libraries(test_web1_handshake
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
  )

  # Logging unit test (Phase 11)
  add_executable(test_logging tests/test_logging.c)
  target_link_libraries(test_logging
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
  )

  # NOTIFY message unit test (bidirectional streaming)
  add_executable(test_notify tests/test_notify.c)
  target_link_libraries(test_notify
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
  )

  # Key lifecycle unit test (Phase 12)
  add_executable(test_key_lifecycle tests/test_key_lifecycle.c)
  target_link_libraries(test_key_lifecycle
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
  )

  # Merkle log unit test (Phase 13)
  add_executable(test_merkle_log tests/test_merkle_log.c)
  target_link_libraries(test_merkle_log
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
  )

  # Anchor coordination unit test (Phase 14)
  add_executable(test_anchor tests/test_anchor.c)
  target_link_libraries(test_anchor
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
      blst::blst
  )

  # Client trust verification unit test (Phase 15)
  add_executable(test_trust tests/test_trust.c)
  target_link_libraries(test_trust
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
      blst::blst
  )

  # Server roles unit test (Phase 16)
  add_executable(test_role tests/test_role.c)
  target_link_libraries(test_role
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
      blst::blst
  )

  # Enable CTest
  enable_testing()
  add_test(NAME quic_handshake COMMAND test_handshake)
  add_test(NAME web1_handshake COMMAND test_web1_handshake)
  add_test(NAME logging COMMAND test_logging)
  add_test(NAME notify COMMAND test_notify)
  add_test(NAME key_lifecycle COMMAND test_key_lifecycle)
  add_test(NAME merkle_log COMMAND test_merkle_log)
  add_test(NAME anchor COMMAND test_anchor)
  add_test(NAME trust COMMAND test_trust)
  add_test(NAME role COMMAND test_role)
  add_test(NAME cache COMMAND test_cache)

  # Cache unit test (Phase 17)
  add_executable(test_cache tests/test_cache.c)
  target_link_libraries(test_cache
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
      blst::blst
  )

  # Integration tests (end-to-end with libuv)
  add_executable(test_integration tests/test_integration.c)
  target_include_directories(test_integration PRIVATE ${LIBUV_INCLUDE_DIRS})
  target_link_libraries(test_integration
    PRIVATE
      nwep
      ngtcp2::ngtcp2_crypto_quictls
      ngtcp2::ngtcp2
      OpenSSL::SSL
      OpenSSL::Crypto
      blst::blst
      ${LIBUV_LIBRARIES}
  )
  target_link_directories(test_integration PRIVATE ${LIBUV_LIBRARY_DIRS})
  add_test(NAME integration COMMAND test_integration)
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "nwep ${PROJECT_VERSION} configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "  Build tests: ${NWEP_BUILD_TESTS}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "  ngtcp2: ${NGTCP2_LIBRARY}")
message(STATUS "")
