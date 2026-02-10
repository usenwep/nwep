cmake_minimum_required(VERSION 3.16)

# Read version from VERSION file
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" NWEP_VERSION_STRING)
string(STRIP "${NWEP_VERSION_STRING}" NWEP_VERSION_STRING)
string(REPLACE "." ";" NWEP_VERSION_LIST "${NWEP_VERSION_STRING}")
list(GET NWEP_VERSION_LIST 0 NWEP_VERSION_MAJOR)
list(GET NWEP_VERSION_LIST 1 NWEP_VERSION_MINOR)
list(GET NWEP_VERSION_LIST 2 NWEP_VERSION_PATCH)
set(NWEP_VERSION "${NWEP_VERSION_STRING}")

project(nwep VERSION ${NWEP_VERSION} LANGUAGES C)

# CMake module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(NWEP_BUILD_TESTS "Build tests" ON)
option(NWEP_ENABLE_WERROR "Treat warnings as errors" OFF)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Generate compile_commands.json for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include feature detection modules
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckFunctionExists)

# Detect platform headers
check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
check_include_file(netinet/in.h HAVE_NETINET_IN_H)
check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(windows.h HAVE_WINDOWS_H)
check_include_file(winsock2.h HAVE_WINSOCK2_H)

# Detect time functions
check_symbol_exists(clock_gettime time.h HAVE_CLOCK_GETTIME)
check_symbol_exists(gettimeofday sys/time.h HAVE_GETTIMEOFDAY)
if(WIN32)
  check_symbol_exists(QueryPerformanceCounter windows.h HAVE_QUERY_PERFORMANCE_COUNTER)
endif()

# Detect memory functions
check_symbol_exists(explicit_bzero string.h HAVE_EXPLICIT_BZERO)
check_symbol_exists(explicit_memset string.h HAVE_EXPLICIT_MEMSET)
check_symbol_exists(memset_s string.h HAVE_MEMSET_S)
if(WIN32)
  check_symbol_exists(SecureZeroMemory windows.h HAVE_SECURE_ZERO_MEMORY)
endif()

# Generate config.h
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h"
  @ONLY
)

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
  if(NOT BUILD_SHARED_LIBS)
    add_compile_options(-fvisibility=hidden)
  endif()
  if(NWEP_ENABLE_WERROR)
    add_compile_options(-Werror)
  endif()
elseif(MSVC)
  # MSVC warning level 4
  add_compile_options(/W4)
  # Disable noisy warnings
  add_compile_options(
    /wd4100  # unreferenced formal parameter
    /wd4127  # conditional expression is constant
    /wd4244  # conversion from 'type1' to 'type2', possible loss of data
    /wd4267  # conversion from 'size_t' to 'type', possible loss of data
    /wd4706  # assignment within conditional expression
  )
  # Enable parallel compilation
  add_compile_options(/MP)
  # Use secure CRT functions
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
  if(NWEP_ENABLE_WERROR)
    add_compile_options(/WX)
  endif()
endif()

# Include picky warnings module if available
include(PickyWarningsC OPTIONAL)

# Generate version.h from template
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/nwep/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/nwep/version.h"
  @ONLY
)

# Third-party paths (can be overridden via -D options for cross-compilation)
if(NOT QUICTLS_ROOT)
  set(QUICTLS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.build/quictls-install")
endif()
if(NOT NGTCP2_ROOT)
  set(NGTCP2_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/ngtcp2")
endif()
if(NOT NGTCP2_BUILD)
  set(NGTCP2_BUILD "${CMAKE_CURRENT_SOURCE_DIR}/.build/ngtcp2-build")
endif()
if(NOT BLST_ROOT)
  set(BLST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/blst")
endif()

# Find OpenSSL (quictls)
# Prevent cmake from adding imported target includes as -isystem, which on
# macOS Intel can cause system LibreSSL headers to shadow our quictls headers.
set(CMAKE_NO_SYSTEM_FROM_IMPORTED ON)
set(OPENSSL_ROOT_DIR "${QUICTLS_ROOT}")
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

# ngtcp2 library paths
# Include both source and build directories (version.h is generated in build)
set(NGTCP2_INCLUDE_DIR "${NGTCP2_ROOT}/lib/includes;${NGTCP2_BUILD}/lib/includes")
set(NGTCP2_CRYPTO_INCLUDE_DIR "${NGTCP2_ROOT}/crypto/includes;${NGTCP2_BUILD}/crypto/includes")

# Find ngtcp2 library (support both Unix .a and Windows .lib)
if(WIN32)
  set(NGTCP2_LIBRARY_CANDIDATES
    "${NGTCP2_BUILD}/lib/Release/ngtcp2.lib"
    "${NGTCP2_BUILD}/lib/Release/ngtcp2_static.lib"
    "${NGTCP2_BUILD}/lib/ngtcp2.lib"
    "${NGTCP2_BUILD}/lib/ngtcp2_static.lib"
    "${NGTCP2_BUILD}/lib/libngtcp2.lib"
    "${NGTCP2_BUILD}/lib/libngtcp2.a"
  )
  set(NGTCP2_CRYPTO_LIBRARY_CANDIDATES
    "${NGTCP2_BUILD}/crypto/quictls/Release/ngtcp2_crypto_quictls.lib"
    "${NGTCP2_BUILD}/crypto/quictls/Release/ngtcp2_crypto_quictls_static.lib"
    "${NGTCP2_BUILD}/crypto/quictls/ngtcp2_crypto_quictls.lib"
    "${NGTCP2_BUILD}/crypto/quictls/ngtcp2_crypto_quictls_static.lib"
    "${NGTCP2_BUILD}/crypto/quictls/libngtcp2_crypto_quictls.lib"
    "${NGTCP2_BUILD}/crypto/quictls/libngtcp2_crypto_quictls.a"
  )
else()
  set(NGTCP2_LIBRARY_CANDIDATES "${NGTCP2_BUILD}/lib/libngtcp2.a")
  set(NGTCP2_CRYPTO_LIBRARY_CANDIDATES "${NGTCP2_BUILD}/crypto/quictls/libngtcp2_crypto_quictls.a")
endif()

# Find first existing library
set(NGTCP2_LIBRARY "")
foreach(lib ${NGTCP2_LIBRARY_CANDIDATES})
  if(EXISTS "${lib}")
    set(NGTCP2_LIBRARY "${lib}")
    break()
  endif()
endforeach()

set(NGTCP2_CRYPTO_LIBRARY "")
foreach(lib ${NGTCP2_CRYPTO_LIBRARY_CANDIDATES})
  if(EXISTS "${lib}")
    set(NGTCP2_CRYPTO_LIBRARY "${lib}")
    break()
  endif()
endforeach()

# Check that ngtcp2 is built
if(NOT NGTCP2_LIBRARY)
  message(FATAL_ERROR "ngtcp2 library not found. Run build.sh first.")
endif()
if(NOT NGTCP2_CRYPTO_LIBRARY)
  message(FATAL_ERROR "ngtcp2_crypto_quictls library not found. Run build.sh first.")
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

# Find blst library (support both Unix .a and Windows .lib)
if(WIN32)
  set(BLST_LIBRARY_CANDIDATES
    "${BLST_ROOT}/blst.lib"
    "${BLST_ROOT}/libblst.lib"
    "${BLST_ROOT}/libblst.a"
  )
else()
  set(BLST_LIBRARY_CANDIDATES "${BLST_ROOT}/libblst.a")
endif()

# Find first existing library
set(BLST_LIBRARY "")
foreach(lib ${BLST_LIBRARY_CANDIDATES})
  if(EXISTS "${lib}")
    set(BLST_LIBRARY "${lib}")
    break()
  endif()
endforeach()

# Check that blst is built
if(NOT BLST_LIBRARY)
  message(FATAL_ERROR "blst library not found. Run third_party/blst/build.sh first.")
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

# Define BUILDING_NWEP for visibility macros and HAVE_CONFIG_H
target_compile_definitions(nwep PRIVATE BUILDING_NWEP HAVE_CONFIG_H)

# Static lib definition
if(NOT BUILD_SHARED_LIBS)
  target_compile_definitions(nwep PUBLIC NWEP_STATICLIB)
endif()

# ngtcp2 static lib definition (required on Windows to avoid dllimport)
target_compile_definitions(nwep PRIVATE NGTCP2_STATICLIB)

# Include directories
target_include_directories(nwep
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}  # for config.h
)

# Link dependencies (PUBLIC so consumers of the static lib get transitive deps)
# Order matters: ngtcp2_crypto_quictls depends on ngtcp2, which depends on OpenSSL
target_link_libraries(nwep
  PUBLIC
    ngtcp2::ngtcp2_crypto_quictls
    ngtcp2::ngtcp2
    OpenSSL::SSL
    OpenSSL::Crypto
    blst::blst
)

# Windows socket libraries
if(WIN32)
  target_link_libraries(nwep
    PRIVATE
      ws2_32
      crypt32
      bcrypt
  )
endif()

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
  target_link_libraries(test_web1_handshake PRIVATE nwep)

  # Logging unit test (Phase 11)
  add_executable(test_logging tests/test_logging.c)
  target_link_libraries(test_logging PRIVATE nwep)

  # NOTIFY message unit test (bidirectional streaming)
  add_executable(test_notify tests/test_notify.c)
  target_link_libraries(test_notify PRIVATE nwep)

  # Key lifecycle unit test (Phase 12)
  add_executable(test_key_lifecycle tests/test_key_lifecycle.c)
  target_link_libraries(test_key_lifecycle PRIVATE nwep)

  # Merkle log unit test (Phase 13)
  add_executable(test_merkle_log tests/test_merkle_log.c)
  target_link_libraries(test_merkle_log PRIVATE nwep)

  # Anchor coordination unit test (Phase 14)
  add_executable(test_anchor tests/test_anchor.c)
  target_link_libraries(test_anchor PRIVATE nwep)

  # Client trust verification unit test (Phase 15)
  add_executable(test_trust tests/test_trust.c)
  target_link_libraries(test_trust PRIVATE nwep)

  # Server roles unit test (Phase 16)
  add_executable(test_role tests/test_role.c)
  target_link_libraries(test_role PRIVATE nwep)

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

  # Cache unit test (Phase 17)
  add_executable(test_cache tests/test_cache.c)
  target_link_libraries(test_cache PRIVATE nwep)
  add_test(NAME cache COMMAND test_cache)

  # Integration tests (end-to-end with libuv)
  add_executable(test_integration tests/test_integration.c)
  target_include_directories(test_integration PRIVATE ${LIBUV_INCLUDE_DIRS})
  target_link_libraries(test_integration PRIVATE nwep ${LIBUV_LIBRARIES})
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
