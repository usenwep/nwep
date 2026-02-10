# Custom FindOpenSSL module for cross-compilation
#
# This module finds OpenSSL/quictls when cross-compiling, where the standard
# CMake FindOpenSSL module may fail due to running host tests.
#
# Expected input variables:
#   OPENSSL_ROOT_DIR - Path to OpenSSL installation
#
# Provides:
#   OPENSSL_FOUND
#   OPENSSL_INCLUDE_DIR
#   OPENSSL_LIBRARIES
#   OPENSSL_SSL_LIBRARY
#   OPENSSL_CRYPTO_LIBRARY
#   OPENSSL_VERSION
#   OpenSSL::SSL (imported target)
#   OpenSSL::Crypto (imported target)

if(NOT OPENSSL_ROOT_DIR)
  message(FATAL_ERROR "OPENSSL_ROOT_DIR must be set for cross-compilation")
endif()

set(OPENSSL_FOUND TRUE)
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include" CACHE PATH "OpenSSL include directory")

# Find libraries - check lib and lib64 for both Unix (.a) and MSVC (.lib)
if(EXISTS "${OPENSSL_ROOT_DIR}/lib/libssl.a")
  set(_ssl "${OPENSSL_ROOT_DIR}/lib/libssl.a")
  set(_crypto "${OPENSSL_ROOT_DIR}/lib/libcrypto.a")
elseif(EXISTS "${OPENSSL_ROOT_DIR}/lib64/libssl.a")
  set(_ssl "${OPENSSL_ROOT_DIR}/lib64/libssl.a")
  set(_crypto "${OPENSSL_ROOT_DIR}/lib64/libcrypto.a")
elseif(EXISTS "${OPENSSL_ROOT_DIR}/lib/libssl.lib")
  # MSVC with lib prefix
  set(_ssl "${OPENSSL_ROOT_DIR}/lib/libssl.lib")
  set(_crypto "${OPENSSL_ROOT_DIR}/lib/libcrypto.lib")
elseif(EXISTS "${OPENSSL_ROOT_DIR}/lib/ssl.lib")
  # MSVC without lib prefix
  set(_ssl "${OPENSSL_ROOT_DIR}/lib/ssl.lib")
  set(_crypto "${OPENSSL_ROOT_DIR}/lib/crypto.lib")
else()
  message(FATAL_ERROR "Could not find OpenSSL libraries in ${OPENSSL_ROOT_DIR}")
endif()

set(OPENSSL_SSL_LIBRARY "${_ssl}" CACHE FILEPATH "OpenSSL SSL library")
set(OPENSSL_CRYPTO_LIBRARY "${_crypto}" CACHE FILEPATH "OpenSSL Crypto library")
set(OPENSSL_LIBRARIES "${_ssl};${_crypto}")

# Extract version from header
if(EXISTS "${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h")
  file(STRINGS "${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h" _version_line
       REGEX "OPENSSL_VERSION_STR")
  if(_version_line)
    string(REGEX REPLACE ".*\"([0-9.]+).*" "\\1" OPENSSL_VERSION "${_version_line}")
  else()
    set(OPENSSL_VERSION "3.0.0")
  endif()
else()
  set(OPENSSL_VERSION "3.0.0")
endif()

# Create imported targets
if(NOT TARGET OpenSSL::Crypto)
  add_library(OpenSSL::Crypto STATIC IMPORTED)
  set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
  if(WIN32)
    set_property(TARGET OpenSSL::Crypto APPEND PROPERTY
      INTERFACE_LINK_LIBRARIES ws2_32 crypt32 bcrypt)
  endif()
endif()

if(NOT TARGET OpenSSL::SSL)
  add_library(OpenSSL::SSL STATIC IMPORTED)
  set_target_properties(OpenSSL::SSL PROPERTIES
    IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
    INTERFACE_LINK_LIBRARIES OpenSSL::Crypto)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenSSL
  REQUIRED_VARS OPENSSL_SSL_LIBRARY OPENSSL_CRYPTO_LIBRARY OPENSSL_INCLUDE_DIR
  VERSION_VAR OPENSSL_VERSION)
