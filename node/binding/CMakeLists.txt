cmake_minimum_required(VERSION 3.16)

# N-API addon target
# cmake-js provides CMAKE_JS_INC and CMAKE_JS_LIB

# Find node-api-headers
execute_process(
  COMMAND node -p "require('node-api-headers').include_dir"
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/node
  OUTPUT_VARIABLE NODE_API_HEADERS_DIR
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(NWEP_NAPI_SOURCES
  nwep_napi.c
  nwep_napi_constants.c
  nwep_napi_error.c
  nwep_napi_crypto.c
  nwep_napi_encoding.c
  nwep_napi_addr.c
  nwep_napi_msg.c
  nwep_napi_handshake.c
  nwep_napi_log.c
  nwep_napi_identity.c
  nwep_napi_server.c
  nwep_napi_client.c
  nwep_napi_conn.c
  nwep_napi_stream.c
  nwep_napi_merkle.c
  nwep_napi_anchor.c
  nwep_napi_trust.c
  nwep_napi_role.c
  nwep_napi_cache.c
)

add_library(nwep_napi SHARED ${NWEP_NAPI_SOURCES})

set_target_properties(nwep_napi PROPERTIES
  PREFIX ""
  SUFFIX ".node"
  C_STANDARD 11
)

target_include_directories(nwep_napi PRIVATE
  ${CMAKE_JS_INC}
  ${NODE_API_HEADERS_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
)

target_compile_definitions(nwep_napi PRIVATE
  NAPI_VERSION=8
  NWEP_STATICLIB
)

# Link against the nwep target from the parent CMakeLists.txt.
# The nwep target has PUBLIC links to ngtcp2, quictls, and blst,
# so all transitive dependencies are pulled in automatically.
# We avoid the packed static lib (dist/) because it may not be
# compiled with -fPIC, which is required for a shared .node addon.
target_link_libraries(nwep_napi PRIVATE
  ${CMAKE_JS_LIB}
  nwep
)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(nwep_napi PRIVATE pthread dl)
endif()
