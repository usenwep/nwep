# FindBlst.cmake
#
# Find the blst library (BLS12-381 signature library)
#
# This module defines:
#   BLST_FOUND        - True if blst was found
#   BLST_INCLUDE_DIRS - Include directories for blst
#   BLST_LIBRARIES    - Libraries to link against
#   blst::blst        - Imported target
#
# Hints:
#   BLST_ROOT         - Root directory of blst installation
#   BLST_INCLUDE_DIR  - Include directory hint
#   BLST_LIBRARY      - Library file hint
#
# Example usage:
#   find_package(Blst REQUIRED)
#   target_link_libraries(myapp PRIVATE blst::blst)

# Try to find include directory
find_path(BLST_INCLUDE_DIR
  NAMES blst.h
  PATHS
    ${BLST_ROOT}
    ${BLST_ROOT}/bindings
    ENV BLST_ROOT
    /usr/local/include
    /usr/include
  PATH_SUFFIXES
    include
    bindings
)

# Library names vary by platform
if(WIN32)
  set(_blst_lib_names blst libblst blst.lib libblst.lib)
else()
  set(_blst_lib_names blst libblst.a)
endif()

# Try to find library
find_library(BLST_LIBRARY
  NAMES ${_blst_lib_names}
  PATHS
    ${BLST_ROOT}
    ENV BLST_ROOT
    /usr/local/lib
    /usr/lib
  PATH_SUFFIXES
    lib
    lib64
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Blst
  REQUIRED_VARS BLST_LIBRARY BLST_INCLUDE_DIR
)

if(BLST_FOUND)
  set(BLST_INCLUDE_DIRS ${BLST_INCLUDE_DIR})
  set(BLST_LIBRARIES ${BLST_LIBRARY})

  if(NOT TARGET blst::blst)
    add_library(blst::blst STATIC IMPORTED)
    set_target_properties(blst::blst PROPERTIES
      IMPORTED_LOCATION "${BLST_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${BLST_INCLUDE_DIR}"
    )

    # On Windows, blst may need additional libraries
    if(WIN32)
      set_target_properties(blst::blst PROPERTIES
        INTERFACE_LINK_LIBRARIES "bcrypt"
      )
    endif()
  endif()
endif()

mark_as_advanced(BLST_INCLUDE_DIR BLST_LIBRARY)
