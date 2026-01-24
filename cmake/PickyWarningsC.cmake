# PickyWarningsC.cmake
#
# Comprehensive warning flags for C code following ngtcp2 patterns.
# This module adds strict warning flags to catch potential issues early.
#
# Usage:
#   include(PickyWarningsC)
#
# Options:
#   NWEP_ENABLE_PICKY_WARNINGS - Enable extra picky warnings (default: OFF)

option(NWEP_ENABLE_PICKY_WARNINGS "Enable extra picky warnings" OFF)

if(NOT NWEP_ENABLE_PICKY_WARNINGS)
  return()
endif()

include(CheckCCompilerFlag)

# Helper function to add a warning flag if supported
function(add_warning_flag_if_supported flag)
  string(REGEX REPLACE "[^a-zA-Z0-9]" "_" flag_var "HAVE_C_FLAG${flag}")
  check_c_compiler_flag("${flag}" ${flag_var})
  if(${flag_var})
    add_compile_options("${flag}")
  endif()
endfunction()

if(CMAKE_C_COMPILER_ID MATCHES "GNU")
  # GCC-specific warnings
  add_warning_flag_if_supported(-Wall)
  add_warning_flag_if_supported(-Wextra)
  add_warning_flag_if_supported(-Wpedantic)
  add_warning_flag_if_supported(-Wformat=2)
  add_warning_flag_if_supported(-Wformat-overflow=2)
  add_warning_flag_if_supported(-Wformat-truncation=2)
  add_warning_flag_if_supported(-Wformat-security)
  add_warning_flag_if_supported(-Wnull-dereference)
  add_warning_flag_if_supported(-Wstack-protector)
  add_warning_flag_if_supported(-Wtrampolines)
  add_warning_flag_if_supported(-Walloca)
  add_warning_flag_if_supported(-Wvla)
  add_warning_flag_if_supported(-Warray-bounds=2)
  add_warning_flag_if_supported(-Wimplicit-fallthrough=3)
  add_warning_flag_if_supported(-Wshift-overflow=2)
  add_warning_flag_if_supported(-Wcast-qual)
  add_warning_flag_if_supported(-Wstringop-overflow=4)
  add_warning_flag_if_supported(-Wconversion)
  add_warning_flag_if_supported(-Warith-conversion)
  add_warning_flag_if_supported(-Wlogical-op)
  add_warning_flag_if_supported(-Wduplicated-cond)
  add_warning_flag_if_supported(-Wduplicated-branches)
  add_warning_flag_if_supported(-Wformat-signedness)
  add_warning_flag_if_supported(-Wshadow)
  add_warning_flag_if_supported(-Wstrict-overflow=4)
  add_warning_flag_if_supported(-Wundef)
  add_warning_flag_if_supported(-Wstrict-prototypes)
  add_warning_flag_if_supported(-Wswitch-default)
  add_warning_flag_if_supported(-Wswitch-enum)
  add_warning_flag_if_supported(-Wstack-usage=1000000)
  add_warning_flag_if_supported(-Wcast-align=strict)
  add_warning_flag_if_supported(-Wjump-misses-init)

elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
  # Clang-specific warnings
  add_warning_flag_if_supported(-Wall)
  add_warning_flag_if_supported(-Wextra)
  add_warning_flag_if_supported(-Wpedantic)
  add_warning_flag_if_supported(-Wformat=2)
  add_warning_flag_if_supported(-Wformat-security)
  add_warning_flag_if_supported(-Wnull-dereference)
  add_warning_flag_if_supported(-Wvla)
  add_warning_flag_if_supported(-Wcast-qual)
  add_warning_flag_if_supported(-Wconversion)
  add_warning_flag_if_supported(-Wshadow)
  add_warning_flag_if_supported(-Wstrict-overflow=4)
  add_warning_flag_if_supported(-Wundef)
  add_warning_flag_if_supported(-Wstrict-prototypes)
  add_warning_flag_if_supported(-Wswitch-default)
  add_warning_flag_if_supported(-Wswitch-enum)
  add_warning_flag_if_supported(-Wcast-align)
  add_warning_flag_if_supported(-Wimplicit-fallthrough)
  add_warning_flag_if_supported(-Wdouble-promotion)
  add_warning_flag_if_supported(-Wconditional-uninitialized)
  add_warning_flag_if_supported(-Wassign-enum)
  add_warning_flag_if_supported(-Wcomma)
  add_warning_flag_if_supported(-Wshorten-64-to-32)

elseif(MSVC)
  # MSVC-specific warnings (in addition to /W4 already set)
  # These are additional warnings not covered by /W4
  add_compile_options(
    /w14242  # conversion from 'type1' to 'type2', possible loss of data
    /w14254  # larger bit field truncated to smaller bit field
    /w14263  # member function does not override any base class virtual member function
    /w14265  # class has virtual functions, but destructor is not virtual
    /w14287  # unsigned/negative constant mismatch
    /we4289  # nonstandard extension used: 'variable' declared in for-loop is used outside the for-loop
    /w14296  # expression is always true/false
    /w14311  # pointer truncation from 'type' to 'type'
    /w14545  # expression before comma evaluates to a function which is missing an argument list
    /w14546  # function call before comma missing argument list
    /w14547  # operator before comma has no effect
    /w14549  # operator before comma has no effect
    /w14555  # expression has no effect
    /w14619  # pragma warning: invalid warning number
    /w14640  # thread unsafe static member initialization
    /w14826  # conversion from 'type1' to 'type2' is sign-extended
    /w14905  # wide string literal cast to 'LPSTR'
    /w14906  # string literal cast to 'LPWSTR'
    /w14928  # illegal copy-initialization
  )
endif()

message(STATUS "Picky C warnings enabled")
