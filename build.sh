#!/bin/bash
#
# nwep build script
#
# This script builds quictls, ngtcp2, and nwep in order.
#

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Number of parallel jobs
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

# Platform detection
# Supports HOST= env var for cross-compilation (e.g., HOST=x86_64-w64-mingw32)
DETECTED_OS=""
DETECTED_ARCH=""

detect_platform() {
  # Skip if already detected for the current HOST value
  if [ -n "$DETECTED_OS" ] && [ "${_DETECTED_HOST:-}" = "${HOST:-}" ]; then
    return
  fi

  local host="${HOST:-}"
  local os=""
  local arch=""

  if [ -n "$host" ]; then
    # Cross-compilation: parse HOST triplet
    case "$host" in
      *-mingw32|*-mingw64|*-w64-mingw32)
        os="mingw"
        ;;
      *-linux-*)
        os="linux"
        ;;
      *-darwin*)
        os="darwin"
        ;;
      *)
        log_error "Unknown host triplet: $host"
        exit 1
        ;;
    esac

    case "$host" in
      x86_64-*|amd64-*)
        arch="x86_64"
        ;;
      i686-*|i386-*)
        arch="x86"
        ;;
      aarch64-*|arm64-*)
        arch="aarch64"
        ;;
      arm-*|armv7-*)
        arch="arm"
        ;;
      mips-*|mipsel-*)
        arch="mips"
        ;;
      mips64-*|mips64el-*)
        arch="mips64"
        ;;
      powerpc64le-*|ppc64le-*)
        arch="ppc64le"
        ;;
      riscv64-*)
        arch="riscv64"
        ;;
      s390x-*)
        arch="s390x"
        ;;
      *)
        log_error "Unknown architecture in host triplet: $host"
        exit 1
        ;;
    esac
  else
    # Native build: detect from system
    case "$(uname -s)" in
      Linux)
        os="linux"
        ;;
      Darwin)
        os="darwin"
        ;;
      MINGW*|MSYS*|CYGWIN*)
        os="mingw"
        ;;
      *)
        log_error "Unknown OS: $(uname -s)"
        exit 1
        ;;
    esac

    case "$(uname -m)" in
      x86_64|amd64)
        arch="x86_64"
        ;;
      i686|i386)
        arch="x86"
        ;;
      aarch64|arm64)
        arch="aarch64"
        ;;
      armv7l|armv6l|arm)
        arch="arm"
        ;;
      mips|mipsel)
        arch="mips"
        ;;
      mips64|mips64el)
        arch="mips64"
        ;;
      ppc64le)
        arch="ppc64le"
        ;;
      riscv64)
        arch="riscv64"
        ;;
      s390x)
        arch="s390x"
        ;;
      *)
        log_error "Unknown architecture: $(uname -m)"
        exit 1
        ;;
    esac
  fi

  DETECTED_OS="$os"
  DETECTED_ARCH="$arch"
  _DETECTED_HOST="${HOST:-}"
}

# Map platform to OpenSSL Configure target
get_openssl_target() {
  local os="$1"
  local arch="$2"

  case "$os-$arch" in
    linux-x86_64)
      echo "linux-x86_64"
      ;;
    linux-x86)
      echo "linux-x86"
      ;;
    linux-aarch64)
      echo "linux-aarch64"
      ;;
    linux-arm)
      echo "linux-armv4"
      ;;
    linux-mips)
      echo "linux-mips32"
      ;;
    linux-mips64)
      echo "linux-mips64"
      ;;
    linux-ppc64le)
      echo "linux-ppc64le"
      ;;
    linux-riscv64)
      echo "linux64-riscv64"
      ;;
    linux-s390x)
      echo "linux64-s390x"
      ;;
    darwin-x86_64)
      echo "darwin64-x86_64-cc"
      ;;
    darwin-aarch64)
      echo "darwin64-arm64-cc"
      ;;
    mingw-x86_64)
      echo "mingw64"
      ;;
    mingw-x86)
      echo "mingw"
      ;;
    *)
      log_error "No OpenSSL target for $os-$arch"
      exit 1
      ;;
  esac
}

# Get cross-compiler prefix for MinGW
get_cross_prefix() {
  local host="${HOST:-}"

  if [ -z "$host" ]; then
    echo ""
    return
  fi

  case "$host" in
    x86_64-w64-mingw32)
      echo "x86_64-w64-mingw32-"
      ;;
    i686-w64-mingw32)
      echo "i686-w64-mingw32-"
      ;;
    aarch64-linux-gnu)
      echo "aarch64-linux-gnu-"
      ;;
    arm-linux-gnueabihf|arm-none-linux-gnueabihf)
      echo "${host}-"
      ;;
    *)
      echo "${host}-"
      ;;
  esac
}

# Get cmake toolchain file for the current HOST triplet
get_toolchain_file() {
  local host="${HOST:-}"
  if [ -z "$host" ]; then
    echo ""
    return
  fi

  local toolchain=""
  case "$host" in
    x86_64-w64-mingw32)
      toolchain="$SCRIPT_DIR/cmake/toolchain-mingw64.cmake"
      ;;
    i686-w64-mingw32)
      toolchain="$SCRIPT_DIR/cmake/toolchain-mingw32.cmake"
      ;;
    aarch64-linux-gnu)
      toolchain="$SCRIPT_DIR/cmake/toolchain-aarch64-linux.cmake"
      ;;
    arm-linux-gnueabihf)
      toolchain="$SCRIPT_DIR/cmake/toolchain-arm-linux-gnueabihf.cmake"
      ;;
    arm-none-linux-gnueabihf)
      toolchain="$SCRIPT_DIR/cmake/toolchain-arm-none-linux-gnueabihf.cmake"
      ;;
  esac

  if [ -n "$toolchain" ] && [ -f "$toolchain" ]; then
    echo "$toolchain"
  fi
}

# Directories (overridable via env vars for cross-compilation CI)
THIRD_PARTY="$SCRIPT_DIR/third_party"
BUILD_CACHE="$SCRIPT_DIR/.build"
QUICTLS_SRC="$THIRD_PARTY/quictls"
QUICTLS_BUILD="${QUICTLS_BUILD:-$BUILD_CACHE/quictls-build}"
QUICTLS_INSTALL="${QUICTLS_INSTALL:-$BUILD_CACHE/quictls-install}"
NGTCP2_SRC="$THIRD_PARTY/ngtcp2"
NGTCP2_BUILD="${NGTCP2_BUILD:-$BUILD_CACHE/ngtcp2-build}"
NWEP_BUILD="${NWEP_BUILD:-$SCRIPT_DIR/build}"

# Colors for output (disabled when piped or NO_COLOR is set)
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  YELLOW=''
  NC=''
fi

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Get expected architecture string for archive verification.
# Returns: "elf:<machine>" for Linux, "macho:<cputype>" for macOS, "" for others (skip check).
expected_arch_tag() {
  detect_platform
  case "$DETECTED_OS" in
    linux)
      case "$DETECTED_ARCH" in
        x86_64)  echo "elf:Advanced Micro Devices X86-64" ;;
        x86)     echo "elf:Intel 80386" ;;
        aarch64) echo "elf:AArch64" ;;
        arm)     echo "elf:ARM" ;;
        riscv64) echo "elf:RISC-V" ;;
        ppc64le) echo "elf:PowerPC64" ;;
        s390x)   echo "elf:IBM S/390" ;;
        mips64)  echo "elf:MIPS R3000" ;;
        *)       echo "" ;;
      esac
      ;;
    darwin)
      case "$DETECTED_ARCH" in
        x86_64)  echo "macho:x86_64" ;;
        aarch64) echo "macho:arm64" ;;
        *)       echo "" ;;
      esac
      ;;
    *)
      # mingw/COFF — skip arch verification
      echo ""
      ;;
  esac
}

# Check if a static archive matches the target architecture.
# Works on Linux (ELF/readelf), macOS (Mach-O/lipo+file), and mingw (skips check).
# Returns 0 if ok, 1 if wrong arch, 2 if corrupt/unreadable.
verify_archive() {
  local archive="$1"
  local ar_bin="ar"

  if [ ! -f "$archive" ]; then
    return 1
  fi

  # Use cross ar if cross-compiling
  if [ -n "${HOST:-}" ]; then
    local cross_prefix
    cross_prefix=$(get_cross_prefix)
    if command -v "${cross_prefix}ar" >/dev/null 2>&1; then
      ar_bin="${cross_prefix}ar"
    fi
  fi

  # Check archive is valid (not corrupt/truncated)
  if ! "$ar_bin" t "$archive" >/dev/null 2>&1; then
    return 2
  fi

  # Check architecture matches target
  local tag
  tag=$(expected_arch_tag)
  if [ -z "$tag" ]; then
    return 0  # no arch check for this platform (e.g. mingw COFF)
  fi

  local format="${tag%%:*}"
  local expected="${tag#*:}"

  case "$format" in
    elf)
      # Use readelf (GNU binutils)
      local readelf_bin="readelf"
      if [ -n "${HOST:-}" ]; then
        local cross_prefix
        cross_prefix=$(get_cross_prefix)
        if command -v "${cross_prefix}readelf" >/dev/null 2>&1; then
          readelf_bin="${cross_prefix}readelf"
        fi
      fi

      if command -v "$readelf_bin" >/dev/null 2>&1; then
        local actual
        actual=$("$readelf_bin" -h "$archive" 2>/dev/null | grep -m1 "Machine:" | sed 's/.*Machine:\s*//')
        if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then
          return 1
        fi
      fi
      ;;
    macho)
      # Use lipo or file (macOS)
      if command -v lipo >/dev/null 2>&1; then
        local actual
        actual=$(lipo -archs "$archive" 2>/dev/null || true)
        if [ -n "$actual" ] && ! echo "$actual" | grep -q "$expected"; then
          return 1
        fi
      elif command -v file >/dev/null 2>&1; then
        local file_out
        file_out=$(file "$archive" 2>/dev/null)
        if [ -n "$file_out" ] && ! echo "$file_out" | grep -qi "$expected"; then
          return 1
        fi
      fi
      ;;
  esac

  return 0
}

# Remove stale cmake cache if the compiler changed
check_cmake_cache() {
  local build_dir="$1"
  local cache="$build_dir/CMakeCache.txt"

  if [ ! -f "$cache" ]; then
    return
  fi

  local cached_compiler
  cached_compiler=$(grep -m1 "CMAKE_C_COMPILER:FILEPATH=" "$cache" 2>/dev/null | cut -d= -f2)

  if [ -z "$cached_compiler" ]; then
    return
  fi

  local cached_base
  cached_base=$(basename "$cached_compiler")

  if [ -n "${HOST:-}" ]; then
    # Cross-compiling: cached compiler must contain the cross prefix
    local cross_prefix
    cross_prefix=$(get_cross_prefix)
    if ! echo "$cached_base" | grep -q "^${cross_prefix}"; then
      log_warn "Stale cmake cache in $build_dir (was: $cached_base, need: ${cross_prefix}gcc)"
      log_info "Clearing cmake cache..."
      rm -rf "$build_dir/CMakeCache.txt" "$build_dir/CMakeFiles"
    fi
  else
    # Native build: cached compiler must NOT be a cross-compiler
    if echo "$cached_base" | grep -qE "^(aarch64|arm|i686|x86_64|mips|riscv|ppc|s390)-"; then
      log_warn "Stale cmake cache in $build_dir (was: $cached_base, need native compiler)"
      log_info "Clearing cmake cache..."
      rm -rf "$build_dir/CMakeCache.txt" "$build_dir/CMakeFiles"
    fi
  fi
}

# Preflight checks: verify sources, tools, and repair what we can
preflight() {
  local ok=1

  log_info "Preflight checks..."

  # --- Required tools ---
  local missing_tools=()
  local missing_optional=()

  # Always required
  command -v git >/dev/null 2>&1 || missing_tools+=("git")
  command -v cmake >/dev/null 2>&1 || missing_tools+=("cmake")
  command -v make >/dev/null 2>&1 || missing_tools+=("make")
  command -v perl >/dev/null 2>&1 || missing_tools+=("perl")
  command -v ar >/dev/null 2>&1 || missing_tools+=("ar")
  command -v tar >/dev/null 2>&1 || missing_tools+=("tar")

  if [ -n "${HOST:-}" ]; then
    # Cross-compilation tools
    local cross_prefix
    cross_prefix=$(get_cross_prefix)
    command -v "${cross_prefix}gcc" >/dev/null 2>&1 || missing_tools+=("${cross_prefix}gcc")
    command -v "${cross_prefix}ar" >/dev/null 2>&1 || missing_tools+=("${cross_prefix}ar")
    command -v "${cross_prefix}ranlib" >/dev/null 2>&1 || missing_tools+=("${cross_prefix}ranlib")
    # Cross readelf is optional (used for arch verification)
    command -v "${cross_prefix}readelf" >/dev/null 2>&1 || missing_optional+=("${cross_prefix}readelf")
  else
    # Native build tools
    command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || missing_tools+=("cc or gcc")
    # pkg-config needed for finding libuv (tests)
    command -v pkg-config >/dev/null 2>&1 || missing_optional+=("pkg-config (needed for tests)")
    # readelf is optional (used for arch verification)
    command -v readelf >/dev/null 2>&1 || missing_optional+=("readelf")
  fi

  # Packaging tools (conditional)
  detect_platform
  if [ "$DETECTED_OS" = "mingw" ]; then
    command -v zip >/dev/null 2>&1 || missing_optional+=("zip (needed for --package)")
  fi

  if [ ${#missing_tools[@]} -gt 0 ]; then
    log_error "  Tools: MISSING ${missing_tools[*]}"
    ok=0
  else
    log_info "  Tools: ok"
  fi

  if [ ${#missing_optional[@]} -gt 0 ]; then
    log_warn "  Optional: MISSING ${missing_optional[*]}"
  fi

  # --- Git submodules ---
  local submodules_ok=1
  if [ ! -f "$THIRD_PARTY/ngtcp2/CMakeLists.txt" ]; then
    log_warn "  Submodule ngtcp2: not initialized"
    submodules_ok=0
  fi
  if [ ! -f "$THIRD_PARTY/quictls/Configure" ]; then
    log_warn "  Submodule quictls: not initialized"
    submodules_ok=0
  fi
  if [ ! -d "$THIRD_PARTY/blst/src" ]; then
    log_warn "  Submodule blst: not initialized"
    submodules_ok=0
  fi

  if [ "$submodules_ok" -eq 0 ]; then
    log_info "  Submodules: initializing..."
    git -C "$SCRIPT_DIR" submodule update --init --recursive
    # Re-check
    if [ -f "$THIRD_PARTY/ngtcp2/CMakeLists.txt" ] && \
       [ -f "$THIRD_PARTY/quictls/Configure" ] && \
       [ -d "$THIRD_PARTY/blst/src" ]; then
      log_info "  Submodules: ok (initialized)"
    else
      log_error "  Submodules: FAILED to initialize"
      ok=0
    fi
  else
    log_info "  Submodules: ok"
  fi

  # --- blst source integrity ---
  # blst's build/ dir contains pre-generated assembly that can be
  # accidentally deleted (e.g. rm -rf build from wrong directory)
  if [ ! -f "$THIRD_PARTY/blst/build/assembly.S" ]; then
    log_warn "  blst assembly: missing (build/assembly.S)"
    log_info "  blst assembly: restoring from git..."
    git -C "$THIRD_PARTY/blst" checkout -- build/ 2>/dev/null
    if [ -f "$THIRD_PARTY/blst/build/assembly.S" ]; then
      log_info "  blst assembly: ok (restored)"
    else
      log_error "  blst assembly: FAILED to restore"
      ok=0
    fi
  else
    log_info "  blst assembly: ok"
  fi

  # --- Dependency build status (with architecture verification) ---
  if [ -f "$THIRD_PARTY/blst/libblst.a" ]; then
    if verify_archive "$THIRD_PARTY/blst/libblst.a"; then
      log_info "  blst lib: ok"
    else
      log_warn "  blst lib: wrong arch (will rebuild)"
    fi
  else
    log_info "  blst lib: not built (will build)"
  fi

  local ssl_check=""
  if [ -f "$QUICTLS_INSTALL/lib/libssl.a" ]; then
    ssl_check="$QUICTLS_INSTALL/lib/libssl.a"
  elif [ -f "$QUICTLS_INSTALL/lib64/libssl.a" ]; then
    ssl_check="$QUICTLS_INSTALL/lib64/libssl.a"
  fi

  if [ -n "$ssl_check" ]; then
    if verify_archive "$ssl_check"; then
      log_info "  quictls: ok ($QUICTLS_INSTALL)"
    else
      log_warn "  quictls: wrong arch (will rebuild)"
    fi
  else
    log_info "  quictls: not built (will build)"
  fi

  if [ -f "$NGTCP2_BUILD/lib/libngtcp2.a" ]; then
    if verify_archive "$NGTCP2_BUILD/lib/libngtcp2.a"; then
      log_info "  ngtcp2: ok ($NGTCP2_BUILD)"
    else
      log_warn "  ngtcp2: wrong arch (will rebuild)"
    fi
  else
    log_info "  ngtcp2: not built (will build)"
  fi

  if [ -f "$NWEP_BUILD/libnwep.a" ]; then
    if verify_archive "$NWEP_BUILD/libnwep.a"; then
      log_info "  nwep: ok ($NWEP_BUILD)"
    else
      log_warn "  nwep: wrong arch (will rebuild)"
    fi
  else
    log_info "  nwep: not built (will build)"
  fi

  if [ "$ok" -eq 0 ]; then
    log_error "Preflight checks failed. Fix the issues above and retry."
    exit 1
  fi

  log_info "Preflight checks passed"
}

# Build blst if not already built
build_blst() {
  local blst_dir="$THIRD_PARTY/blst"

  # Check if already built (and correct architecture)
  if [ -f "$blst_dir/libblst.a" ]; then
    if verify_archive "$blst_dir/libblst.a"; then
      log_info "blst already built, skipping..."
      return 0
    else
      log_warn "blst: wrong architecture or corrupt, rebuilding..."
      rm -f "$blst_dir/libblst.a"
    fi
  elif [ -f "$blst_dir/blst.lib" ]; then
    log_info "blst already built, skipping..."
    return 0
  fi

  # Verify source integrity before building
  if [ ! -f "$blst_dir/build/assembly.S" ]; then
    log_warn "blst assembly missing, restoring..."
    git -C "$blst_dir" checkout -- build/ 2>/dev/null
    if [ ! -f "$blst_dir/build/assembly.S" ]; then
      log_error "Cannot restore blst assembly files"
      exit 1
    fi
  fi

  log_info "Building blst..."
  cd "$blst_dir"

  local cross_prefix
  cross_prefix=$(get_cross_prefix)
  if [ -n "$cross_prefix" ]; then
    CC="${cross_prefix}gcc" CFLAGS="-fPIC" ./build.sh
  else
    CFLAGS="-fPIC" ./build.sh
  fi

  log_info "blst built successfully"
}

# Build quictls if not already built
build_quictls() {
  local openssl_target
  local cross_prefix

  # Detect platform
  detect_platform
  openssl_target=$(get_openssl_target "$DETECTED_OS" "$DETECTED_ARCH")
  cross_prefix=$(get_cross_prefix)

  log_info "Platform: $DETECTED_OS-$DETECTED_ARCH"
  log_info "OpenSSL target: $openssl_target"
  if [ -n "$cross_prefix" ]; then
    log_info "Cross-compiler prefix: $cross_prefix"
  fi

  # Check for both lib and lib64 (mingw64 uses lib64)
  local ssl_lib=""
  if [ -f "$QUICTLS_INSTALL/lib/libssl.a" ]; then
    ssl_lib="$QUICTLS_INSTALL/lib/libssl.a"
  elif [ -f "$QUICTLS_INSTALL/lib64/libssl.a" ]; then
    ssl_lib="$QUICTLS_INSTALL/lib64/libssl.a"
  fi

  if [ -n "$ssl_lib" ]; then
    if verify_archive "$ssl_lib"; then
      log_info "quictls already built, skipping..."
      return 0
    else
      log_warn "quictls: wrong architecture or corrupt, rebuilding..."
      rm -rf "$QUICTLS_INSTALL" "$QUICTLS_BUILD"
    fi
  fi

  log_info "Building quictls..."

  if [ ! -d "$QUICTLS_SRC" ]; then
    log_error "quictls source not found at $QUICTLS_SRC"
    exit 1
  fi

  mkdir -p "$QUICTLS_BUILD"
  cd "$QUICTLS_BUILD"

  local configure_args=(
    --prefix="$QUICTLS_INSTALL"
    --openssldir="$QUICTLS_INSTALL"
    no-shared
    no-tests
    enable-tls1_3
    -fPIC
    "$openssl_target"
  )

  # Add cross-compiler prefix if cross-compiling
  if [ -n "$cross_prefix" ]; then
    configure_args+=(--cross-compile-prefix="$cross_prefix")
  fi

  "$QUICTLS_SRC/Configure" "${configure_args[@]}"

  make -j"$JOBS"
  make install_sw

  # Create lib symlink if mingw64 installed to lib64
  cd "$QUICTLS_INSTALL"
  if [ -d lib64 ] && [ ! -e lib ]; then
    ln -s lib64 lib
  fi

  log_info "quictls built successfully"
}

# Build ngtcp2 if not already built
build_ngtcp2() {
  local cmake_args=()

  if [ -f "$NGTCP2_BUILD/lib/libngtcp2.a" ] && [ -f "$NGTCP2_BUILD/crypto/quictls/libngtcp2_crypto_quictls.a" ]; then
    if verify_archive "$NGTCP2_BUILD/lib/libngtcp2.a"; then
      log_info "ngtcp2 already built, skipping..."
      return 0
    else
      log_warn "ngtcp2: wrong architecture or corrupt, rebuilding..."
      rm -rf "$NGTCP2_BUILD"
    fi
  fi

  log_info "Building ngtcp2..."

  if [ ! -d "$NGTCP2_SRC" ]; then
    log_error "ngtcp2 source not found at $NGTCP2_SRC"
    exit 1
  fi

  mkdir -p "$NGTCP2_BUILD"
  cd "$NGTCP2_BUILD"

  # Check for stale cmake cache (e.g. switching between native and cross)
  check_cmake_cache "$NGTCP2_BUILD"

  cmake_args=(
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DENABLE_SHARED_LIB=OFF
    -DENABLE_STATIC_LIB=ON
    -DENABLE_OPENSSL=ON
    -DENABLE_GNUTLS=OFF
    -DENABLE_BORINGSSL=OFF
    -DENABLE_PICOTLS=OFF
    -DENABLE_WOLFSSL=OFF
    -DOPENSSL_ROOT_DIR="$QUICTLS_INSTALL"
    -DOPENSSL_USE_STATIC_LIBS=ON
  )

  # Add toolchain file and custom modules for cross-compilation
  if [ -n "${HOST:-}" ]; then
    local toolchain_file
    toolchain_file=$(get_toolchain_file)
    if [ -n "$toolchain_file" ]; then
      cmake_args+=(-DCMAKE_TOOLCHAIN_FILE="$toolchain_file")
    fi
    cmake_args+=(-DCMAKE_MODULE_PATH="$SCRIPT_DIR/cmake")
  fi

  cmake "$NGTCP2_SRC" "${cmake_args[@]}"

  make -j"$JOBS"

  log_info "ngtcp2 built successfully"
}

# Build nwep
build_nwep() {
  local cmake_args=()

  # Check if already built and correct architecture
  if [ -f "$NWEP_BUILD/libnwep.a" ]; then
    if verify_archive "$NWEP_BUILD/libnwep.a"; then
      log_info "nwep already built, skipping..."
      return 0
    else
      log_warn "nwep: wrong architecture or corrupt, rebuilding..."
      rm -rf "$NWEP_BUILD"
    fi
  fi

  log_info "Building nwep..."

  mkdir -p "$NWEP_BUILD"
  cd "$NWEP_BUILD"

  # Check for stale cmake cache (e.g. switching between native and cross)
  check_cmake_cache "$NWEP_BUILD"

  cmake_args=(
    -DCMAKE_BUILD_TYPE=Release
    -DBUILD_SHARED_LIBS=OFF
    -DQUICTLS_ROOT="$QUICTLS_INSTALL"
    -DNGTCP2_BUILD="$NGTCP2_BUILD"
  )

  # Add toolchain file for cross-compilation
  if [ -n "${HOST:-}" ]; then
    local toolchain_file
    toolchain_file=$(get_toolchain_file)
    if [ -n "$toolchain_file" ]; then
      cmake_args+=(-DCMAKE_TOOLCHAIN_FILE="$toolchain_file")
    fi
    # Disable tests when cross-compiling (they need host libuv)
    cmake_args+=(-DNWEP_BUILD_TESTS=OFF)
  fi

  cmake "$SCRIPT_DIR" "${cmake_args[@]}"

  make -j"$JOBS"

  if [ -f "$NWEP_BUILD/libnwep.a" ]; then
    log_info "nwep built successfully: $NWEP_BUILD/libnwep.a"
  else
    log_error "Failed to build nwep"
    exit 1
  fi
}

# Build Node.js N-API addon
build_node() {
  # Skip when cross-compiling — cmake-js builds for the host only
  if [ -n "${HOST:-}" ]; then
    log_info "Skipping Node.js addon (cross-compiling for $HOST)"
    return 0
  fi

  # Verify node is available
  command -v node >/dev/null 2>&1 || { log_error "node not found"; exit 1; }

  # Install npm deps if needed
  if [ ! -d "$SCRIPT_DIR/node/node_modules" ]; then
    log_info "Installing npm dependencies..."
    npm --prefix "$SCRIPT_DIR/node" install --ignore-scripts
  fi

  # Build deps (already PIC on supported platforms)
  build_blst
  build_quictls
  build_ngtcp2

  # cmake-js must run from the repo root (where CMakeLists.txt lives)
  # Output to .build/node/ to avoid conflicting with the C library build in build/
  # cmake-js sets CMAKE_JS_INC which triggers POSITION_INDEPENDENT_CODE ON
  # on the nwep target and includes the node/binding/ subdirectory
  log_info "Building Node.js addon..."
  cd "$SCRIPT_DIR"
  "$SCRIPT_DIR/node/node_modules/.bin/cmake-js" build \
    --out "$BUILD_CACHE/node" \
    --CDNWEP_BUILD_TESTS=OFF \
    --CDQUICTLS_ROOT="$QUICTLS_INSTALL" \
    --CDNGTCP2_BUILD="$NGTCP2_BUILD" \
    --CDBLST_ROOT="$THIRD_PARTY/blst"

  # Verify output
  if [ -f "$BUILD_CACHE/node/Release/nwep_napi.node" ]; then
    log_info "Node.js addon built: .build/node/Release/nwep_napi.node"
  else
    log_error "Node.js addon not found after build"
    exit 1
  fi
}

# Clean build (nwep + blst, not deps)
clean() {
  log_info "Cleaning build directories..."
  rm -rf "$NWEP_BUILD"
  rm -f "$THIRD_PARTY/blst/libblst.a" "$THIRD_PARTY/blst/blst.lib"
  log_info "Clean complete"
}

# Clean all (including dependencies, cross-compile dirs, and dist)
clean_all() {
  log_info "Cleaning all build directories..."
  rm -rf "$BUILD_CACHE"
  rm -rf "$SCRIPT_DIR/dist"
  # Clean blst in-place build
  rm -f "$THIRD_PARTY/blst/libblst.a" "$THIRD_PARTY/blst/blst.lib"
  log_info "Clean all complete"
}

# Create a fat archive merging all static libraries
create_fat_archive() {
  local output="$1"
  shift
  local inputs=("$@")

  # Filter to only existing libraries
  local existing=()
  for lib in "${inputs[@]}"; do
    if [ -f "$lib" ]; then
      existing+=("$lib")
    else
      log_warn "Library not found, skipping: $lib"
    fi
  done

  if [ ${#existing[@]} -eq 0 ]; then
    log_error "No libraries found for fat archive"
    exit 1
  fi

  # macOS: BSD ar doesn't support MRI scripts, use libtool instead
  if [ "$(uname -s)" = "Darwin" ]; then
    libtool -static -o "$output" "${existing[@]}"
    log_info "Created fat archive (libtool): $output"
    return
  fi

  # Linux/MinGW: use ar -M with MRI script
  local ar_bin="ar"
  if [ -n "${HOST:-}" ]; then
    local cross_prefix
    cross_prefix=$(get_cross_prefix)
    ar_bin="${cross_prefix}ar"
  fi

  local mri_script
  mri_script="CREATE ${output}"$'\n'
  for lib in "${existing[@]}"; do
    mri_script+="ADDLIB ${lib}"$'\n'
  done
  mri_script+="SAVE"$'\n'
  mri_script+="END"$'\n'

  echo "$mri_script" | "$ar_bin" -M
  log_info "Created fat archive: $output"
}

# Package built artifacts into a distributable archive
package() {
  local version
  version=$(cat "$SCRIPT_DIR/VERSION")
  version=$(echo "$version" | tr -d '[:space:]')

  detect_platform
  local os="$DETECTED_OS"
  local arch="$DETECTED_ARCH"
  local pkg_name="nwep-${version}-${os}-${arch}"
  local staging="$SCRIPT_DIR/dist/${pkg_name}"
  local dist_dir="$SCRIPT_DIR/dist"

  log_info "Packaging ${pkg_name}..."

  # Verify nwep was built
  if [ ! -f "$NWEP_BUILD/libnwep.a" ]; then
    log_error "nwep not built. Run ./build.sh first."
    exit 1
  fi

  # Clean and create staging directory
  rm -rf "$staging"
  mkdir -p "$staging/lib" "$staging/include/nwep" "$staging/include/ngtcp2" "$staging/include/openssl"

  # --- Libraries ---
  cp "$NWEP_BUILD/libnwep.a" "$staging/lib/"
  cp "$NGTCP2_BUILD/lib/libngtcp2.a" "$staging/lib/"
  cp "$NGTCP2_BUILD/crypto/quictls/libngtcp2_crypto_quictls.a" "$staging/lib/"

  # quictls: handle lib vs lib64
  if [ -f "$QUICTLS_INSTALL/lib/libssl.a" ]; then
    cp "$QUICTLS_INSTALL/lib/libssl.a" "$staging/lib/"
    cp "$QUICTLS_INSTALL/lib/libcrypto.a" "$staging/lib/"
  elif [ -f "$QUICTLS_INSTALL/lib64/libssl.a" ]; then
    cp "$QUICTLS_INSTALL/lib64/libssl.a" "$staging/lib/"
    cp "$QUICTLS_INSTALL/lib64/libcrypto.a" "$staging/lib/"
  else
    log_error "quictls libraries not found"
    exit 1
  fi

  cp "$THIRD_PARTY/blst/libblst.a" "$staging/lib/"

  # --- Fat archive ---
  create_fat_archive "$staging/lib/libnwep_packed.a" \
    "$NWEP_BUILD/libnwep.a" \
    "$NGTCP2_BUILD/crypto/quictls/libngtcp2_crypto_quictls.a" \
    "$NGTCP2_BUILD/lib/libngtcp2.a" \
    "$staging/lib/libssl.a" \
    "$staging/lib/libcrypto.a" \
    "$THIRD_PARTY/blst/libblst.a"

  # --- Headers ---
  # nwep
  cp "$SCRIPT_DIR/include/nwep/nwep.h" "$staging/include/nwep/"
  cp "$NWEP_BUILD/include/nwep/version.h" "$staging/include/nwep/"

  # openssl
  cp "$QUICTLS_INSTALL/include/openssl/"*.h "$staging/include/openssl/"

  # ngtcp2 (source headers + generated version.h)
  cp "$NGTCP2_SRC/lib/includes/ngtcp2/ngtcp2.h" "$staging/include/ngtcp2/"
  cp "$NGTCP2_BUILD/lib/includes/ngtcp2/version.h" "$staging/include/ngtcp2/"
  cp "$NGTCP2_SRC/crypto/includes/ngtcp2/ngtcp2_crypto.h" "$staging/include/ngtcp2/"
  cp "$NGTCP2_SRC/crypto/includes/ngtcp2/ngtcp2_crypto_quictls.h" "$staging/include/ngtcp2/"

  # blst
  cp "$THIRD_PARTY/blst/bindings/blst.h" "$staging/include/"

  # --- pkg-config ---
  mkdir -p "$staging/lib/pkgconfig"
  cat > "$staging/lib/pkgconfig/nwep.pc" <<EOF
prefix=\${pcfiledir}/../..
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: nwep
Description: WEB/1 protocol library over QUIC
Version: ${version}
Libs: -L\${libdir} -lnwep_packed -lpthread -ldl
Cflags: -I\${includedir} -DNWEP_STATICLIB
EOF

  # --- Node.js addon ---
  if [ -f "$BUILD_CACHE/node/Release/nwep_napi.node" ]; then
    mkdir -p "$staging/nodejs"
    cp "$BUILD_CACHE/node/Release/nwep_napi.node" "$staging/nodejs/"
    log_info "Including Node.js addon: nodejs/nwep_napi.node"
  fi

  # --- LICENSE ---
  if [ -f "$SCRIPT_DIR/LICENSE" ]; then
    cp "$SCRIPT_DIR/LICENSE" "$staging/"
  fi

  # --- Create archive ---
  cd "$dist_dir"
  local archive_file=""
  case "$os" in
    mingw)
      zip -r "${pkg_name}.zip" "${pkg_name}"
      archive_file="${pkg_name}.zip"
      log_info "Package created: dist/${archive_file}"
      ;;
    *)
      tar czf "${pkg_name}.tar.gz" "${pkg_name}"
      archive_file="${pkg_name}.tar.gz"
      log_info "Package created: dist/${archive_file}"
      ;;
  esac

  # Generate checksum
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$archive_file" >> SHA256SUMS
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$archive_file" >> SHA256SUMS
  fi

  cd "$SCRIPT_DIR"
}

# Build and package all locally-possible targets
package_all() {
  local targets=(
    ""                          # native (linux-x86_64)
    "aarch64-linux-gnu"         # linux-aarch64
    "arm-none-linux-gnueabihf"  # linux-arm (ARM official toolchain)
    "x86_64-w64-mingw32"        # mingw-x86_64
    "i686-w64-mingw32"          # mingw-x86
  )

  local failed=()
  local succeeded=()
  local blst_dir="$THIRD_PARTY/blst"

  preflight

  for host in "${targets[@]}"; do
    local label="${host:-native}"
    log_info "=========================================="
    log_info "Building target: $label"
    log_info "=========================================="

    # Each target gets isolated build directories to avoid clobbering
    local target_dir="$BUILD_CACHE/${label}"
    local blst_cache="$target_dir/blst"

    # blst builds in-place — save/restore per target to avoid arch conflicts
    rm -f "$blst_dir/libblst.a" "$blst_dir/blst.lib"
    if [ -f "$blst_cache/libblst.a" ]; then
      cp "$blst_cache/libblst.a" "$blst_dir/libblst.a"
    fi

    if (
      # Run in subshell so env changes don't leak between targets
      export HOST="$host"
      export QUICTLS_BUILD="$target_dir/quictls-build"
      export QUICTLS_INSTALL="$target_dir/quictls-install"
      export NGTCP2_BUILD="$target_dir/ngtcp2-build"
      export NWEP_BUILD="$target_dir/nwep"

      preflight
      build_blst
      build_quictls
      build_ngtcp2
      build_nwep
      package
    ); then
      succeeded+=("$label")
    else
      log_error "Failed to build $label"
      failed+=("$label")
    fi

    # Cache blst artifact for this target
    mkdir -p "$blst_cache"
    if [ -f "$blst_dir/libblst.a" ]; then
      cp "$blst_dir/libblst.a" "$blst_cache/libblst.a"
    fi
  done

  echo ""
  log_info "=========================================="
  log_info "package-all summary"
  log_info "=========================================="
  log_info "Succeeded (${#succeeded[@]}): ${succeeded[*]}"
  if [ ${#failed[@]} -gt 0 ]; then
    log_error "Failed (${#failed[@]}): ${failed[*]}"
  fi
  echo ""
  log_info "Packages in dist/:"
  ls -lh "$SCRIPT_DIR/dist/"*.tar.gz "$SCRIPT_DIR/dist/"*.zip 2>/dev/null || true
}

# Map architecture name to Docker --platform string
arch_to_docker_platform() {
  local arch="$1"
  case "$arch" in
    x86_64)   echo "linux/amd64" ;;
    x86)      echo "linux/386" ;;
    aarch64)  echo "linux/arm64" ;;
    arm)      echo "linux/arm/v7" ;;
    riscv64)  echo "linux/riscv64" ;;
    ppc64le)  echo "linux/ppc64le" ;;
    s390x)    echo "linux/s390x" ;;
    mips64)   echo "linux/mips64le" ;;
    *)
      log_error "No Docker platform mapping for arch: $arch"
      exit 1
      ;;
  esac
}

# Build for a foreign architecture via QEMU + Docker
emulate() {
  local arch="$1"

  if [ -z "$arch" ]; then
    log_error "Usage: $0 emulate <arch>"
    log_error "Supported: x86_64, aarch64, arm, riscv64, ppc64le, s390x, mips64"
    exit 1
  fi

  # Verify docker is available
  if ! command -v docker >/dev/null 2>&1; then
    log_error "Docker is required for emulated builds"
    log_error "Install docker and ensure the daemon is running"
    exit 1
  fi

  # Verify QEMU binfmt is registered
  if [ ! -d /proc/sys/fs/binfmt_misc ] || [ ! -f /proc/sys/fs/binfmt_misc/status ]; then
    log_warn "binfmt_misc not detected. QEMU emulation may not work."
    log_warn "Try: sudo systemctl enable --now systemd-binfmt"
  fi

  local platform
  platform=$(arch_to_docker_platform "$arch")

  log_info "Building for $arch via QEMU emulation ($platform)"
  log_info "This will be slow — QEMU emulates every instruction"

  # Ensure submodules are initialized on the host first
  preflight

  # Create dist dir on host so the bind mount works
  mkdir -p "$SCRIPT_DIR/dist"

  docker run --rm \
    --platform "$platform" \
    -v "$SCRIPT_DIR:/src:ro" \
    -v "$SCRIPT_DIR/dist:/output" \
    ubuntu:24.04 \
    bash -c '
      set -e

      echo "=== Running on: $(uname -m) ==="

      # Install build dependencies
      apt-get update -qq
      apt-get install -y -qq cmake make gcc g++ perl nodejs npm >/dev/null 2>&1

      # Copy source to writable workdir (source mount is read-only)
      cp -a /src/. /work/
      cd /work

      # Build everything and package
      ./build.sh --package

      # Copy package to output
      cp -a dist/* /output/

      echo "=== Build complete ==="
    '

  log_info "Emulated build complete. Packages in dist/:"
  ls -lh "$SCRIPT_DIR/dist/"*"$arch"* 2>/dev/null || log_warn "No packages found for $arch"
}

# Show help
show_help() {
  echo "Usage: $0 [--package] [command]"
  echo ""
  echo "From a fresh clone, just run ./build.sh — it handles submodules,"
  echo "dependency builds (blst, quictls, ngtcp2), and nwep automatically."
  echo ""
  echo "Commands:"
  echo "  all              Build everything (default)"
  echo "  quictls          Build quictls only"
  echo "  ngtcp2           Build ngtcp2 only"
  echo "  nwep             Build nwep only"
  echo "  node             Build Node.js N-API addon"
  echo "  package          Package built artifacts (no rebuild)"
  echo "  package-all      Build + package all cross-compile targets"
  echo "  emulate <arch>   Build for <arch> via QEMU + Docker"
  echo "  clean            Clean nwep build"
  echo "  clean-all        Clean all builds (including dependencies)"
  echo "  help             Show this help"
  echo ""
  echo "Flags:"
  echo "  --package   After building, create a distributable package"
  echo ""
  echo "Environment variables:"
  echo "  JOBS        Number of parallel jobs (default: nproc)"
  echo "  HOST        Cross-compilation target triplet"
  echo ""
  echo "Supported platforms:"
  echo "  Linux:   x86_64, aarch64, arm, mips, mips64, ppc64le, riscv64, s390x"
  echo "  macOS:   x86_64, aarch64"
  echo "  Windows: x86_64, x86 (via MinGW)"
  echo ""
  echo "Cross-compilation examples:"
  echo "  HOST=x86_64-w64-mingw32 $0    # Windows x64 via MinGW"
  echo "  HOST=i686-w64-mingw32 $0      # Windows x86 via MinGW"
  echo "  HOST=aarch64-linux-gnu $0     # Linux ARM64"
  echo ""
  echo "Packaging examples:"
  echo "  $0 --package              # Build everything + package"
  echo "  $0 package                # Package already-built artifacts"
  echo "  $0 package-all            # Build all 5 local targets to dist/"
  echo ""
  echo "Emulated builds (requires Docker + QEMU binfmt):"
  echo "  $0 emulate riscv64        # RISC-V 64-bit"
  echo "  $0 emulate ppc64le        # IBM POWER"
  echo "  $0 emulate s390x          # IBM Z"
  echo "  $0 emulate aarch64        # ARM64 (if no native hardware)"
}

# Parse arguments: separate flags from positional args
DO_PACKAGE=0
POSITIONAL=()

for arg in "$@"; do
  case "$arg" in
    --package)
      DO_PACKAGE=1
      ;;
    *)
      POSITIONAL+=("$arg")
      ;;
  esac
done

COMMAND="${POSITIONAL[0]:-all}"

# Main
case "$COMMAND" in
  all)
    preflight
    build_blst
    build_quictls
    build_ngtcp2
    build_nwep
    if command -v node >/dev/null 2>&1; then
      build_node
    fi
    if [ "$DO_PACKAGE" -eq 1 ]; then
      package
    fi
    ;;
  quictls)
    preflight
    build_quictls
    [ "$DO_PACKAGE" -eq 1 ] && log_warn "--package is only used with 'all' command, ignoring"
    ;;
  ngtcp2)
    preflight
    build_quictls
    build_ngtcp2
    [ "$DO_PACKAGE" -eq 1 ] && log_warn "--package is only used with 'all' command, ignoring"
    ;;
  nwep)
    preflight
    build_blst
    build_quictls
    build_ngtcp2
    build_nwep
    [ "$DO_PACKAGE" -eq 1 ] && log_warn "--package is only used with 'all' command, ignoring"
    ;;
  node)
    preflight
    build_node
    ;;
  package)
    package
    ;;
  package-all)
    package_all
    ;;
  emulate)
    emulate "${POSITIONAL[1]:-}"
    ;;
  clean)
    clean
    ;;
  clean-all)
    clean_all
    ;;
  help|--help|-h)
    show_help
    ;;
  *)
    log_error "Unknown command: $COMMAND"
    show_help
    exit 1
    ;;
esac
