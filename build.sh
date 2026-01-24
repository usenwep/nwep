#!/bin/bash
#
# nwep build script
#
# This script builds quictls, ngtcp2, and nwep in order.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Number of parallel jobs
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

# Platform detection
# Supports HOST= env var for cross-compilation (e.g., HOST=x86_64-w64-mingw32)
detect_platform() {
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
    arm-linux-gnueabihf)
      echo "arm-linux-gnueabihf-"
      ;;
    *)
      echo "${host}-"
      ;;
  esac
}

# Directories
THIRD_PARTY="$SCRIPT_DIR/third_party"
QUICTLS_SRC="$THIRD_PARTY/quictls"
QUICTLS_BUILD="$THIRD_PARTY/quictls-build"
QUICTLS_INSTALL="$THIRD_PARTY/quictls-install"
NGTCP2_SRC="$THIRD_PARTY/ngtcp2"
NGTCP2_BUILD="$THIRD_PARTY/ngtcp2-build"
NWEP_BUILD="$SCRIPT_DIR/build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

log_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
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

  if [ -f "$QUICTLS_INSTALL/lib/libssl.a" ] && [ -f "$QUICTLS_INSTALL/lib/libcrypto.a" ]; then
    log_info "quictls already built, skipping..."
    return 0
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
    "$openssl_target"
  )

  # Add cross-compiler prefix if cross-compiling
  if [ -n "$cross_prefix" ]; then
    configure_args+=(--cross-compile-prefix="$cross_prefix")
  fi

  "$QUICTLS_SRC/Configure" "${configure_args[@]}"

  make -j"$JOBS"
  make install_sw

  log_info "quictls built successfully"
}

# Build ngtcp2 if not already built
build_ngtcp2() {
  local cmake_args=()

  if [ -f "$NGTCP2_BUILD/lib/libngtcp2.a" ] && [ -f "$NGTCP2_BUILD/crypto/quictls/libngtcp2_crypto_quictls.a" ]; then
    log_info "ngtcp2 already built, skipping..."
    return 0
  fi

  log_info "Building ngtcp2..."

  if [ ! -d "$NGTCP2_SRC" ]; then
    log_error "ngtcp2 source not found at $NGTCP2_SRC"
    exit 1
  fi

  mkdir -p "$NGTCP2_BUILD"
  cd "$NGTCP2_BUILD"

  cmake_args=(
    -DCMAKE_BUILD_TYPE=Release
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

  # Add toolchain file for cross-compilation
  if [ -n "${HOST:-}" ]; then
    local toolchain_file=""
    case "$HOST" in
      x86_64-w64-mingw32)
        toolchain_file="$SCRIPT_DIR/cmake/toolchain-mingw64.cmake"
        ;;
      i686-w64-mingw32)
        toolchain_file="$SCRIPT_DIR/cmake/toolchain-mingw32.cmake"
        ;;
      aarch64-linux-gnu)
        toolchain_file="$SCRIPT_DIR/cmake/toolchain-aarch64-linux.cmake"
        ;;
    esac
    if [ -n "$toolchain_file" ] && [ -f "$toolchain_file" ]; then
      cmake_args+=(-DCMAKE_TOOLCHAIN_FILE="$toolchain_file")
    fi
  fi

  cmake "$NGTCP2_SRC" "${cmake_args[@]}"

  make -j"$JOBS"

  log_info "ngtcp2 built successfully"
}

# Build nwep
build_nwep() {
  local cmake_args=()

  log_info "Building nwep..."

  mkdir -p "$NWEP_BUILD"
  cd "$NWEP_BUILD"

  cmake_args=(
    -DCMAKE_BUILD_TYPE=Release
    -DBUILD_SHARED_LIBS=OFF
  )

  # Add toolchain file for cross-compilation
  if [ -n "${HOST:-}" ]; then
    local toolchain_file=""
    case "$HOST" in
      x86_64-w64-mingw32)
        toolchain_file="$SCRIPT_DIR/cmake/toolchain-mingw64.cmake"
        ;;
      i686-w64-mingw32)
        toolchain_file="$SCRIPT_DIR/cmake/toolchain-mingw32.cmake"
        ;;
      aarch64-linux-gnu)
        toolchain_file="$SCRIPT_DIR/cmake/toolchain-aarch64-linux.cmake"
        ;;
    esac
    if [ -n "$toolchain_file" ] && [ -f "$toolchain_file" ]; then
      cmake_args+=(-DCMAKE_TOOLCHAIN_FILE="$toolchain_file")
    fi
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

# Clean build
clean() {
  log_info "Cleaning build directories..."
  rm -rf "$NWEP_BUILD"
  log_info "Clean complete"
}

# Clean all (including dependencies)
clean_all() {
  log_info "Cleaning all build directories..."
  rm -rf "$NWEP_BUILD"
  rm -rf "$NGTCP2_BUILD"
  rm -rf "$QUICTLS_BUILD"
  rm -rf "$QUICTLS_INSTALL"
  log_info "Clean all complete"
}

# Show help
show_help() {
  echo "Usage: $0 [command]"
  echo ""
  echo "Commands:"
  echo "  all         Build everything (default)"
  echo "  quictls     Build quictls only"
  echo "  ngtcp2      Build ngtcp2 only"
  echo "  nwep        Build nwep only"
  echo "  clean       Clean nwep build"
  echo "  clean-all   Clean all builds (including dependencies)"
  echo "  help        Show this help"
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
}

# Main
case "${1:-all}" in
  all)
    build_quictls
    build_ngtcp2
    build_nwep
    ;;
  quictls)
    build_quictls
    ;;
  ngtcp2)
    build_quictls
    build_ngtcp2
    ;;
  nwep)
    build_nwep
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
    log_error "Unknown command: $1"
    show_help
    exit 1
    ;;
esac
