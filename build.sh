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

  "$QUICTLS_SRC/Configure" \
    --prefix="$QUICTLS_INSTALL" \
    --openssldir="$QUICTLS_INSTALL" \
    no-shared \
    no-tests \
    enable-tls1_3 \
    linux-x86_64

  make -j"$JOBS"
  make install_sw

  log_info "quictls built successfully"
}

# Build ngtcp2 if not already built
build_ngtcp2() {
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

  cmake "$NGTCP2_SRC" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_SHARED_LIB=OFF \
    -DENABLE_STATIC_LIB=ON \
    -DENABLE_OPENSSL=ON \
    -DENABLE_GNUTLS=OFF \
    -DENABLE_BORINGSSL=OFF \
    -DENABLE_PICOTLS=OFF \
    -DENABLE_WOLFSSL=OFF \
    -DOPENSSL_ROOT_DIR="$QUICTLS_INSTALL" \
    -DOPENSSL_USE_STATIC_LIBS=ON

  make -j"$JOBS"

  log_info "ngtcp2 built successfully"
}

# Build nwep
build_nwep() {
  log_info "Building nwep..."

  mkdir -p "$NWEP_BUILD"
  cd "$NWEP_BUILD"

  cmake "$SCRIPT_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF

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
