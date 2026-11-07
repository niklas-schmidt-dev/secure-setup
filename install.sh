#!/bin/sh
# Installs secure-setup and starts it.
#
#   On your computer, to set a server up over SSH:
#     sh -c "$(curl -fsSL https://raw.githubusercontent.com/niklas-schmidt-dev/secure-setup/main/install.sh)"
#
#   On the server itself (root), to lock this machine down:
#     curl -fsSL https://raw.githubusercontent.com/niklas-schmidt-dev/secure-setup/main/install.sh | sh -s -- here
#
#   Unattended, e.g. in cloud-init, with a Tailscale auth key:
#     see examples/cloud-init.yaml (the auth key comes from a root-only file)
#
# Arguments after the script are passed to secure-setup. Without arguments
# the wizard for a remote server starts.
#
# What it does: downloads the release archive for your OS and architecture
# from GitHub Releases together with checksums.txt, verifies the SHA-256,
# installs one static binary, and runs it. Nothing else touches your machine.
# With the GitHub CLI (gh) installed it also checks the release's signed
# build provenance: the release workflow built this archive from a tag.
#
# Environment:
#   SECURE_SETUP_VERSION        release tag to install, e.g. v0.1.0 (default: latest)
#   SECURE_SETUP_INSTALL_DIR    where the binary goes (default: /usr/local/bin as root, else ~/.local/bin)
#   SECURE_SETUP_NO_RUN=1       install only, do not start it
#   SECURE_SETUP_NO_PROVENANCE=1  skip the provenance check (releases up to v0.4.0 have none)
set -eu

REPO="niklas-schmidt-dev/secure-setup"
NAME="secure-setup"

say() { printf '%s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

# check_provenance verifies provenance.json from the same release with gh.
# checksums.txt only catches a broken download; the provenance is signed by
# the release workflow, so a replaced archive or a missing file stops here.
check_provenance() {
  [ "${SECURE_SETUP_NO_PROVENANCE:-0}" = 1 ] && return 0
  if ! command -v gh >/dev/null 2>&1; then
    say "Provenance not checked (that needs the GitHub CLI, gh)."
    return 0
  fi
  if ! gh attestation verify --help 2>/dev/null | grep -q -- --signer-workflow; then
    say "Provenance not checked: this gh is too old for \`gh attestation verify\`."
    return 0
  fi
  fetch "$base/provenance.json" "$tmp/provenance.json" ||
    die "this release has no provenance.json, so its origin cannot be checked
  (releases up to v0.4.0 have none; SECURE_SETUP_NO_PROVENANCE=1 installs without the check)"
  if ! gh attestation verify "$tmp/$archive" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release.yml" \
    --bundle "$tmp/provenance.json" >/dev/null 2>"$tmp/provenance.err"; then
    die "the provenance check failed for $archive: it was not built by the release workflow of $REPO
$(tail -n 3 "$tmp/provenance.err")"
  fi
  say "Provenance OK: built by the release workflow of $REPO."
}

main() {
  os=$(uname -s)
  case "$os" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) die "unsupported OS: $os (macOS and Linux are supported; on Windows use WSL)" ;;
  esac

  arch=$(uname -m)
  case "$arch" in
    x86_64 | amd64) arch=amd64 ;;
    arm64 | aarch64) arch=arm64 ;;
    *) die "unsupported architecture: $arch" ;;
  esac

  if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
  elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
  else
    die "curl or wget is required"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
  elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
  else
    die "sha256sum or shasum is required"
  fi

  version=${SECURE_SETUP_VERSION:-latest}
  if [ "$version" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$version"
  fi
  archive="${NAME}_${os}_${arch}.tar.gz"
  if [ -n "${SECURE_SETUP_INSTALL_DIR:-}" ]; then
    install_dir=$SECURE_SETUP_INSTALL_DIR
  elif [ "$(id -u)" = 0 ]; then
    install_dir=/usr/local/bin
  else
    install_dir=$HOME/.local/bin
  fi

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  say "Downloading $NAME ($version, $os/$arch)..."
  fetch "$base/$archive" "$tmp/$archive" || die "download failed: $base/$archive"
  fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"

  expected=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
  [ -n "$expected" ] || die "no entry for $archive in checksums.txt"
  actual=$(sha256 "$tmp/$archive")
  if [ "$actual" != "$expected" ]; then
    die "checksum mismatch for $archive
  expected $expected
  got      $actual"
  fi
  say "Checksum OK."
  check_provenance

  tar -xzf "$tmp/$archive" -C "$tmp" "$NAME"
  mkdir -p "$install_dir"
  install -m 0755 "$tmp/$NAME" "$install_dir/$NAME"
  bin="$install_dir/$NAME"
  say "Installed $bin ($("$bin" version))"

  case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) say "note: $install_dir is not in your PATH. Add it, or call $bin directly." ;;
  esac

  if [ "${SECURE_SETUP_NO_RUN:-0}" = 1 ]; then
    exit 0
  fi

  say ""
  if [ -t 0 ]; then
    exec "$bin" "$@"
  elif ( : </dev/tty ) 2>/dev/null; then
    # Piped through sh: hand secure-setup the terminal.
    exec "$bin" "$@" </dev/tty
  elif [ $# -gt 0 ]; then
    # No terminal (cloud-init, a script): run the given command as is.
    exec "$bin" "$@"
  else
    say "No terminal available. Start the wizard with: $bin"
  fi
}

main "$@"
