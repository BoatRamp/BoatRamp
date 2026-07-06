#!/bin/sh
# boatramp installer. Downloads the right release archive for your
# OS/arch from GitHub Releases, verifies its SHA-256 against the release's
# SHA256SUMS, and installs the `boatramp` binary.
#
#   curl --proto '=https' --tlsv1.2 -fsSL \
#     https://raw.githubusercontent.com/BoatRamp/BoatRamp/main/packaging/install/install.sh | sh
#
# Env knobs:
#   BOATRAMP_VERSION   release tag to install (default: latest)
#   BOATRAMP_INSTALL_DIR  where to put the binary (default: $HOME/.local/bin)
set -eu

REPO="BoatRamp/BoatRamp"
BIN="boatramp"
VERSION="${BOATRAMP_VERSION:-latest}"
INSTALL_DIR="${BOATRAMP_INSTALL_DIR:-$HOME/.local/bin}"

err() {
	echo "boatramp-install: $*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1"
}

# --- detect target triple ---------------------------------------------------
detect_target() {
	os="$(uname -s)"
	arch="$(uname -m)"
	case "$os" in
	Linux) os_part="unknown-linux-gnu" ;;
	Darwin) os_part="apple-darwin" ;;
	*) err "unsupported OS: $os (Windows: use install.ps1)" ;;
	esac
	case "$arch" in
	x86_64 | amd64) arch_part="x86_64" ;;
	aarch64 | arm64) arch_part="aarch64" ;;
	*) err "unsupported architecture: $arch" ;;
	esac
	echo "${arch_part}-${os_part}"
}

# --- download helper (curl or wget) -----------------------------------------
download() {
	# download <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" "$1"
	else
		err "need curl or wget to download"
	fi
}

# --- sha256 verify (portable across coreutils / macOS) ----------------------
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		err "need sha256sum or shasum to verify the download"
	fi
}

main() {
	need uname
	need tar

	target="$(detect_target)"
	asset="${BIN}-${target}.tar.xz"

	if [ "$VERSION" = "latest" ]; then
		base="https://github.com/${REPO}/releases/latest/download"
	else
		base="https://github.com/${REPO}/releases/download/${VERSION}"
	fi

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT

	echo "boatramp-install: downloading ${asset} (${VERSION})"
	download "${base}/${asset}" "${tmp}/${asset}"
	download "${base}/SHA256SUMS" "${tmp}/SHA256SUMS"

	# Verify: the computed digest must equal the one SHA256SUMS lists for our asset.
	want="$(grep " ${asset}\$" "${tmp}/SHA256SUMS" | cut -d' ' -f1)"
	[ -n "$want" ] || err "no checksum for ${asset} in SHA256SUMS"
	got="$(sha256_of "${tmp}/${asset}")"
	[ "$want" = "$got" ] || err "checksum mismatch for ${asset} (expected ${want}, got ${got})"

	tar -C "$tmp" -xJf "${tmp}/${asset}"

	mkdir -p "$INSTALL_DIR"
	install -m 0755 "${tmp}/${BIN}" "${INSTALL_DIR}/${BIN}"

	echo "boatramp-install: installed ${INSTALL_DIR}/${BIN}"
	case ":${PATH}:" in
	*":${INSTALL_DIR}:"*) : ;;
	*) echo "boatramp-install: add ${INSTALL_DIR} to your PATH to run 'boatramp'." ;;
	esac
	"${INSTALL_DIR}/${BIN}" --version || true
}

main "$@"
