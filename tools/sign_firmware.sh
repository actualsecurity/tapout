#!/usr/bin/env sh
# =============================================================================
# sign_firmware.sh -- sign a compiled tapout image with the
# esp32 Arduino core's bin_signing.py (RSA-PSS / SHA-256 -> 512-byte trailer).
#
# This is the LOCAL equivalent of the "Sign firmware" step in
# .github/workflows/firmware.yml. CI is the normal path; use this for an
# attended/manual signed build.
#
# Usage:
#   tools/sign_firmware.sh <firmware.ino.bin> <private_key.pem> <out.signed.bin>
#
# Example (after `arduino-cli compile --export-binaries --output-dir build_out`):
#   tools/sign_firmware.sh \
#       build_out/tapout.ino.bin \
#       private_key.pem \
#       build_out/tapout.signed.bin
#
# Publish the .signed.bin as the OTA asset and put its sha256/size into
# ota/manifest.json. NEVER esptool-flash a .signed.bin (the 512-byte trailer
# is not a valid app image for the serial bootloader) -- flash the plain
# .ino.bin for serial recovery instead.
#
# -----------------------------------------------------------------------------
# ONE-TIME KEY SETUP (see tools/keygen-instructions.md for the full writeup):
#
#   # Option A -- esp32 core tool (matches the firmware verifier exactly):
#   CORE="$HOME/Library/Arduino15/packages/esp32/hardware/esp32/3.3.10"
#   python3 "$CORE/tools/bin_signing.py" --generate-key rsa-2048 --out private_key.pem
#   python3 "$CORE/tools/bin_signing.py" --extract-pubkey private_key.pem --out public_key.pem
#   #   ^ this ALSO writes public_key.h next to public_key.pem
#   cp public_key.h tapout/public_key.h   # commit this (public key is not secret)
#
#   # Option B -- equivalent with openssl (RSA-2048):
#   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
#   openssl rsa -in private_key.pem -pubout -out public_key.pem
#   #   then derive public_key.h with the core tool so the byte format matches:
#   python3 "$CORE/tools/bin_signing.py" --extract-pubkey private_key.pem --out public_key.pem
#
#   Put private_key.pem's FULL CONTENTS into the GitHub Actions secret
#   OTA_SIGNING_KEY. NEVER commit private_key.pem (.gitignore blocks it).
# =============================================================================
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <firmware.ino.bin> <private_key.pem> <out.signed.bin>" >&2
  exit 2
fi

BIN="$1"
KEY="$2"
OUT="$3"

# Default to the locally-installed esp32 core 3.3.10 (override with CORE=...).
CORE="${CORE:-$HOME/Library/Arduino15/packages/esp32/hardware/esp32/3.3.10}"
SIGNER="$CORE/tools/bin_signing.py"

if [ ! -f "$SIGNER" ]; then
  echo "error: bin_signing.py not found at $SIGNER" >&2
  echo "       set CORE=/path/to/esp32/hardware/esp32/3.3.10 and retry" >&2
  exit 1
fi

python3 "$SIGNER" --bin "$BIN" --key "$KEY" --out "$OUT" --hash sha256

# Best-effort: verify the signature with the public half of the key.
PUB="$(mktemp)"
trap 'rm -f "$PUB"' EXIT
python3 "$SIGNER" --extract-pubkey "$KEY" --out "$PUB" >/dev/null 2>&1 || true
python3 "$SIGNER" --verify "$OUT" --pubkey "$PUB" || {
  echo "error: signed image failed self-verify" >&2
  exit 1
}

echo "signed: $OUT"
echo "size:   $(wc -c < "$OUT") bytes"
echo "sha256: $( (sha256sum "$OUT" 2>/dev/null || shasum -a 256 "$OUT") | cut -d' ' -f1)"
