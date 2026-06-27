# Firmware-signing key setup (RAIL A)

Tapout only flashes pull-OTA images whose RSA-2048 / RSA-PSS /
SHA-256 signature verifies against the **public key embedded in the running
firmware** (`tapout/public_key.h`). The matching **private key**
signs builds in CI and must **never** be committed.

- **public key** -> committed to the repo as `tapout/public_key.h`
  (a public key is not a secret). OTA stays **disabled** while that file is the
  shipped placeholder (it contains the literal `CHANGE-ME`).
- **private key** -> lives **only** in the GitHub Actions secret
  `OTA_SIGNING_KEY`. It is `.gitignore`d locally as `private_key.pem`.

Use the esp32 core's `bin_signing.py` so the on-device verifier
(`UpdaterRSAVerifier(PUBLIC_KEY, PUBLIC_KEY_LEN, HASH_SHA256)`) and the signing
side agree byte-for-byte.

```
CORE="$HOME/Library/Arduino15/packages/esp32/hardware/esp32/3.3.10"
```

## 1. Generate the keypair (one time)

```sh
# RSA-2048 private key
python3 "$CORE/tools/bin_signing.py" --generate-key rsa-2048 --out private_key.pem
```

OpenSSL equivalent (interchangeable — same PEM):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
```

## 2. Derive the public key + the C header

```sh
python3 "$CORE/tools/bin_signing.py" --extract-pubkey private_key.pem --out public_key.pem
```

That command writes **two** files next to `--out`:
- `public_key.pem` — the PEM public key, and
- `public_key.h` — a C header defining
  `const uint8_t PUBLIC_KEY[] PROGMEM = { ... };` and
  `const size_t PUBLIC_KEY_LEN = ...;`  (this is what the firmware `#include`s).

Copy the generated header into the sketch (overwrites the placeholder):

```sh
cp public_key.h tapout/public_key.h
git add tapout/public_key.h
git commit -m "Add real OTA signing public key (enables signed pull-OTA)"
```

> The shipped `public_key.h` placeholder contains `CHANGE-ME`, which makes the
> firmware's `looksLikePlaceholder()` gate keep OTA **off**. Replacing it with a
> real key is what arms RAIL A. The CI workflow refuses to publish while the
> placeholder is still present.

## 3. Store the private key as the GitHub Actions secret

Settings -> Secrets and variables -> Actions -> **New repository secret**:

- **Name:** `OTA_SIGNING_KEY`
- **Value:** the **entire** contents of `private_key.pem`, including the
  `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----` lines.

```sh
# convenience (GitHub CLI):
gh secret set OTA_SIGNING_KEY < private_key.pem
```

Then **destroy or vault** your local copy:

```sh
# keep it in a password manager / HSM, or:
rm -P private_key.pem    # macOS secure delete (Linux: shred -u private_key.pem)
```

## 4. (optional) Verify a signed build locally

```sh
tools/sign_firmware.sh build_out/tapout.ino.bin private_key.pem build_out/tapout.signed.bin
python3 "$CORE/tools/bin_signing.py" --verify build_out/tapout.signed.bin --pubkey public_key.pem
```

## Rules

- **Never commit** `private_key.pem` (or any `*.pem` except `public_key.pem`) —
  `.gitignore` enforces this.
- **Never esptool-flash** a `*.signed.bin` — it carries a 512-byte signature
  trailer and is only valid through `Update.*`. Flash the plain `*.ino.bin` for
  serial recovery.
- If the private key is ever exposed, generate a new keypair, ship the new
  `public_key.h` via an **attended/serial** reflash first (a rotated public key
  can't be delivered by an OTA the old key signed), then rotate `OTA_SIGNING_KEY`.
