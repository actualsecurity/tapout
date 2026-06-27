# Tapout

An always-on ESP32 device that detects when the station POTS line rings and
pushes a notification to crew phones. **Secondary/convenience layer only — the
hard-wired fire bell stays primary.** The device always boots to a working ring
alerter even if NTP, the web page, OTA, mDNS, and provisioning all fail.

**Firmware: v2.0.9**

## What's new in v2.0.0

v2.0.0 keeps every v1.2.1 behavior (see [Features](#features-carried-from-v110v121))
and adds three things so the device can update itself safely over the internet:

1. **Secrets moved out of the compiled image into NVS.** The published `.bin`
   ships only `CHANGE-ME` placeholders, so it is **secret-free** and can live in
   a **public** repo. Real WiFi/ntfy/password values live in the NVS namespace
   `fhacfg` and are loaded at boot. See [Provisioning](#provisioning-secrets-in-nvs).
2. **First-boot SoftAP setup portal + network `/provision`.** Fresh units boot a
   captive-portal AP (`tapout-setup`) to enter secrets; already-deployed units
   can be re-provisioned over the LAN with an authed `POST /provision`. See
   [Provisioning](#provisioning-secrets-in-nvs).
3. **Signed, fully-automatic GitHub pull-OTA with health-gated auto-rollback.**
   The device polls a GitHub-hosted `manifest.json` on a schedule, downloads a
   **cryptographically signed** image, refuses anything that doesn't verify
   against the embedded public key, flashes it, and **automatically reverts** if
   the new image can't prove itself healthy within ~60 s. See
   [Signed pull-OTA](#signed-pull-ota-the-update-pipeline).

> **Why this design:** the device lives on an isolated IoT VLAN where the old
> ArduinoOTA reverse connection is blocked cross-VLAN, so reflashing was painful.
> Pull-OTA flips the direction — the device reaches **out** over the one thing the
> VLAN reliably allows (outbound 443) — and firmware **signing** plus
> **auto-rollback** make pulling executable code from the internet safe for a
> life-safety device.

## Hardware

| Part | Role |
|------|------|
| Arduino Nano ESP32 (ABX00083, ESP32-S3) | Reads detector, sends notifications over WiFi |
| ELK-930 Doorbell & Telephone Ring Detector | Isolates the phone line, outputs a clean ring signal |
| Existing POTS line + hard-wired fire bell | Unchanged |

## Wiring

```
Phone line (tip/ring) ──> ELK-930 telephone INPUT terminals
ELK-930 OUT ───────────> Nano ESP32 D4   (active-low, internal pull-up)
ELK-930 NEG ───────────> Nano ESP32 GND
Nano ESP32 powered via USB-C
```

Idle = HIGH; during a ring the ELK-930 pulls D4 LOW. ELK-930 telephone output
is rated 40 mA @ 12 V max; we drive D4 at 3.3 V, well within range. No high
voltage reaches the ESP32.

> **Pin gotcha:** always use the label `D4`, never a bare `4`. The label
> resolves correctly regardless of *Tools > Pin Numbering*; a bare integer
> points at the wrong physical pin. Leave Pin Numbering at its default.

## Features (carried from v1.1.0/v1.2.1)

These all still work in v2.0.0 and run **before** any of the new code each loop:

- **WiFi connect + non-blocking reconnect** with exponential backoff.
- **Active-low ring detection** — 25 ms debounce, 60 s cooldown ceiling, and an
  8 s idle re-arm so one call's ring cadence collapses to a single alert while
  two genuinely distinct calls each page. **This is the life-safety path and runs
  first every loop — never starved, including during a firmware download.**
- **ntfy.sh HTTPS alert** (Pushover template included, commented out).
- **Never-lose-a-call retry latch** — a detected ring is latched and retried
  until delivered; if delivery ultimately fails it surfaces a failure notice on
  the STATUS topic. Retries are *not* burned while WiFi is down.
- **NTP wall-clock timestamps** on CALL alerts (graceful uptime fallback).
- **mDNS + LAN status web page** at `http://tapout.local`, with a
  `/status.json` endpoint and auth-gated reboot / send-test / simulate actions.
- **Persistent NVS ring log** — rolling log of the last 20 ring events, survives
  reboots and brownouts.
- **Boot-count + reset-reason + heap telemetry** in the restart ("online") ping.
- **Boot-time D4 self-test** — warns on the STATUS topic if the detector reads
  active at startup.
- **Low-heap / fragmentation canary**, **chunk-streamed** web/JSON (heap-frag
  hardening), `tls_ready` / `largest_free_block` / `min_free_heap` telemetry.
- **Dead-man's switch** (`serviceDeadman()`) — alert-on-absence check-in that
  withholds its ping when the device is degraded.
- **`real_calls_delivered`** lifetime NVS counter — increments only on a genuine
  delivered CALL alert (stays `0` through every simulation).
- **Simulated-ring test endpoint** (`POST /simulate-ring`) — drives the real
  pipeline to the STATUS topic, tagged `[SIM]`, without paging the crew.
- **Hardware task watchdog** (`esp_task_wdt`, 30 s) fed every loop and during
  long operations (including the OTA download).
- **Hourly heartbeat** ping and **onboard RGB status LED**.

### RGB status LED (onboard, active-low)

| Color | Meaning |
|-------|---------|
| Blue | Booting |
| Green | WiFi up / idle |
| Red | Ring detected |
| Yellow | Error / WiFi offline |
| Magenta | OTA in progress (download/flash) |

---

## Provisioning (secrets in NVS)

In v2.0.0 the firmware no longer carries real secrets. At boot, `loadConfig()`
reads the NVS namespace **`fhacfg`** into a runtime struct; any field that is
missing falls back to the `CHANGE-ME` compiled placeholder. A unit is considered
**provisioned** only when a real (non-placeholder) WiFi SSID is present. There
are two ways to write the NVS config.

### A. First-boot SoftAP setup portal (fresh units)

If the device is **not provisioned**, it does **not** join WiFi as a station.
Instead it starts an open SoftAP captive portal and waits for setup:

1. Power the device. It brings up WiFi AP **`tapout-setup`** at
   `http://192.168.4.1` (captive DNS catch-all redirects any host to the form).
2. Join `tapout-setup` from a phone/laptop; the setup form opens.
3. Fill in WiFi SSID/password, the ntfy CALL and STATUS URLs, the web-admin and
   OTA passwords, timezone, NTP server(s), optional dead-man URL, the OTA
   manifest URL, **Enable auto pull-OTA? (1/0)**, and the OTA check interval
   (minutes, default 360 = 6 h).
4. Submit. The device writes NVS, marks itself provisioned, and reboots into
   normal station mode.

The ring-detection path stays armed even in setup mode (ntfy delivery is simply
suppressed while WiFi isn't connected). Password fields are **write-only** — the
form never echoes a stored secret.

### B. Authed network `POST /provision` (deployed units — migration)

Once a unit is on the LAN in normal mode, you can write/patch NVS over the
network without a USB cable or SoftAP. This is the migration path for the
already-deployed unit.

```
curl -u crew:<webpass> -X POST 'http://<device-ip>/provision' \
  -d 'wifi_ssid=<your-2.4GHz-ssid>' \
  -d 'wifi_pass=<wifi-key>' \
  -d 'ntfy_call=https://ntfy.sh/<call-topic>' \
  -d 'ntfy_status=https://ntfy.sh/<status-topic>' \
  -d 'web_pass=<new-web-pass>' \
  -d 'ota_pass=<new-ota-pass>' \
  -d 'tz=EST5EDT,M3.2.0,M11.1.0' \
  -d 'ota_manifest=https://raw.githubusercontent.com/<org>/tapout/main/ota/manifest.json' \
  -d 'ota_enabled=1' \
  -d 'ota_interval=360'
```

Both the portal and `/provision` funnel through one writer: **only fields that
are present in the request are written**, so you can patch a single value
(e.g. rotate the WiFi key) without resending everything. Add `-d 'reboot=1'` to
reboot after saving (the reply flushes first). `/provision` requires the same
HTTP Basic Auth as the other admin endpoints and never echoes secrets back.

### NVS config fields

| Field (form / `-d` key) | NVS key | Default placeholder | Notes |
|---|---|---|---|
| `wifi_ssid` / `wifi_pass` | `wifi_ssid` / `wifi_pass` | `CHANGE-ME` / "" | IoT-VLAN WiFi creds |
| `ntfy_call` | `ntfy_call` | `https://ntfy.sh/CHANGE-ME` | crew CALL topic |
| `ntfy_status` | `ntfy_status` | `https://ntfy.sh/CHANGE-ME` | monitoring STATUS topic |
| `web_user` / `web_pass` | `web_user` / `web_pass` | `crew` / `CHANGE-ME` | Basic Auth for admin endpoints |
| `ota_pass` | `ota_pass` | `CHANGE-ME` | ArduinoOTA (attended LAN reflash) password |
| `tz` | `tz` | `EST5EDT,M3.2.0,M11.1.0` | POSIX TZ; handles DST |
| `ntp1` / `ntp2` / `ntp3` | `ntp1`..`ntp3` | gateway IP / `pool.ntp.org` / `time.nist.gov` | set `ntp1` to the VLAN gateway IP |
| `deadman` | `deadman` | "" (disabled) | dead-man check-in URL |
| `ota_manifest` | `ota_manifest` | "" (disabled) | raw GitHub manifest URL |
| `ota_enabled` | `ota_enabled` | `false` | `1` = auto pull-OTA on |
| `ota_interval` | `ota_interval` | `360` | manifest poll interval, minutes |

> **Security by default (fail closed):** while `web_pass` or `ota_pass` is still
> the shipped `CHANGE-ME` placeholder, the matching feature stays **DISABLED** —
> ArduinoOTA will not arm and the admin reboot/send-test/provision actions return
> 403, with a one-shot warning to the STATUS topic. The read-only status page and
> mDNS still work. Auto pull-OTA additionally stays off until the device is
> provisioned, `ota_enabled=1`, a real manifest URL is set, **and** a real signing
> public key is compiled in (placeholder key = OTA disabled).

---

## Signed pull-OTA (the update pipeline)

### How it works (happy path)

1. Every `ota_interval` minutes the device runs `otaCheckManifest()`: a bounded
   HTTPS GET of `ota_manifest`. It parses `{version, url, size, sha256,
   min_supported, notes}`.
2. **Version gate (anti-downgrade):** the update is accepted only if
   `version > FW_VERSION` **and** `FW_VERSION >= min_supported`. (The anti-rollback
   eFuse is **off**, so monotonicity is enforced in firmware.)
3. **Pre-flight safety gate (`otaSafeToStart()`):** refuses to start if a call is
   pending/in-flight, if D4 is active right now or within the re-arm window, if
   WiFi isn't solid, if the largest contiguous heap block is below the TLS
   threshold, or if there is no good fallback slot to roll back to.
4. **Download + verify (`otaDownloadAndFlash()`):** streams the **signed** `.bin`
   over `WiFiClientSecure` (with `setInsecure()` and redirect-follow for the
   GitHub release-asset → CDN hop). It calls `Update.installSignature(&g_verifier)`
   **before** `Update.begin(totalSize)` (size = firmware **+ 512-byte signature**),
   and feeds the watchdog and pumps `handleRing()` on every chunk so the
   life-safety path is never starved during a multi-MB flash.
5. **RAIL A — signature gate:** `Update.end()` performs the SHA-256 + RSA-PSS
   verification against the embedded public key. A bad/forged image fails here
   (`UPDATE_ERROR_SIGN`), is **never made bootable**, the running image is
   untouched, and an "OTA REJECTED" notice goes to the STATUS topic.
6. On success the device records a "pending" marker in NVS and **reboots itself**
   into the new image on trial.

### Safety rails

**RAIL A — Firmware signing.** Built with `build_opt.h` containing `-DUPDATE_SIGN`,
which compiles in the core-native RSA-PSS verifier. The running firmware embeds
the **public** key (`public_key.h`); the **private** key signs builds in CI and
exists only as a GitHub Actions secret — never in the repo. A MITM on port 443
cannot push firmware without that private key. Trust is anchored by the signature,
**not** the TLS transport (which stays `setInsecure()` because that's the only
thing the IoT VLAN reliably allows).

**RAIL B — Health-gated auto-rollback.** A freshly flashed image boots in
`ESP_OTA_IMG_PENDING_VERIFY`. `otaCheckProbationOnBoot()` (early in `setup()`)
detects this and starts a ~60 s trial. `otaServiceProbation()` (in `loop()`,
after ring handling) requires **WiFi up AND able to reach ntfy** within the
window:
- healthy → `esp_ota_mark_app_valid_cancel_rollback()` commits the image and
  posts "OTA committed" to STATUS;
- not healthy in time → `esp_ota_mark_app_invalid_rollback_and_reboot()`
  **automatically reverts** to the previous good slot and posts "OTA ROLLBACK".

The health gate deliberately excludes NTP/web/mDNS so a genuinely working image
can never false-revert. **Belt-and-suspenders:** if a bad image hangs *before*
probation runs, the bootloader/task watchdog resets it while still
PENDING_VERIFY and the bootloader auto-reverts. The old slot is never erased, so
re-rollback always remains possible. A bad auto-update can never take the alerter
offline or brick it.

**No update during a call.** Ring handling runs first every loop; `otaSafeToStart()`
refuses while a call is latched/in-flight or the line is active, and the download
loop itself keeps pumping `handleRing()`.

### Where to watch it

`/status.json` exposes (no secrets): `fw_version`, `ota_enabled`, `provisioned`,
`running_partition`, `on_probation`, `ota_pending_version`,
`last_ota_check_ms_ago`, and `rollback_possible`. STATUS-topic pings narrate the
lifecycle: staged → committed / rolled-back / rejected / skipped.

> **CRITICAL — never esptool-flash a `.signed.bin`.** The signed image is for
> **OTA only** (it carries the 512-byte signature trailer the verifier expects).
> For USB/serial recovery use the **unsigned** `tapout.ino.bin`,
> which CI also publishes.

---

## Repo, manifest & CI setup

The repo root is published to a **public** GitHub org repo. Layout:

```
tapout/
  tapout.ino     # the one sketch (v2.0.0)
  build_opt.h                  # one line: -DUPDATE_SIGN  (enables signature verify)
  public_key.h                 # COMMITTED public key (not a secret); placeholder until generated
  config.example.h             # documents NVS fields + a sample /provision curl (no secrets)
ota/
  manifest.json                # the LIVE manifest the device fetches (raw on main)
  manifest.example.json        # template
tools/
  sign_firmware.sh             # wrapper around the core's bin_signing.py
  keygen.md                    # one-time keygen + secret-setup instructions
.github/workflows/firmware.yml # build → sign → release → update manifest
.gitignore                     # excludes private_key.pem / *.pem (keeps public_key.*)
```

### One-time key generation

```
python <CORE>/tools/bin_signing.py --generate-key rsa-2048 --out private_key.pem
python <CORE>/tools/bin_signing.py --extract-pubkey private_key.pem --out public_key.pem
cp public_key.h tapout/public_key.h   # overwrites the placeholder
```

where `<CORE>` is `~/Library/Arduino15/packages/esp32/hardware/esp32/3.3.10`.
Commit the generated `public_key.h` (a public key is not secret). Put the
**contents of `private_key.pem`** into the GitHub Actions secret
**`OTA_SIGNING_KEY`** and **never commit it**. Until `public_key.h` is replaced,
the firmware fail-closes: it detects the placeholder marker and keeps OTA
**disabled**.

### `manifest.json`

The device fetches this raw from `main`. Shape:

```json
{
  "version": "2.0.1",
  "url": "https://github.com/<org>/tapout/releases/download/v2.0.1/tapout.signed.bin",
  "size": 1389056,
  "sha256": "<hex sha256 of the signed .bin>",
  "min_supported": "2.0.0",
  "notes": "Health-gated; auto-rolls back if unhealthy within 60s."
}
```

`size` must be the byte count of the **signed** `.bin` (firmware + 512-byte
signature). `min_supported` blocks dangerous version skips.

### CI (`.github/workflows/firmware.yml`)

Triggers on `push` of a `v*` tag and on manual `workflow_dispatch`:

1. Checkout; install `arduino-cli`; `arduino-cli core install esp32:esp32@3.3.10`.
2. `pip install cryptography`.
3. `arduino-cli compile --fqbn esp32:esp32:nano_nora --export-binaries
   ./tapout` (picks up `build_opt.h` automatically) →
   `tapout.ino.bin`.
4. Write the private key from the secret: `echo "$OTA_SIGNING_KEY" > private_key.pem`.
5. Sign → `tapout.signed.bin` via the core's `bin_signing.py`.
6. `sha256sum` the signed file and write `ota/manifest.json` (version from the
   tag, release-asset URL, size, sha256, min_supported, notes).
7. `gh release create` uploading **both** the `.signed.bin` (OTA) and the
   unsigned `.ino.bin` (serial recovery).
8. Commit the updated `ota/manifest.json` back to `main` so the raw URL the device
   polls reflects the new release. `rm -f private_key.pem` always.

### How to cut a release

1. Bump `FW_VERSION` in the sketch (line ~215) — must be **strictly greater** than
   what's deployed, or the device's anti-downgrade gate rejects it.
2. Commit, then tag: `git tag v2.0.1 && git push origin v2.0.1`.
3. CI compiles, signs, publishes the release, and updates `ota/manifest.json`.
4. Within one `ota_interval`, provisioned units with `ota_enabled=1` pull the
   signed image, verify it, flash, and either commit (healthy) or auto-roll-back.

---

## Build / flash via arduino-cli

```
arduino-cli compile \
  --fqbn esp32:esp32:nano_nora \
  --output-dir build \
  tapout
```

The **first** flash of a fresh unit is over **USB**:

```
arduino-cli upload -p /dev/cu.usbmodemXXXX \
  --fqbn esp32:esp32:nano_nora tapout
```

Requires the **esp32 by Espressif** core **v3.3.10**. No extra libraries —
`WiFi`, `WiFiClientSecure`, `HTTPClient`, `Update`, `esp_ota_ops`, `SHA2Builder`,
`esp_task_wdt`, `ArduinoOTA`, `ESPmDNS`, `WebServer`, `DNSServer`, and
`Preferences` all ship with the core. Leave *Pin Numbering* at its default.

> A freshly USB-flashed **secret-free** unit boots straight into the SoftAP setup
> portal (no NVS secrets yet) — that's expected. Provision it (portal or, after
> it's on the LAN, `/provision`) to bring it online.

---

## Web status page

Reachable on the LAN at **`http://tapout.local`** (or the device IP)
once WiFi is up and inbound TCP 80 is permitted.

> **Operational note — prefer the IP:** mDNS `.local` resolution is slow/flaky
> right after a reboot and across VLANs. For anything that matters use the
> device's **IP with a DHCP reservation**. Treat `.local` as a convenience.

- **`GET /`** — auto-refreshing human status page: time, uptime, rings, last ring,
  WiFi SSID/IP/RSSI, heap, boot count, reset reason, heartbeat timing, firmware
  build, OTA/provisioning state, and the persistent recent-rings log. Shows a
  SECURITY banner while default passwords are in place. No secrets exposed.
- **`GET /status.json`** — machine-readable, `Cache-Control: no-store`, streamed in
  chunks. Includes the v1.2.x telemetry plus the v2.0.0 OTA fields listed above.
- **`POST /send-test`** — test alert to the **STATUS** topic (never pages crew). Auth.
- **`POST /simulate-ring`** — injects a simulated ring through the real pipeline to
  STATUS, `[SIM]`-tagged; 409 if a real CALL is in flight; never increments
  `real_calls_delivered`. A deliberate commissioning page to the CALL topic is
  double-gated via `?topic=call&confirm=<web-pass>`. Auth.
- **`POST /provision`** — write/patch NVS config (see [Provisioning](#b-authed-network-post-provision-deployed-units--migration)). Auth.
- **`POST /reboot`** — deferred reboot so the reply flushes first. Auth.

POST actions use **HTTP Basic Auth** (`web_user` default `crew` / `web_pass`).

---

## Firewall rules (isolated IoT VLAN)

Outbound TCP 443 to ntfy.sh is required for the core alert path. **For pull-OTA,
add outbound TCP 443 to the GitHub hosts** below. Every other feature degrades
gracefully if its rule is missing.

| Direction | Port / proto | Endpoint | Purpose | Status |
|-----------|--------------|----------|---------|--------|
| Outbound | TCP 443 | ntfy.sh (`159.203.148.75`) | **Ring alerts (required)** | Confirmed working |
| Outbound | TCP 443 | `raw.githubusercontent.com` | **Pull-OTA manifest** | Add for OTA |
| Outbound | TCP 443 | `github.com`, `objects.githubusercontent.com` | **Pull-OTA signed `.bin`** (release asset 302 → CDN) | Add for OTA |
| Outbound | TCP 443 | `codeload.github.com` | GitHub asset/CDN path (optional) | Add for OTA |
| Outbound | UDP 53 | VLAN DNS resolver | **Required** — ntfy and all GitHub hosts resolve first | Confirmed working |
| Outbound | UDP 123 | NTP servers | NTP wall-clock sync | Confirmed working |
| Inbound | TCP 80 | Device | Web status page / `/status.json` / admin POSTs | Confirmed working |
| Inbound | TCP 3232 (+ reverse high-port) | Device ⇄ flashing host | ArduinoOTA (attended LAN reflash only) | Same-VLAN only |
| Bidir | UDP 5353 | mDNS / reflection | `.local` name across VLANs | Optional |

> DNS (UDP 53) is required for **alerts and OTA**, not just NTP — if DNS is
> blocked, both the CALL send and the manifest fetch fail after a timeout. **No
> inbound rule is needed for pull-OTA** (the device reaches out); the old
> ArduinoOTA reverse connection can stay blocked cross-VLAN.

---

## Notifications

Two ntfy topics, so real calls don't get lost in monitoring noise:

| Topic | Receives | Who subscribes |
|-------|----------|----------------|
| `ntfy_call` | **Real ring alerts only** (max priority, timestamped) | the crew |
| `ntfy_status` | Boot/restart pings, hourly heartbeat, errors, canary warnings, **OTA lifecycle** (staged/committed/rolled-back/rejected) | whoever monitors uptime |

- **Default: ntfy.sh** — HTTPS POST to `https://ntfy.sh/<topic>`; subscribe in the
  free ntfy app. The hourly heartbeat on the status topic is the silent-failure
  canary — if it stops, the device is offline.
- **Alternative: Pushover** — emergency priority 2 re-alerts until acked; a
  commented `sendPushover()` template is at the bottom of the sketch.

TLS uses `setInsecure()` (skips cert validation) — a deliberate trade-off so a
Let's Encrypt rotation can't fail the CALL path closed; outbound 443 to ntfy is
pinned to its single IP. **For OTA, authenticity does not rely on TLS at all** —
it relies on the embedded signing key (RAIL A). If you suspect tampering on the
alert path, rotate the `ntfy_*` topics via `/provision`.

## Security notes

- **Published `.bin` is secret-free.** It ships only `CHANGE-ME` placeholders;
  real secrets live in NVS `fhacfg`. Safe for a public repo.
- **Private signing key never in the repo.** It lives only in the GH Actions
  secret `OTA_SIGNING_KEY`. `public_key.h` / `public_key.pem` are intentionally
  tracked; `.gitignore` excludes `private_key.pem` / `*.pem`.
- **Web Basic Auth is plaintext.** Acceptable only because traffic stays on the
  isolated LAN. **Never expose port 80 to the internet**; provision and use admin
  actions only from a trusted same-VLAN host. The portal and `/provision` are
  **write-only** — secrets are never echoed on the page or in `/status.json`.
- **Rotate the placeholder passwords** (`web_pass`, `ota_pass`) during
  provisioning — features stay disabled while they are `CHANGE-ME`.
- **No secrets on the web page.** Status page and JSON expose only the WiFi SSID
  name — never the WiFi key, ntfy topics, OTA URL, or passwords.

## Test & verify before relying on it

1. **Measure loaded line voltage** during a real ring (multimeter on AC volts
   across tip/ring, ~2 s window) — confirm it exceeds the ELK-930's ~50 V trigger
   with the bell loading the line. *Treat the line as live/hazardous.*
2. **Confirm D4 pulls LOW** with `d4_pin_test` (or watch the boot self-test).
3. **Confirm the notification arrives** on every subscribed crew phone.
4. **Check the web page** shows "Idle — armed", the correct time, and
   `"provisioned":true`.
5. **Dry-run an OTA** — cut a `v*` release, watch `/status.json` for
   `on_probation`/`running_partition` to flip and a "committed" STATUS ping;
   confirm a deliberately-unhealthy build auto-rolls-back.
6. **Tune the cooldown / re-arm** if a single call yields more/fewer alerts than
   wanted.

## Reliability hardening

Done in firmware: watchdog, hourly heartbeat, WiFi reconnect/backoff, never-lose-
a-call retry latch, persistent ring log, low-heap canary, RGB status, **signed
OTA + health-gated auto-rollback**. Still recommended at the install:

- **Power backup** — run the ESP32 from a USB battery / small UPS.
- **Offline fallback (optional)** — cellular module (SIM7600/SIM800 + SIM) for
  SMS independent of WiFi if building internet is unreliable.

**Keep the bell primary. This device is the convenience layer, not the lifeline.**
