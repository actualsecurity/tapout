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
- **Active-low ring detection that ignores boot/replug blips** (v2.0.10,
  `tapout/ring_detect.h`). D4 is sampled every 5 ms by a dedicated `esp_timer`,
  so blocking network sends in `loop()` can never hide or split a ring.
  Detection **arms only after the line has read idle for 3 s continuously**, so
  the D4 blip while the board boots, which is what paged the crew on every
  power unplug/replug, can never page. Two modes, set by `ring_mode` (NVS,
  applied live):
  - **`single` (default):** pages once **one** ring has lasted `ring_min_ms`
    (default 500 ms, range 100–1500; a normal ring is ~2 s, so higher could miss every call), i.e. on the **first** ring. The station
    line may ring only once before the call rolls to county dispatch.
    Shorter blips are ignored.
    - Trade-off: a power sag of at least `ring_min_ms` while the board stays
      powered can still page.
  - **`pattern` (opt-in):** pages only on a ring pattern:
    - **(A)** two ring-shaped bursts (0.3–3.5 s) within 8 s, or
    - **(B)** three or more bursts of at least 0.3 s, each within 8 s of the
      previous.
    - A single burst of any length never pages. The cost is the page fires on
      the 2nd ring, and a call that rings only once **doesn't page**.
  - **Setting it:** `curl -u crew:<pass> -d ring_mode=pattern http://<device>/provision`
    (or `ring_min_ms=800`). From v2.1.0, `tapout ring-mode` does the same.
  - **Ignored activity** goes to STATUS as "Line activity ignored (not a ring)",
    at most one attempt per 10 min. It is counted in the heartbeat, the
    status page and `/status.json` (`ignored_line_activity`,
    `line_glitches`). The JSON also shows `ring_mode` and `ring_min_ms`.
  - **One alert per call:** "same call or a new one?" is decided from the
    continuous samples (8 s idle re-arm, 60 s ceiling).
  - **Arming watchdog:** if detection hasn't armed 60 s after boot, STATUS
    gets "Ring detector NOT armed". `/status.json` reports `healthy:false`
    with fault `detector_unarmed`, the dead-man check-in is withheld, and the
    status pill says "Arming".
  - **No reboot wipes a call:** reboots (`/reboot`, OTA staged, OTA rollback)
    are held while a real call is confirmed or in flight.
  - **This is the life-safety path. It is never starved, including during a
    firmware download.**
- **ntfy.sh HTTPS alert** (Pushover template included, commented out).
- **Pre-alert retry latch, with a 2-minute deadline.** A detected ring is
  latched and retried until it is delivered, but only for **2 min after the
  ring**, whether WiFi is down or up with no internet. A later pre-alert is
  useless, because the real dispatch page has gone out by then. A call that
  misses the window is dropped and logged on STATUS as "Pre-alert NOT sent (too
  late)", sent once the network is back.
- **The crew channel only ever carries the standard alert:** "Incoming call on
  the station line at <time the phone rang>". If the first send fails and a
  retry delivers it, the crew still gets exactly that, and STATUS gets "Crew
  alert: first send failed" with the first error code and how late it was.
  v2.0.9 used to change the crew text to "…(alert delayed by network)". A
  firmware gate refuses every other message to the crew topic.
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
| `ntfy_cmd` | `ntfy_cmd` | "" (disabled) | private command topic URL for `tools/tapout` (v2.1.0) |
| `ring_mode` | `ring_mode` | `single` | `single` = page on the 1st ring; `pattern` = only on a 2-ring pattern |
| `ring_min_ms` | `ring_min_ms` | `500` | single mode: page once a ring lasts this long (100–3000) |
| `cmd_interval` | `cmd_interval` | `30` | command-topic poll interval, seconds (15–3600) |

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

## Black box, restart reports & self-heal (v2.0.10)

The unit needed manual reboots a few times on v2.0.9 and nothing recorded why.
Now it does.

**After every restart**, the first thing sent once WiFi is back is a
**"Tapout restarted"** message on STATUS. It goes at **high** priority, titled
"…UNEXPECTEDLY", whenever the restart wasn't requested. It says:

- **Cause:**
  - a **requested** restart, with the reason: OTA update, `/reboot`,
    `/provision`, setup portal, OTA rollback, or self-heal
  - **POWER LOSS:** unplugged, power-cycled, reset button, or the supply cut
    out
  - **BROWNOUT:** the supply sagged
  - **CRASH**
  - **HANG:** the watchdog restarted frozen firmware
- **Downtime:** when the device was last alive, and how long ago that was.
- **Just before:** uptime, WiFi up or down plus signal, the last successful
  send, failures in a row, WiFi drops (with the router's last disconnect
  reason), and free memory, largest block and low-water mark.
- **Recent events:** WiFi lost or back, "no internet while WiFi up", send
  failures, self-heal actions, low memory, calls, restarts.

If the firmware crashed, a second **"Tapout crash report"** gives the task,
crash address and backtrace, then clears the dump. Decode it with the release's
`tapout.ino.elf`, which CI now attaches to every GitHub release:
`xtensa-esp32s3-elf-addr2line -pfiaC -e tapout.ino.elf <addresses>`.

**How it's recorded:** a small flight recorder holds a checkpoint and the last
16 events.

- A copy in RTC memory is refreshed every minute. It survives crashes,
  watchdog resets and software restarts.
- A copy in NVS is written every 5 min and before every requested restart. It
  survives power loss, so the "last sign of life" is accurate to about 5 min
  after a power cut.
- The hourly heartbeat now also shows the WiFi signal, drops since boot and
  the memory low-water mark.
- `/status.json` adds `restart_why`, `wifi_drops`, `last_disconnect_reason`,
  `net_ok_ms_ago`, `net_fail_probes`, `heal_streak` and `crash_dump_pending`.

**Self-heal.** v2.0.9 only reconnected when WiFi reported *disconnected*. If
WiFi stayed "connected" but nothing got through, the watchdog stayed happy and
the unit just went dark. Now:

- Whenever nothing has succeeded for 5 min, it runs a cheap probe (an ntfy
  poll that creates no message).
- **3 failed probes:** it forces a WiFi reconnect.
- **5 failed probes (~25 min):** it reboots.
- **WiFi down for 15 min:** it reboots, backing off to 30, 60 and 120 min if
  the outage continues.
- Each heal is logged and shows up in the next restart report.
- It never self-heals during an OTA download or trial.

**Calls survive a restart, within the 2-minute window.** A real call that was
detected but not yet delivered is saved. After a restart it is sent to the crew
as the standard alert, if it is still under 2 min since the ring. The clock
survives a software or watchdog restart; after a power cut its age is unknown.
Otherwise it is reported on STATUS only.

**Knowing while it's down: the dead-man check-in.** A device that's off can't
report anything, so this needs an outside watcher. The firmware already pings
a URL every 15 min while healthy, and withholds the ping when it's degraded
(WiFi down, detector stuck or unarmed, memory too fragmented). One-time setup:

1. Create a free check at [healthchecks.io](https://healthchecks.io): period
   15 min, grace 15 min.
2. In that check's **Integrations**, add **ntfy** with your STATUS topic. The
   STATUS channel then gets "Tapout is DOWN" within about 30 min of the device
   going quiet, and "UP" when it's back.
3. Give the device the check's ping URL:
   `curl -u crew:<web_pass> -d deadman=https://hc-ping.com/<uuid> http://<device>/provision`.
   No reboot is needed; it takes effect within 15 min.

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

## Remote commands (`tools/tapout`, v2.1.0)

A local CLI that drives the deployed unit from anywhere, over the one path the
IoT VLAN already allows (outbound 443 to ntfy.sh). The device **polls** a private
command topic every `cmd_interval` seconds (default 30) and acknowledges every
command on the **STATUS** topic.

```sh
# one-time setup
tools/tapout init --status-url https://ntfy.sh/<status-topic>   # topic + ECDSA key pair; rewrites tapout/cmd_public_key.h
git add tapout/cmd_public_key.h && git commit -m "cmd key"      # ...then cut a release (the device needs the key compiled in)
tools/tapout provision --device http://<device-ip>              # POST /provision ntfy_cmd (no secrets), reboot
tools/tapout ping                                               # device replies on STATUS

tools/tapout test                                  # [TEST] notification -> STATUS
tools/tapout maint start --minutes 45              # maintenance window, announced on STATUS
tools/tapout maint end                             # "complete, resuming normal operations" on STATUS
tools/tapout send -t "Line work" -m "Tue 0900" [-p low|default|high]   # custom message to STATUS ("announce" works too)
tools/tapout send -m "hello" --url other-topic      # custom message to any other ntfy topic
tools/tapout test --url https://ntfy.sh/other      # [TEST] to any other ntfy topic
tools/tapout set-topic status|cmd <url>             # change a device topic (verified first)
tools/tapout set-topic call <url>                   # STAGE a crew-topic move ([TEST] alert sent there)
tools/tapout confirm-topic call                     # ...activate it once the crew got the [TEST] alert
tools/tapout revert-topic call|status|cmd           # undo the last move (call: staged + confirmed again)
tools/tapout ring-mode single [--min-ms 500]       # page on the 1st ring (default)
tools/tapout ring-mode pattern                     # page only on a 2-ring pattern (asks you to type 'yes')
tools/tapout sim-ring [--to call]                  # same as POST /simulate-ring; --to call = [TEST] alert to the crew
tools/tapout check-ota                             # check GitHub for a signed update now
tools/tapout reboot
tools/tapout watch                                 # tail STATUS
```

Global flags: `--dry-run` (print the signed line, send nothing), `--no-wait`,
`--timeout N`, `-y/--yes` (skip the crew confirmation; required when not on a TTY).

**The crew channel only ever carries the standard ring alert.** Everything else
goes to STATUS, which is the device's log channel: command acks, tests, custom
messages, maintenance notices, and all health and diagnostic detail, including
"first send failed / delivered late".

- **Firmware gate:** `sendNtfy()` refuses the crew CALL topic unless the call
  comes from the ring-alert function itself.
- **Commands:** the device refuses `to=call` for every command except
  `sim-ring --to call`. That is the standard alert, `[TEST]`-labelled, for
  checking the crew's phones, and the CLI makes you type `crew` first.
- **The CLI** never knows the CALL topic URL.

**Other topics and changing topics.** `--url` takes a bare topic name (which
becomes `https://ntfy.sh/<name>`) or a URL of exactly the form
`https://<host>/<topic>`. The topic may use letters, digits, `-` and `_`; ports,
extra path segments, `?query`, `#fragment` and trailing slashes are refused on
both the CLI and the device. The device refuses a `--url` that is its CREW or
command topic. Before comparing, it normalises both URLs: host case, a
`?query`, `#fragment`, `:443` and a trailing slash are all ignored, because ntfy
treats those spellings as the same topic. Titles must be a single line, since they become an HTTP
header.

- **`set-topic status`** sends a `[TEST] Tapout channel check` to the new URL.
  It switches only if that succeeds, keeps the old value as `prev_status` in
  NVS, and acknowledges on the *old* status topic.
- **`set-topic cmd`** test-polls the new inbox before switching, so the device
  can't go deaf.
- For `status` and `cmd`, the CLI requires the device's ack (no `--no-wait`).
  It rewrites `status_url`/`cmd_url` in its config only when the ack says
  `<which> topic changed`.
- **`set-topic call` is two-step.** ntfy accepts a post to *any* topic name, so
  a delivered test can't prove anyone is subscribed. The device only
  **stages** the change: it sends the standard alert, `[TEST]`-labelled, to the
  new URL, keeps real alerts on the current topic, and returns a confirm code.
  - After the crew confirm they got the `[TEST]` alert,
    `tapout confirm-topic call` activates it within 30 min. The code is
    remembered by the CLI.
  - Nothing is posted on the *old* crew topic, since crew channels carry only
    the standard alert. Tell anyone subscribed there to switch.
  - A reboot or a 30-minute timeout cancels the staging.
  - `revert-topic call` goes through the same stage-and-confirm steps.
- The three topics must stay distinct. Moving the crew topic asks you to type
  `crew`; the others ask for `yes`.

**Maintenance mode is informational.** It announces a window, shows a
MAINTENANCE pill on the status page, mentions it in the heartbeat, and
auto-closes with a "complete" notice when it expires. The window is kept in NVS,
so it survives the reboots maintenance usually involves.

- Maintenance notices go to STATUS only. If the end notice is more than 15 min
  late (for example, the device was off), it carries the date.
- Maintenance mode **never suppresses or alters a real ring alert**.

**Security model.** The same asymmetric model as the signed OTA updates. Wire
format and verifier: `tapout/cmd_proto.h`.

- Every command is one line signed with **ECDSA P-256 / SHA-256**, using the
  operator's **private** key. That key lives only at
  `~/.config/tapout/cmd_private_key.pem` (mode 600; back it up). The CLI signs
  with the system `openssl`.
- The device holds only the **public** key, compiled in from
  `tapout/cmd_public_key.h`. That file is committed and not secret, like
  `public_key.h` for OTA.
  - Nothing secret is ever provisioned to or stored on the device, and
    `/provision` only sets the topic.
  - A dumped device can't forge commands.
  - Changing who can command the unit takes a signed firmware release.
- While the header is still the `CHANGE-ME` placeholder, the command channel
  stays **off** (`cmd_key_installed:false` in `/status.json`).
- The signature covers every field, including the destination, so nothing can
  be re-routed to the crew.
- Accepted only if signed within ±5 min of device time (needs NTP) **and** newer
  than every command ever accepted (floor persisted in NVS before executing, so
  a `reboot` can't replay itself after the reboot).
- Unauthentic messages are ignored, with at most one "rejected command" STATUS
  ping per 10 min.
- Knowing the command topic lets someone *read* your commands (ntfy topics are
  public-by-name) and post junk, but not forge one.
- If the private key leaks, run `tapout init --force`, commit the new header and
  cut a release. Until that release is installed, the old key still works.
  `--force` keeps your command topic and moves the old key to
  `cmd_private_key.pem.bak-<timestamp>`.
- `tapout ring-mode single --min-ms N` accepts 100–1500 ms and asks you to
  confirm anything above 1000 ms. A normal ring is about 2 s, so a higher
  threshold could miss every call.
- The device never polls while a call is latched, the line is ringing or just
  rang, during OTA, or on OTA probation. If a real call latches while a batch of
  commands is running, the rest waits for the next poll. A `reboot`, whether
  remote or from the web page, is held until any real call alert has been
  delivered. Each poll is one bounded TLS GET, and
  `handleRing()` runs immediately after it.
- Fully inert until a real public key is compiled in **and** `ntfy_cmd` is
  provisioned. The command topic must differ from the CALL and STATUS topics.

`tools/test_cmd_proto.sh` cross-checks the CLI signer against the device's C
verifier on the host, built against OpenSSL (`brew install openssl@3`). It
covers valid commands, a different key, re-routing, field tampering, the old
HMAC format and the placeholder key.

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
7. **Confirm a real call is detected.** Place a test call and check that it
   pages on the first ring in `single` mode (on the 2nd in `pattern` mode) and
   that STATUS shows **no** "Line activity ignored" note. Then compare `recent_bursts` in `/status.json`: each ring
   should be about 2000 ms long, and consecutive `ago_ms` about 6000 ms apart.
   Do the same after unplugging and replugging the phone cord: it should show
   one burst and an "ignored" note, never a page. The design assumes the
   ELK-930 output *follows the ring cadence*. If it held D4 low for the whole
   call, calls would show up as one long ignored burst instead of paging.
   `tools/test_ring_detect.cpp` replays 30 simulated waveforms on the host:
   `c++ -std=c++17 -o /tmp/trd tools/test_ring_detect.cpp && /tmp/trd`.

## Reliability hardening

Done in firmware: watchdog, hourly heartbeat, WiFi reconnect/backoff, never-lose-
a-call retry latch, persistent ring log, low-heap canary, RGB status, **signed
OTA + health-gated auto-rollback**. Still recommended at the install:

- **Power backup** — run the ESP32 from a USB battery / small UPS.
- **Offline fallback (optional)** — cellular module (SIM7600/SIM800 + SIM) for
  SMS independent of WiFi if building internet is unreliable.

**Keep the bell primary. This device is the convenience layer, not the lifeline.**
