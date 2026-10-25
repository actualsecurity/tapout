/*
 * Tapout
 * -------------------------------------------------------------------------
 * Detects when the station POTS line rings (via an ELK-930 ring detector)
 * and sends a push notification to crew phones over WiFi (ntfy.sh by default).
 *
 * THIS IS A SECONDARY / CONVENIENCE LAYER. The physical fire bell remains the
 * primary alert. This device must never be the only thing between a call and
 * the crew. The ring-detection path and watchdog feeding take priority over
 * every optional subsystem below; the device always boots to a working ring
 * alerter even if NTP, web, OTA and mDNS all fail.
 *
 * Board:  Arduino Nano ESP32 (ABX00083, ESP32-S3)
 * Core:   esp32 by Espressif (Boards Manager) -- v3.x assumed
 * Wiring: ELK-930 OUT -> D4 (active-low, internal pull-up)
 *         ELK-930 NEG -> GND
 *         Powered via USB-C
 *
 * IMPORTANT (Nano ESP32 pin gotcha):
 *   Always reference the pin as D4 -- the printed label -- never a bare `4`.
 *   The label resolves correctly regardless of Tools > Pin Numbering; a bare
 *   integer points at the wrong physical pin. Leave Pin Numbering at default.
 *
 * Features:
 *   - WiFi connect + non-blocking reconnect with exponential backoff
 *   - ELK-930 active-low ring detection, sampled every 5 ms off-loop, armed only
 *     after 3 s of idle line (boot/replug blips never page). ring_mode=single
 *     (default) pages once a ring lasts ring_min_ms (500 ms) -- the 1st ring;
 *     ring_mode=pattern pages only on a 2-ring pattern. One alert per call.
 *   - ntfy.sh HTTPS alert (Pushover alternative included, commented out)
 *   - NEVER-LOSE-A-CALL: a ring is latched + retried until delivered (or it
 *     surfaces a delivery-failure on the STATUS topic) so a WiFi/ntfy blip
 *     can't silently drop a real call
 *   - NTP wall-clock time (graceful uptime fallback) -> timestamped CALL alerts
 *   - Boot "online" ping now reports boot count + last reset reason + free heap
 *   - Boot-time D4 self-test (warns if the detector reads active at startup)
 *   - Persistent (NVS) rolling ring-event log that survives reboots/brownouts
 *   - Low-heap canary warning on the STATUS topic
 *   - ArduinoOTA WiFi reflash (password-protected, watchdog-safe, LED feedback)
 *   - ESPmDNS + LAN status web page (http://tapout.local) with a
 *     /status.json endpoint and auth-gated reboot / send-test actions
 *   - Hardware task watchdog (esp_task_wdt) with periodic feed
 *   - Hourly heartbeat ping (now carries a monotonic heartbeat_seq + largest
 *     free block) so silent failures and a fragmenting heap are both detectable
 *   - Onboard RGB LED status (boot / connected / ring / error / OTA)
 *   - Auth-gated SIMULATED-ring endpoint (POST /simulate-ring) that drives the
 *     REAL ring->NVS-log->latch->CALL/ntfy->web pipeline so it can be proven
 *     remotely; sims go to the STATUS topic + are tagged [SIM] and NEVER count
 *     as a real delivered call (separate lifetime real_calls_delivered counter)
 *   - Heap-fragmentation hardening: status JSON is fully streamed (no large
 *     String), and largest_free_block / min_free_heap / tls_ready are exposed
 *     so the contiguous block each mbedTLS CALL handshake needs is watchable
 *   - Dead-man's-switch: optional pull-based check-in to an external uptime
 *     monitor, WITHHELD when the device is degraded, so silence becomes the
 *     alarm; plus a machine-checkable "healthy" verdict + "faults" list in JSON
 *
 * NETWORK / FIREWALL (the IoT VLAN -- currently ONLY outbound TCP 443 to
 * ntfy.sh is allowed). Each optional feature degrades gracefully if its port
 * is still blocked. Rules the user must add to fully enable everything:
 *   - ntfy ALERTS ....... OUTBOUND TCP 443 to ntfy.sh (159.203.148.75, already
 *                         allowed) PLUS OUTBOUND UDP 53 to the VLAN DNS resolver
 *                         (e.g. 192.168.10.1). EVERY ntfy send resolves the name
 *                         'ntfy.sh' first, so if DNS is blocked the CALL alert
 *                         itself fails after a multi-second timeout. This UDP 53
 *                         rule is REQUIRED for the alert path, not just for NTP.
 *   - NTP wall-clock .... OUTBOUND UDP 123 (and UDP 53 if using DNS names)
 *   - Web status page ... INBOUND  TCP 80   (from the viewing VLAN)
 *   - OTA reflash ....... INBOUND  TCP+UDP 3232 (from the dev host, attended)
 *   - mDNS (.local) ..... UDP 5353 + mDNS reflection for cross-VLAN name use
 *   (.local / inbound web / inbound OTA only work from the SAME VLAN unless
 *    mDNS reflection / cross-VLAN allow rules are configured. SECURITY: the web
 *    admin uses plaintext HTTP Basic Auth on TCP 80 -- credentials can be sniffed
 *    by a hostile host on the VLAN. ONLY use the reboot/send-test actions from a
 *    TRUSTED host on this isolated VLAN, and do NOT bridge TCP 80 or enable mDNS
 *    reflection for :80 across VLANs.)
 * -------------------------------------------------------------------------
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <esp_task_wdt.h>
#include <ArduinoOTA.h>     // pulls in Update; bundled with esp32 core v3.x
#include <ESPmDNS.h>        // mDNS responder (tapout.local)
#include <WebServer.h>      // LAN status page + JSON
#include <Preferences.h>    // NVS: boot counter + persistent ring log
#include <esp_system.h>     // esp_reset_reason()
#include <esp_heap_caps.h>  // heap_caps_get_largest_free_block (fragmentation canary)
#include <time.h>           // configTzTime / localtime_r / strftime
#include <Update.h>         // pull-OTA staging: Update.begin/write/end (no core signing)
#include <mbedtls/sha256.h> // SHA-256 over the firmware image (RAIL A)
#include <mbedtls/pk.h>     // RSA-PSS public-key signature verification (RAIL A)
#include <mbedtls/md.h>     // MBEDTLS_MD_SHA256
#include <esp_ota_ops.h>    // esp_ota_* A/B partition + rollback (RAIL B)
#include <DNSServer.h>      // captive-portal DNS for the SoftAP setup mode
#include <esp_timer.h>      // 5 ms D4 sampler, independent of loop() (ring detection)
#include <esp_core_dump.h>  // read + report a saved crash dump after a crash reboot
#include "public_key.h"     // RSA-2048 signing public key (RAIL A) -- committed, not secret
#include "ring_detect.h"    // ring-PATTERN detector (rejects boot/replug/brownout blips)

// ======================= USER CONFIG -- SECRET-FREE DEFAULTS =============
// v2.0.0: ALL secrets now live in NVS namespace "fhacfg" (Preferences), written
// either by the SoftAP setup portal (fresh units) or the authed POST /provision
// endpoint (already-deployed units). The COMPILED IMAGE below carries ONLY
// CHANGE-ME placeholders so the published .bin is SECRET-FREE and safe to host in
// a PUBLIC repo. loadConfig() reads NVS at boot into the runtime struct `C`; if a
// field is missing it falls back to these DEF_* defaults. An unprovisioned device
// (no NVS, or WiFi SSID still a placeholder) boots into the SoftAP setup portal
// instead of bricking. See README "provisioning" + migration runbook.
//
// >>> DO NOT put real secrets here. The .bin is meant to be published. <<<
static const char* DEF_WIFI_SSID    = "CHANGE-ME";
static const char* DEF_WIFI_PASS    = "";
static const char* DEF_NTFY_CALL    = "https://ntfy.sh/CHANGE-ME";
static const char* DEF_NTFY_STATUS  = "https://ntfy.sh/CHANGE-ME";
static const char* DEF_OTA_PASS     = "CHANGE-ME";   // ArduinoOTA (attended LAN reflash) password
static const char* DEF_WEB_USER     = "crew";
static const char* DEF_WEB_PASS     = "CHANGE-ME";   // web admin (reboot/send-test/provision) password
static const char* DEF_TZ           = "EST5EDT,M3.2.0,M11.1.0";
static const char* DEF_NTP1         = "192.168.10.1";  // VLAN gateway (answers locally, no DNS)
static const char* DEF_NTP2         = "pool.ntp.org";  // needs DNS + UDP 123 outbound
static const char* DEF_NTP3         = "time.nist.gov";
static const char* DEF_DEADMAN      = "";              // dead-man's-switch URL ("" = disabled)
// Pull-OTA manifest URL. "" => pull-OTA disabled. Example:
//   https://raw.githubusercontent.com/<org>/tapout/main/ota/manifest.json
static const char* DEF_OTA_MANIFEST = "";

static const uint32_t DEADMAN_PING_MS = 15UL*60UL*1000UL;  // >= 5 min; longer than WiFi flaps

// Forward-declared so the Arduino-generated prototype for formatEvent() (which
// takes a const RingEvent&) is valid; the full definition lives further below.
// MUST precede the first function DEFINITION in this file (e.g. clampOtaInterval
// below): arduino-cli inserts all auto-generated prototypes just before the first
// function definition, so any type a prototype references must be declared above
// that point or the generated formatEvent() prototype fails to compile.
struct RingEvent;
struct BoxRec;      // same reason: boxCrc()/boxValid() prototypes reference it

// Pull-OTA manifest-check interval bounds (minutes). A 0 / non-numeric operator
// entry would otherwise make the loop scheduler fire otaCheckManifest() on EVERY
// pass (a blocking TLS GET) -- hammering GitHub and starving the ring path. The
// floor throttles that; the ceiling keeps otaIntervalMin * 60000UL from
// overflowing the 32-bit multiply.
static const uint32_t OTA_INTERVAL_MIN_MINUTES = 1;           // >= 1 min between checks (fast polling allowed for the testing/trial period; raise via OTA later)
static const uint32_t OTA_INTERVAL_MAX_MINUTES = 10080;       // <= 1 week (overflow-safe)
static inline uint32_t clampOtaInterval(uint32_t v) {
  if (v < OTA_INTERVAL_MIN_MINUTES) return OTA_INTERVAL_MIN_MINUTES;
  if (v > OTA_INTERVAL_MAX_MINUTES) return OTA_INTERVAL_MAX_MINUTES;
  return v;
}

// Single-mode ring threshold bounds: below ~100 ms is glitch territory. The
// ceiling stays well under a normal ~2 s US ring: at >= ~2 s every ring would end
// before reaching the threshold and NO call would ever page.
static const uint32_t RING_MIN_MS_MAX = 1500;
static inline uint32_t clampRingMinMs(uint32_t v) {
  if (v < 100)             return 100;
  if (v > RING_MIN_MS_MAX) return RING_MIN_MS_MAX;
  return v;
}

// ---- Runtime config struct (populated from NVS "fhacfg" by loadConfig) -------
static Preferences cfg;                       // NVS namespace "fhacfg"  (<=15 chars)
struct Cfg {
  String   wifiSsid, wifiPass, ntfyCall, ntfyStatus;
  String   otaPass, webUser, webPass, tz, ntp1, ntp2, ntp3, deadman, otaManifest;
  String   otaFailedVer;   // version that just failed health probation (skip re-stage)
  bool     otaEnabled;
  uint32_t otaIntervalMin;
  uint8_t  ringMode;       // RD_MODE_SINGLE (default: page on the 1st ring) | RD_MODE_PATTERN
  uint32_t ringMinMs;      // single mode: page once a ring has lasted this long
  bool     provisioned;
} C;

// Forward decl: the placeholder/blank-credential gate, defined in SECURITY HELPERS.
static bool looksLikePlaceholder(const char* s);

// Load NVS config into C (with secret-free DEF_* fallbacks). Never blocks; safe
// to call once at boot. Read-only open so a corrupt/missing namespace just yields
// defaults (-> device boots to setup mode, never bricks).
static void loadConfig() {
  cfg.begin("fhacfg", /*readOnly=*/true);
  C.wifiSsid    = cfg.getString("wifi_ssid",    DEF_WIFI_SSID);
  C.wifiPass    = cfg.getString("wifi_pass",    DEF_WIFI_PASS);
  C.ntfyCall    = cfg.getString("ntfy_call",    DEF_NTFY_CALL);
  C.ntfyStatus  = cfg.getString("ntfy_status",  DEF_NTFY_STATUS);
  C.otaPass     = cfg.getString("ota_pass",     DEF_OTA_PASS);
  C.webUser     = cfg.getString("web_user",     DEF_WEB_USER);
  C.webPass     = cfg.getString("web_pass",     DEF_WEB_PASS);
  C.tz          = cfg.getString("tz",           DEF_TZ);
  C.ntp1        = cfg.getString("ntp1",         DEF_NTP1);
  C.ntp2        = cfg.getString("ntp2",         DEF_NTP2);
  C.ntp3        = cfg.getString("ntp3",         DEF_NTP3);
  C.deadman     = cfg.getString("deadman",      DEF_DEADMAN);
  C.otaManifest = cfg.getString("ota_manifest", DEF_OTA_MANIFEST);
  C.otaFailedVer   = cfg.getString("ota_failed_ver", "");  // last version that flunked probation
  C.otaEnabled     = cfg.getBool("ota_enabled", false);   // SAFE DEFAULT: off until provisioned
  // Clamp on READ too: defends against a 0/garbage value already committed to NVS
  // by an older build or a hand-edited namespace, not just the write path.
  C.otaIntervalMin = clampOtaInterval(cfg.getUInt("ota_interval", 360));  // 6 h default
  C.provisioned    = cfg.getBool("provisioned", false);
  C.ringMode       = cfg.getUChar("ring_mode", RD_MODE_SINGLE) == RD_MODE_PATTERN ? RD_MODE_PATTERN : RD_MODE_SINGLE;
  C.ringMinMs      = clampRingMinMs(cfg.getUInt("ring_min_ms", RD_SINGLE_MIN_DEFAULT_MS));
  cfg.end();
}

// "Has real WiFi config been written?" -- gates normal mode vs the setup portal.
static bool isProvisioned() {
  return C.provisioned && C.wifiSsid.length() && !looksLikePlaceholder(C.wifiSsid.c_str());
}
// ========================================================================

// ----------------------------- Pins -------------------------------------
static const int RING_PIN = D4;   // ELK-930 open-collector output (active LOW)

// --------------------------- Tunables -----------------------------------
// (Ring qualification -- arm delay, burst length, 2-burst pattern -- lives in
//  ring_detect.h; see RD_* there.)
static const uint32_t COOLDOWN_MS         = 60UL * 1000UL;  // absolute re-alert ceiling
// Re-arm for a NEW call once the line has been idle (HIGH) at least this long --
// longer than the within-call inter-ring silence (US cadence ~4 s off). This lets
// one call's ring cadence collapse to a single alert while two genuinely DISTINCT
// calls seconds apart each page. Trade-off: distinct calls closer together than
// this still merge into one alert; COOLDOWN_MS stays as an absolute ceiling so a
// line stuck ringing eventually re-alerts.
static const uint32_t RING_REARM_IDLE_MS  = 8000;
static const uint32_t HEARTBEAT_MS        = 60UL * 60UL * 1000UL;  // hourly
static const uint32_t WDT_TIMEOUT_S       = 30;             // watchdog timeout (seconds)
static const uint32_t WIFI_BACKOFF_MIN_MS = 1000;          // reconnect backoff floor
static const uint32_t WIFI_BACKOFF_MAX_MS = 60UL * 1000UL; // reconnect backoff ceiling

// Bounded HTTP timeouts so a stuck ntfy socket can't stall the ring path or
// trip the 30 s watchdog (connect + read each < WDT_TIMEOUT_S).
static const uint16_t HTTP_CONNECT_TIMEOUT_MS = 4000;
static const uint16_t HTTP_READ_TIMEOUT_MS    = 4000;
// Bound the TLS HANDSHAKE too. WiFiClientSecure defaults to 120 s, which is NOT
// covered by setConnectTimeout()/setTimeout(); a slow/stalled handshake to
// ntfy.sh can therefore block the loop far past the 30 s watchdog -> reset.
// 10 s keeps handshake + connect + read well under WDT_TIMEOUT_S.
static const uint8_t  TLS_HANDSHAKE_TIMEOUT_S = 10;

// Never-lose-a-call retry of the CALL alert when WiFi/ntfy is down.
static const uint8_t  CALL_MAX_ATTEMPTS = 12;          // ~1 min of retries
static const uint32_t CALL_RETRY_MS     = 5000;        // gap between retries

// Non-blocking red-LED hold after a ring (replaces the old blocking delay).
static const uint32_t RING_LED_HOLD_MS  = 1500;

// Low-heap canary (brownout/leak early warning to the STATUS topic).
static const uint32_t LOW_HEAP_THRESHOLD = 40000;      // bytes
static const uint32_t LOW_HEAP_CLEAR     = 60000;      // re-arm above this
static const uint32_t HEAP_CHECK_MS      = 10UL * 60UL * 1000UL;  // every 10 min

// Minimum CONTIGUOUS free block (bytes) each mbedTLS handshake (every CALL/ntfy
// POST) needs. Total free heap can look healthy while fragmentation has shrunk
// the largest block below this, silently poisoning the alert path. Single source
// of truth for the low-heap canary, the /status.json tls_ready flag, the web
// pill, and the dead-man's-switch health gate.
static const uint32_t TLS_MIN_CONTIG_BLOCK = 16000;

// Clock "is it real?" floor (~2023-11-14). Below this => not synced.
static const time_t   TIME_VALID_EPOCH  = 1700000000;

// Persistent rolling ring-event log (NVS).
static const uint8_t  RINGLOG_N         = 20;          // events kept on flash
static const uint8_t  RINGLOG_VERSION   = 2;           // bump if blob layout changes (v2 adds simMask)

// Web identity / build stamp.
static const char* FW_VERSION    = "2.0.10";
static const char* FW_BUILD_MARK = __DATE__ " " __TIME__;

// --------------------------- State --------------------------------------
static uint32_t lastAlertMs      = 0;
static volatile uint32_t lastRingActiveMs = 0;  // millis() the line was last active (>= 30 ms); written by the ring sampler
static bool     everAlerted      = false;
// ---- Ring detection state. ringSample() (the 5 ms esp_timer) owns everything
// below; loop() only reads it under ringMux or consumes the *Pending counters.
static RingDet      ringDet          = {};  // ring-pattern detector (ring_detect.h)
static portMUX_TYPE ringMux          = portMUX_INITIALIZER_UNLOCKED;
static esp_timer_handle_t ringTimer  = nullptr;
static bool         ringTimerOk      = false;   // false => loop() samples inline (fallback)
static bool         idleSinceAlert   = true;    // line idle >= RING_REARM_IDLE_MS since the last page (=> next pattern is a NEW call)
static uint32_t     ringPagesPending = 0;       // confirmed NEW calls not yet handed to the alert pipeline
static uint32_t     ringPageAtMs     = 0;       // millis() the newest one was confirmed
static uint32_t     ringDetectedAtMs = 0;       // ...as handed to triggerRingPipeline() (message age)
// Line activity that did NOT form a ring pattern (boot blip, power/cord replug,
// brownout...). Never pages; surfaced on STATUS (throttled), heartbeat and JSON.
static const uint32_t IGNORED_PING_MS = 10UL * 60UL * 1000UL;
static uint32_t     ignoredActivity    = 0;     // runs of >= 0.3 s activity that weren't a ring (since boot)
static uint32_t     glitchCount        = 0;     // isolated < 0.3 s blips (since boot; counted only)
static uint32_t     ignoredPending     = 0;
static uint32_t     lastIgnoredMs      = 0;
static uint32_t     lastIgnoredLenMs   = 0;
static uint32_t     lastIgnoredBursts  = 0;
static uint32_t     lastIgnoredPingMs  = 0;
static bool         ignoredPingPending = false;
// Last few bursts (>= 30 ms) for field validation of real D4 timing in /status.json.
struct BurstRec { uint32_t startMs, lenMs; };
static const uint8_t BURSTLOG_N = 8;
static BurstRec     burstLog[BURSTLOG_N];
static uint8_t      burstLogHead = 0, burstLogCount = 0;
static uint32_t lastHeartbeatMs  = 0;
static uint32_t wifiBackoffMs    = WIFI_BACKOFF_MIN_MS;
static uint32_t lastWifiAttempt  = 0;
static bool     onlineAnnounced  = false;   // send the "online" ping exactly once

// ----- Boot diagnostics (reset reason + boot count) -----
static Preferences  bootPrefs;
static uint32_t     bootCount   = 0;
// Lifetime count of GENUINE CALL alerts actually delivered (NVS, "fha"
// namespace). Distinct from ringCount: stays 0 through every simulation and
// ticks to 1 only on the first real delivered dispatch -- the "it works for
// real" milestone, and the guarantee a sim can never be read as a real call.
static uint32_t     realCallsDelivered = 0;
static esp_reset_reason_t bootReason = ESP_RST_UNKNOWN;
static const char*  gResetReason = "unknown";

// ----- Continuous "stuck line" detector monitor -----
// D4 LOW means the line is active. A real ring is brief (~2 s on / 4 s off), so
// D4 held LOW continuously past this threshold is NOT a normal call -- it means
// the detector is miswired/shorted, the ELK-930 has stuck active, or (harmless)
// no tip/ring is connected so the open-collector output isn't sitting idle-HIGH.
// Runs every loop, so it catches a line that drops low at boot OR any time later,
// and clears itself when the line returns to idle. (Replaces the old boot-only
// check, which false-fired on the brief LOW transient during startup.)
static const uint32_t LINE_STUCK_MS  = 20000;   // D4 LOW this long continuously = stuck
static uint32_t lineLowSinceMs   = 0;           // millis() D4 first went continuously LOW (0 = idle/HIGH)
static bool     lineStuckWarned  = false;       // warned about the current stuck episode

// ----- Black box / self-heal (defined in the BLACK BOX section) -----
static const uint32_t BOX_MAGIC          = 0x54504258;    // "TPBX"
static const uint8_t  BOX_VERSION        = 1;
static const uint8_t  BOX_EVENTS         = 16;
static const uint32_t BOX_RTC_MS         = 60UL * 1000UL;        // refresh the RTC checkpoint
static const uint32_t BOX_NVS_MS         = 5UL * 60UL * 1000UL;  // persist to flash
static const uint32_t NET_PROBE_MS       = 5UL * 60UL * 1000UL;  // probe if nothing succeeded this long
static const uint8_t  NET_HEAL_RECONNECT = 3;                    // failed probes -> reconnect WiFi
static const uint8_t  NET_HEAL_REBOOT    = 5;                    // failed probes -> reboot
static const uint32_t WIFI_DOWN_REBOOT_MS = 15UL * 60UL * 1000UL; // x 1/2/4/8 with the heal streak
static const uint32_t RESTORED_CALL_MAX_S = 10UL * 60UL;         // re-page a saved call only if this fresh

enum BoxEv : uint8_t {
  EV_BOOT = 1, EV_WIFI_LOST, EV_WIFI_UP, EV_NET_DOWN, EV_NET_UP, EV_SEND_FAIL,
  EV_HEAL_RECONNECT, EV_HEAL_REBOOT, EV_LOW_HEAP, EV_CALL, EV_REBOOT_REQ
};

struct __attribute__((packed)) BoxCp {
  uint32_t epoch;          // 0 = clock not synced
  uint32_t upS;
  uint32_t bootCount;
  uint32_t freeHeap, largest, minFree;
  uint32_t sinceOkS;       // s since the last successful network op; 0xFFFFFFFF = never
  uint32_t ringCount;
  uint16_t wifiDrops;
  uint16_t lastDisc;       // last WiFi disconnect reason code
  int8_t   rssi;
  uint8_t  wifiUp;
  uint8_t  failStreak;     // consecutive failed sends/probes while "connected"
  uint8_t  pad;
};
struct __attribute__((packed)) BoxEvt { uint32_t epoch, upS; uint8_t code, pad; uint16_t arg; };
struct __attribute__((packed)) BoxRec {
  uint32_t magic;
  uint8_t  version, head, count, pad;
  BoxCp    cp;
  BoxEvt   ev[BOX_EVENTS];
  uint32_t crc;
};

RTC_NOINIT_ATTR static BoxRec   boxRtc;     // survives crash/WDT/software resets (not power loss)
RTC_NOINIT_ATTR static uint32_t healMagic, healStreak;  // consecutive self-heal reboots without recovery
static BoxRec    box = {};                  // live recorder for this boot
static BoxRec    boxPrev = {};              // what the previous boot left behind
static bool      boxPrevValid = false;
static bool      boxPrevFromRtc = false;
static char      rebootWhy[96] = "";        // reason the PREVIOUS boot recorded before restarting
static uint32_t  lastBoxRtcMs = 0, lastBoxNvsMs = 0;
static uint32_t  lastNetOkMs = 0;           // millis() of the last successful send/probe
static bool      netEverOk = false;
static uint8_t   netFailStreak = 0;
static uint8_t   netFailProbes = 0;
static uint32_t  lastProbeMs = 0;
static uint32_t  wifiDownSinceMs = 0;
static uint16_t  wifiDrops = 0;
static volatile uint16_t lastDiscReason = 0;  // written by the WiFi event task
static bool      restartReported = false;
static bool      crashPending = false;
static esp_core_dump_summary_t crashSum;
static char      crashReason[64] = "";
static uint32_t  savedCallEpoch = 0;        // a real call detected before the restart (NVS), 0 = none
static bool      savedCallChecked = false;

static uint32_t callRestoredEpoch = 0;   // != 0: the latched call was saved before a restart
static char     pendingRebootWhy[72] = "requested reboot";   // recorded by the deferred-reboot handler
static void boxBoot();
static void boxSaveCall();
static void boxClearCall();
static void boxEvent(uint8_t code, uint16_t arg);
static void netOk();
static void netFail(int code);
static void noteReboot(const char* why);
static void serviceBlackBox();
static void serviceRestartReport();
static void serviceCrashReport();
static void serviceSavedCall();

// ----- Never-lose-a-call queue -----
static bool     callPending    = false;
static uint32_t callDetectedMs = 0;
static uint8_t  callAttempts   = 0;
static uint32_t lastCallTryMs  = 0;
// Whether the currently-latched call is a SIMULATION (so retries via
// serviceCallQueue() keep routing to the STATUS topic, never the crew CALL
// topic) and, for a deliberate commissioning sim, whether to route to CALL.
static bool     callSimulated  = false;
static bool     callSimToCall  = false;

// ----- Heartbeat sequence (monotonic; a gap on STATUS reveals a missed beat) --
static uint32_t heartbeatSeq   = 0;

// ----- Dead-man's-switch (external pull-based check-in) -----
static uint32_t lastDeadmanMs      = 0;
static uint32_t lastDeadmanOkEpoch = 0;   // 0 = never / clock unsynced
static bool     deadmanOk          = false;

// ----- Non-blocking ring-LED hold -----
static uint32_t ringLedUntil   = 0;   // 0 = not holding

// ----- Low-heap canary -----
static bool     lowHeapWarned  = false;
static uint32_t lastHeapCheckMs = 0;

// ----- OTA (ArduinoOTA attended reflash) -----
static bool otaInProgress = false;    // true only while an upload is streaming

// ----- Pull-OTA (signed GitHub auto-update + health-gated rollback) -----
enum OtaState { PULL_OTA_IDLE, PULL_OTA_DOWNLOADING, PULL_OTA_PENDING_REBOOT };
static OtaState  otaState        = PULL_OTA_IDLE;
static uint32_t  lastOtaCheckMs  = 0;        // throttles otaCheckManifest()
static bool      g_onProbation   = false;    // booted into a freshly-flashed image on trial
static uint32_t  trialDeadlineMs = 0;        // millis() by which the new image must prove healthy
static char      otaPendingVer[16] = {0};    // version we are staging / on trial (for status.json)
// OTA poll visibility: last poll outcome (shown on /status.json; survives the throttle)
static char      otaLastResult[100] = "(no OTA poll yet)";
static uint32_t  otaLastResultMs    = 0;
static uint32_t  lastNoUpdatePingMs = 0;     // throttles the routine "no new version" STATUS ping

// ----- SoftAP setup portal (fresh, unprovisioned units) -----
static DNSServer dns;
static bool      inSetupMode = false;        // true => SoftAP captive portal, no STA

// ----- Web / mDNS -----
static WebServer server(80);
static bool      netServicesArmed = false;  // OTA + mDNS advertised once up
static uint32_t  pendingRebootMs  = 0;      // 0 = no reboot scheduled
static uint32_t  ringCount        = 0;      // total rings since boot (RAM only)
static uint32_t  lastRingEpoch    = 0;      // 0 = never / clock unsynced
static uint32_t  lastRingUptimeMs = 0;      // millis() of last ring

// ----- Persistent ring-event log -----
struct RingEvent {
  uint32_t epoch;     // unix seconds; 0 = clock not synced when recorded
  uint32_t uptimeMs;  // millis() at record time; 0 = restored from NVS (pre-reboot)
};
struct __attribute__((packed)) RingLogBlob {
  uint8_t  version;
  uint8_t  count;
  uint8_t  head;
  uint8_t  reserved;
  uint32_t simMask;             // bit i set => physical slot i was a SIMULATION
  uint32_t epochs[RINGLOG_N];
};
static RingEvent   ringLog[RINGLOG_N];
static uint8_t     ringLogCount = 0;        // valid entries (<= N)
static uint8_t     ringLogHead  = 0;        // next write slot
static Preferences ringLogPrefs;
// "Was this entry a simulation?" flag, parallel to ringLog[]. Persisted to NVS as
// a bitmask in RingLogBlob (v2) so the [SIM] tag SURVIVES a reboot/brownout --
// otherwise a previously-simulated ring would reappear in the audit log untagged
// and be indistinguishable from a real dispatch. The authoritative lifetime
// real-vs-test counter remains realCallsDelivered above.
static bool        ringLogSim[RINGLOG_N] = {false};

// ----------------------- RGB LED helpers --------------------------------
// On the Nano ESP32 the onboard RGB LED is ACTIVE LOW (LOW = on).
static void ledOff() {
  digitalWrite(LED_RED, HIGH);
  digitalWrite(LED_GREEN, HIGH);
  digitalWrite(LED_BLUE, HIGH);
}
static void ledSet(bool r, bool g, bool b) {
  digitalWrite(LED_RED,   r ? LOW : HIGH);
  digitalWrite(LED_GREEN, g ? LOW : HIGH);
  digitalWrite(LED_BLUE,  b ? LOW : HIGH);
}
// Status colors
static void statusBoot()       { ledSet(false, false, true);  } // blue    = booting
static void statusConnected()  { ledSet(false, true,  false); } // green   = WiFi up / idle
static void statusRing()       { ledSet(true,  false, false); } // red     = ring detected
static void statusError()      { ledSet(true,  true,  false); } // yellow  = error/offline
static void statusOta()        { ledSet(true,  false, true);  } // magenta = OTA in progress

// ----------------------- Forward decls ----------------------------------
static bool sendNtfy(const char* url, const char* title, const char* message, const char* priority, const char* tags);
static void serviceWifi();
static void handleRing();
static void handleHeartbeat();
static void announceOnlineOnce();
static void serviceStuckLine();
static void serviceCredWarn();
static void serviceHeapCheck();
static void serviceIgnoredActivity();
static void serviceArmCheck();
static void startRingSampler();
static void applyRingConfig();
static bool realCallInFlight();
static void fireCallAlert(bool simulated);
static void serviceCallQueue();
static void triggerRingPipeline(bool simulated);
static void handleSimulateRing();
static void serviceDeadman();
static bool httpGetBounded(const char* url);
static void setupOTA();
static void armNetworkServices();
static void recordRing(bool simulated);
static void loadRingLog();
static void persistRingLog();
static void formatTimestamp(char* out, size_t n);
static bool timeSynced();
// ---- v2.0.0: provisioning + pull-OTA ----
static void startSetupPortal();
static void handleSetupForm();
static void provisionFromArgs();
static void otaCheckProbationOnBoot();
static void otaServiceProbation();
static void otaCheckManifest();
static bool otaDownloadAndFlash(const String& url, size_t totalSize);
static bool otaEnabledAndSafe();
static bool otaSafeToStart();

// ===================== SECURITY HELPERS ================================
// A credential still set to its shipped CHANGE-ME placeholder (or left blank)
// must NOT be trusted: an un-edited flash would otherwise expose OTA reflash and
// the admin reboot/send-test endpoints to any LAN client who can read this
// source. Detect the placeholder so those services fail CLOSED until edited.
static bool looksLikePlaceholder(const char* s) {
  if (!s || s[0] == '\0') return true;
  return strstr(s, "CHANGE-ME") != nullptr || strstr(s, "change-me") != nullptr;
}

// ===================== TIME / FORMAT HELPERS ============================
// true once NTP has actually set the clock. Never blocks (reads RTC only).
static bool timeSynced() { return time(nullptr) > TIME_VALID_EPOCH; }

// Wall-clock timestamp if synced, else an uptime string. NEVER blocks (uses
// time()/localtime_r, never getLocalTime() with its 5 s default timeout).
static void formatTimestamp(char* out, size_t n) {
  time_t now = time(nullptr);
  if (now > TIME_VALID_EPOCH) {
    struct tm lt;
    localtime_r(&now, &lt);
    strftime(out, n, "%Y-%m-%d %H:%M:%S %Z", &lt);   // "2026-06-26 14:03:21 EDT"
    return;
  }
  uint32_t s = millis() / 1000UL;
  snprintf(out, n, "uptime %luh%02lum%02lus (clock not synced)",
           (unsigned long)(s / 3600UL),
           (unsigned long)((s % 3600UL) / 60UL),
           (unsigned long)(s % 60UL));
}

// "2d 03h 14m 07s"
static String fmtDuration(uint32_t ms) {
  uint32_t s = ms / 1000, d = s / 86400; s %= 86400;
  uint32_t h = s / 3600;  s %= 3600;
  uint32_t m = s / 60;    s %= 60;
  char buf[40];
  snprintf(buf, sizeof(buf), "%lud %02luh %02lum %02lus",
           (unsigned long)d, (unsigned long)h, (unsigned long)m, (unsigned long)s);
  return String(buf);
}

// Absolute epoch -> "YYYY-MM-DD HH:MM:SS" (or em-dash if unset/unsynced).
static String fmtEpoch(uint32_t t) {
  if (t < (uint32_t)TIME_VALID_EPOCH) return String("--");
  time_t tt = (time_t)t;
  struct tm tmv; localtime_r(&tt, &tmv);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
  return String(buf);
}

static const char* rssiQuality(int dbm) {
  if (dbm >= -50) return "Excellent";
  if (dbm >= -60) return "Good";
  if (dbm >= -70) return "Fair";
  if (dbm >= -80) return "Weak";
  return "Very weak";
}

static const char* resetReasonToStr(esp_reset_reason_t r) {
  switch (r) {
    case ESP_RST_POWERON:   return "Power-on";
    case ESP_RST_SW:        return "Software reset";
    case ESP_RST_PANIC:     return "PANIC / crash";
    case ESP_RST_INT_WDT:   return "Interrupt watchdog";
    case ESP_RST_TASK_WDT:  return "Task watchdog";
    case ESP_RST_WDT:       return "Other watchdog";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_EXT:       return "External reset";
    case ESP_RST_DEEPSLEEP: return "Deep-sleep wake";
    case ESP_RST_SDIO:      return "SDIO";
    default:                return "Unknown";
  }
}

// ===================== PERSISTENT RING-EVENT LOG =======================
// oldest = logical index 0
static uint8_t ringLogPhys(uint8_t logical) {
  return (uint8_t)((ringLogHead + RINGLOG_N - ringLogCount + logical) % RINGLOG_N);
}

static void persistRingLog() {
  RingLogBlob blob;
  blob.version  = RINGLOG_VERSION;
  blob.count    = ringLogCount;
  blob.head     = ringLogHead;
  blob.reserved = 0;
  blob.simMask  = 0;
  for (uint8_t i = 0; i < RINGLOG_N; i++) {
    blob.epochs[i] = ringLog[i].epoch;
    if (ringLogSim[i]) blob.simMask |= (1UL << i);   // preserve the [SIM] tag across reboots
  }

  ringLogPrefs.begin("ringlog", false);            // RW
  ringLogPrefs.putBytes("log", &blob, sizeof(blob));
  ringLogPrefs.end();
}

static void loadRingLog() {
  RingLogBlob blob;
  ringLogPrefs.begin("ringlog", true);             // read-only
  size_t n = ringLogPrefs.getBytes("log", &blob, sizeof(blob));
  ringLogPrefs.end();

  if (n != sizeof(blob) || blob.version != RINGLOG_VERSION) return;  // first boot / format change

  ringLogCount = blob.count > RINGLOG_N ? RINGLOG_N : blob.count;
  ringLogHead  = blob.head % RINGLOG_N;
  for (uint8_t i = 0; i < RINGLOG_N; i++) {
    ringLog[i].epoch    = blob.epochs[i];
    ringLog[i].uptimeMs = 0;                        // pre-reboot: uptime unknown
    ringLogSim[i]       = (blob.simMask >> i) & 1U; // restore the [SIM] tag
  }
}

// Fast, non-blocking record of a ring. Called from triggerRingPipeline().
// `simulated` tags the RAM-only ringLogSim[] slot; the persisted blob is
// unchanged (see ringLogSim[] note) so there is no NVS migration.
static void recordRing(bool simulated) {
  time_t now = time(nullptr);
  RingEvent &e = ringLog[ringLogHead];
  e.epoch    = (now > TIME_VALID_EPOCH) ? (uint32_t)now : 0;
  e.uptimeMs = millis();
  ringLogSim[ringLogHead] = simulated;             // RAM-only sim tag for this slot

  ringLogHead = (ringLogHead + 1) % RINGLOG_N;
  if (ringLogCount < RINGLOG_N) ringLogCount++;

  ringCount++;
  lastRingEpoch    = e.epoch;
  lastRingUptimeMs = e.uptimeMs;

  persistRingLog();
  esp_task_wdt_reset();                             // NVS commit can take a few ms
}

// Human string for one event (web + serial).
static void formatEvent(const RingEvent &e, char *out, size_t n) {
  if (e.epoch != 0) {
    time_t t = (time_t)e.epoch;
    struct tm tmv;
    localtime_r(&t, &tmv);
    char ts[24];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    if (e.uptimeMs) snprintf(out, n, "%s  (uptime %lus)", ts, (unsigned long)(e.uptimeMs / 1000));
    else            snprintf(out, n, "%s  (before last reboot)", ts);
  } else if (e.uptimeMs) {
    snprintf(out, n, "uptime +%lus  (clock not synced)", (unsigned long)(e.uptimeMs / 1000));
  } else {
    snprintf(out, n, "time unknown  (pre-reboot, clock not synced)");
  }
}

// (Newest-first HTML list is now streamed inline by handleRoot(), and the JSON
//  ring_log object is streamed per-event inline by handleStatusJson() -- both
//  avoid building a large String that would fragment the heap the CALL TLS
//  handshake needs. See the heap-fragmentation note.)

// ===================== BOOT / STATUS PINGS =============================
// Send the boot "online" ping the first time WiFi is up -- works whether the
// connection completes during setup() or later in the loop (serviceWifi).
// Now reports boot count + last reset reason + free heap (brownout canary).
// v2.0.10: replaced by the black-box restart report (cause, downtime, what it
// looked like just before, recent events) -- see serviceRestartReport().
static void announceOnlineOnce() {
  if (onlineAnnounced) return;
  serviceRestartReport();
}

// Boot-time D4 self-test: if the detector read LOW at startup it is miswired,
// shorted, or the line was actually ringing during boot. Retries until the
// warning is delivered. Non-blocking; safe to call every loop.
// Continuously watch for the detector line being STUCK active (D4 LOW far longer
// than any real ring). Warns once per stuck episode and again on recovery, so a
// miswired/shorted/stuck detector -- or simply tip/ring not yet connected -- is
// visible without false-firing on normal rings or the brief boot-time transient.
static void serviceStuckLine() {
  bool low = (digitalRead(RING_PIN) == LOW);
  uint32_t now = millis();

  if (!low) {                                  // line idle (HIGH) -> healthy
    if (lineStuckWarned && WiFi.status() == WL_CONNECTED) {
      if (sendNtfy(C.ntfyStatus.c_str(), "Detector line recovered",
                   "D4 returned to idle (HIGH). The ring line is no longer stuck active.",
                   "default", "white_check_mark")) {
        lineStuckWarned = false;
      }
    } else if (lineStuckWarned) {
      lineStuckWarned = false;                 // clear even if the ping couldn't go out
    }
    lineLowSinceMs = 0;
    return;
  }

  if (lineLowSinceMs == 0) lineLowSinceMs = now;        // line just went low
  if (lineStuckWarned) return;                          // already flagged this episode
  if ((now - lineLowSinceMs) < LINE_STUCK_MS) return;   // not stuck long enough yet (ignores normal rings + boot transient)
  if (WiFi.status() != WL_CONNECTED) return;

  char msg[200];
  snprintf(msg, sizeof(msg),
    "D4 has read LOW (line active) continuously for >%lus -- too long to be a real "
    "call. Likely the ELK-930 is miswired/shorted/stuck, or tip/ring isn't connected "
    "so the open-collector output isn't sitting idle-HIGH. Verify the detector. (Bell stays primary.)",
    (unsigned long)(LINE_STUCK_MS / 1000));
  if (sendNtfy(C.ntfyStatus.c_str(), "Detector line STUCK active", msg, "high", "warning")) {
    lineStuckWarned = true;
  }
}

// Low-heap canary: one throttled STATUS warning when free heap drops low.
static void serviceHeapCheck() {
  if (millis() - lastHeapCheckMs < HEAP_CHECK_MS) return;
  lastHeapCheckMs = millis();
  uint32_t h = ESP.getFreeHeap();
  // Total free heap can look healthy while the heap is fragmented into pieces too
  // small for the ~16 KB contiguous block each mbedTLS handshake (every CALL/ntfy
  // POST) needs. Watch the largest free block too, or fragmentation could silently
  // poison the alert path without tripping a total-free threshold.
  uint32_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  bool low = (h < LOW_HEAP_THRESHOLD) || (largest < TLS_MIN_CONTIG_BLOCK);
  if (low && !lowHeapWarned) {
    char m[160];
    snprintf(m, sizeof(m),
             "Heap pressure: free %u B, largest block %u B. TLS alerts may start "
             "failing; consider a scheduled power-cycle.",
             (unsigned)h, (unsigned)largest);
    boxEvent(EV_LOW_HEAP, (uint16_t)(largest / 1024));
    sendNtfy(C.ntfyStatus.c_str(), "Low memory", m, "high", "warning");
    lowHeapWarned = true;
  } else if (h > LOW_HEAP_CLEAR && largest > 24000) {
    lowHeapWarned = false;
  }
}

// One-shot STATUS warning when the device booted with default OTA/admin creds,
// which forces those services to fail closed (see looksLikePlaceholder()).
static void serviceCredWarn() {
  static bool sent = false;
  if (sent) return;
  if (!looksLikePlaceholder(C.webPass.c_str()) && !looksLikePlaceholder(C.otaPass.c_str())) {
    sent = true;                                   // nothing to warn about
    return;
  }
  if (WiFi.status() != WL_CONNECTED) return;       // retry once WiFi is up
  if (sendNtfy(C.ntfyStatus.c_str(), "Default passwords in use",
               "OTA reflash and the admin reboot/send-test/provision actions are "
               "DISABLED: the web_pass and/or ota_pass NVS fields are still the "
               "shipped CHANGE-ME defaults. Re-provision (POST /provision or the "
               "SoftAP setup portal) with real values to enable them.",
               "high", "warning")) {
    sent = true;
  }
}

// ===================== NEVER-LOSE-A-CALL QUEUE =========================
// Sends the CALL alert; on failure leaves callPending true to retry, and after
// CALL_MAX_ATTEMPTS surfaces a delivery-failure on the STATUS topic so a ring
// is never silently lost.
static void fireCallAlert(bool simulated) {
  // NEVER burn a retry attempt when there is no link. sendNtfy() would return
  // false immediately without a real POST, so counting it would exhaust all
  // CALL_MAX_ATTEMPTS within ~60 s and SILENTLY drop a real call during any
  // WiFi/ntfy outage longer than a minute. Instead, leave the call latched and
  // wait for WiFi to return, then deliver it. The give-up cap is reserved for
  // genuine HTTP failures while actually CONNECTED.
  if (WiFi.status() != WL_CONNECTED) return;

  char ts[48];
  formatTimestamp(ts, sizeof(ts));
  uint32_t ageS = (millis() - callDetectedMs) / 1000;
  char msg[224];
  if (callRestoredEpoch && !simulated) {
    char when[24];
    time_t t = (time_t)callRestoredEpoch; struct tm lt; localtime_r(&t, &lt);
    strftime(when, sizeof(when), "%H:%M:%S", &lt);
    time_t now = time(nullptr);
    snprintf(msg, sizeof(msg),
      "Phone rang at %s. This alert was delayed ~%lu min because the device restarted.",
      when, (unsigned long)(now > (time_t)callRestoredEpoch ? (now - callRestoredEpoch + 59) / 60 : 1));
  } else if (ageS < 3) {
    snprintf(msg, sizeof(msg),
      "Incoming call on the station line at %s.", ts);
  } else {
    snprintf(msg, sizeof(msg),
      "Phone rang ~%lus ago at %s (alert delayed by network).",
      (unsigned long)ageS, ts);
  }

  // Real ring: byte-identical to v1.1.0 (CALL topic, max priority).
  // Simulation: same message body (so the full TLS POST path is exercised) but
  // routed to the STATUS topic and clearly tagged [SIM] so the crew is never
  // paged -- UNLESS this is a deliberate, auth+confirm-gated commissioning sim
  // (callSimToCall), which goes to the CALL topic with a [SIM/COMMISSIONING
  // TEST] title to prove the crew subscription actually receives.
  const char* url   = C.ntfyCall.c_str();
  const char* title = "STATION PHONE RINGING";
  const char* prio  = "max";
  const char* tags  = "rotating_light,fire_engine";
  if (simulated) {
    if (callSimToCall) {
      // DEFAULT test: exercise the REAL crew path -- CALL topic at MAX priority,
      // so it actually validates that crew phones alarm / break through DND --
      // but clearly TEST-labeled so nobody rolls a truck. Never counts as a real
      // delivered call (realCallsDelivered only ticks when !simulated).
      url   = C.ntfyCall.c_str();
      title = "[TEST] STATION PHONE RINGING";
      prio  = "max";
      tags  = "test_tube,rotating_light";
    } else {
      // Quiet plumbing test (?quiet=1 / ?topic=status): STATUS only, crew not paged.
      url   = C.ntfyStatus.c_str();
      title = "[SIM] STATION PHONE RINGING (quiet test, crew not paged)";
      prio  = "default";
      tags  = "test_tube";
    }
  }

  if (sendNtfy(url, title, msg, prio, tags)) {
    callPending = false;                 // delivered
    if (!simulated) {
      boxClearCall();                    // delivered: nothing to re-send after a restart
      callRestoredEpoch = 0;
      // The unambiguous "it worked for real" milestone -- persisted so it
      // survives reboots and can NEVER be confused with a simulation.
      realCallsDelivered++;
      bootPrefs.begin("fha", false);
      bootPrefs.putUInt("realcalls", realCallsDelivered);
      bootPrefs.end();
      esp_task_wdt_reset();
      Serial.printf("[ring] CALL alert delivered (real_calls_delivered=%lu)\n",
                    (unsigned long)realCallsDelivered);
    } else {
      Serial.println(F("[sim] simulated ring alert delivered"));
    }
  } else if (++callAttempts >= CALL_MAX_ATTEMPTS) {
    callPending = false;                 // give up; surface on STATUS
    if (!simulated) { boxClearCall(); callRestoredEpoch = 0; }
    Serial.println(F("[ring] CALL alert FAILED after retries"));
    sendNtfy(C.ntfyStatus.c_str(), "ALERT DELIVERY FAILED",
             "A ring was detected but the CALL alert could not be delivered "
             "after retries. Check WiFi / outbound 443 to ntfy.sh.",
             "high", "warning");
    statusError();
  } else {
    Serial.printf("[ring] CALL alert retry %u/%u pending\n",
                  callAttempts, CALL_MAX_ATTEMPTS);
  }
}

// Non-blocking retry pump; gated on CALL_RETRY_MS so it never spins.
static void serviceCallQueue() {
  if (!callPending) return;
  if (millis() - lastCallTryMs < CALL_RETRY_MS) return;
  lastCallTryMs = millis();
  fireCallAlert(callSimulated);   // retries keep the original real/sim routing
}

// ============================ OTA ======================================
// Keep hostname IDENTICAL to WiFi.setHostname() so mDNS, OTA and firewall
// lists all agree: "tapout" -> tapout.local:3232.
static void setupOTA() {
  ArduinoOTA.setHostname("tapout");
  ArduinoOTA.setPassword(C.otaPass.c_str());   // espota must present this to flash
  // Default OTA port 3232 (TCP) -- left default so the flash command is simple.

  ArduinoOTA.onStart([]() {
    noteReboot("ArduinoOTA reflash (attended, over WiFi)");
    otaInProgress = true;
    // A flash erase/write can block far longer than the 30 s WDT. Detach the
    // dog for the duration so a legitimate upload can't panic-reset mid-write.
    esp_task_wdt_delete(NULL);
    statusOta();                          // magenta = OTA in progress
    Serial.println(F("[ota] update starting -- watchdog detached"));
  });

  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    esp_task_wdt_reset();                 // harmless even while detached
    static bool on = false;
    on = !on;
    if (on) statusOta(); else ledOff();   // blink so a human sees progress
    (void)progress; (void)total;
  });

  ArduinoOTA.onEnd([]() {
    Serial.println(F("[ota] update complete -- rebooting"));
    statusOta();
    // ArduinoOTA reboots into the new image on return; WDT re-inits in setup().
  });

  ArduinoOTA.onError([](ota_error_t error) {
    Serial.printf("[ota] ERROR %u -- aborting, keeping old image\n", error);
    // Upload failed: NO reboot, old firmware keeps running. Re-arm the dog we
    // detached in onStart so normal protection resumes.
    esp_task_wdt_add(NULL);
    esp_task_wdt_reset();
    otaInProgress = false;
    statusError();                        // loop restores green/idle next pass
  });

  ArduinoOTA.begin();                     // also starts the mDNS responder
  Serial.println(F("[ota] ready: tapout.local:3232"));
}

// Arm OTA + advertise mDNS http service exactly once, after WiFi is up.
static void armNetworkServices() {
  if (netServicesArmed || WiFi.status() != WL_CONNECTED) return;
  if (looksLikePlaceholder(C.otaPass.c_str())) {
    // Fail CLOSED: do not arm OTA with the shipped default password -- anyone who
    // read this source could otherwise push arbitrary firmware. Still bring up the
    // mDNS responder so the read-only status page stays reachable at .local.
    MDNS.begin("tapout");
    MDNS.addService("http", "tcp", 80);
    netServicesArmed = true;
    Serial.println(F("[net] OTA DISABLED -- OTA_PASSWORD still default; mDNS http only"));
    return;
  }
  setupOTA();                             // ArduinoOTA.begin() starts mDNS too
  MDNS.addService("http", "tcp", 80);     // advertise the status page
  netServicesArmed = true;
  Serial.println(F("[net] OTA armed + mDNS advertising http on :80"));
}

// ========================= WEB HANDLERS ================================
// Gate a state-changing endpoint behind HTTP Basic Auth.
static bool requireAuth() {
  if (looksLikePlaceholder(C.webPass.c_str())) {
    // Fail CLOSED: an un-provisioned web_pass is public (CHANGE-ME default), so
    // refuse every state-changing action until a real one is provisioned to NVS.
    server.send(403, "text/plain",
                "Admin actions DISABLED: the web_pass NVS field is still the "
                "shipped CHANGE-ME default. Provision a real password "
                "(SoftAP portal or POST /provision) first.\n");
    return false;
  }
  if (server.authenticate(C.webUser.c_str(), C.webPass.c_str())) return true;
  server.requestAuthentication();         // 401 + WWW-Authenticate
  return false;
}

// GET /  -- auto-refreshing human status page. No secrets (SSID name only).
static void handleRoot() {
  const bool wifiUp = (WiFi.status() == WL_CONNECTED);
  int  rssi = wifiUp ? WiFi.RSSI() : 0;
  uint32_t now = millis();

  // Stream the page in small chunks rather than accumulating one large String.
  // Over a months-long uptime, repeated growth/free of a 4 KB+ String fragments
  // the heap and can starve the contiguous block each ntfy TLS handshake needs.
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");

  server.sendContent(F(
         "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
         "<meta name='viewport' content='width=device-width,initial-scale=1'>"
         "<meta http-equiv='refresh' content='10'>"
         "<title>Tapout</title><style>"
         "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
         "margin:0;background:#0f1115;color:#e6e6e6}"
         ".wrap{max-width:680px;margin:0 auto;padding:16px}"
         "h1{font-size:1.25rem;margin:.2rem 0}"
         ".sub{color:#9aa3af;font-size:.85rem;margin-bottom:14px}"
         ".card{background:#1a1d24;border:1px solid #262b34;border-radius:12px;"
         "padding:14px 16px;margin:12px 0}"
         "table{width:100%;border-collapse:collapse}"
         "td{padding:6px 4px;border-bottom:1px solid #262b34;vertical-align:top}"
         "td.k{color:#9aa3af;width:42%}"
         ".pill{display:inline-block;padding:2px 10px;border-radius:999px;"
         "font-size:.8rem;font-weight:600}"
         ".ok{background:#0f3d2e;color:#5ee0a8}"
         ".warn{background:#4a3a0f;color:#f5d061}"
         ".bad{background:#4a1717;color:#f08a8a}"
         ".log{font-family:ui-monospace,Menlo,monospace;font-size:.85rem}"
         "</style></head><body><div class='wrap'>"));

  server.sendContent(F("<h1>Tapout</h1>"));
  server.sendContent(String(F("<div class='sub'>tapout &nbsp;&bull;&nbsp; fw "))
                     + FW_VERSION + F("</div>"));

  // security banner if shipped default credentials are still in place
  if (looksLikePlaceholder(C.webPass.c_str()) || looksLikePlaceholder(C.otaPass.c_str()))
    server.sendContent(F("<div class='card'><span class='pill bad'>SECURITY</span> "
           "Default OTA/admin password still in use &mdash; OTA reflash and the "
           "admin reboot/send-test actions are DISABLED until you set real "
           "passwords and reflash.</div>"));

  // status pill
  server.sendContent(F("<div class='card'>"));
  if (!wifiUp)                            server.sendContent(F("<span class='pill bad'>WiFi DOWN</span>"));
  else if (digitalRead(RING_PIN) == LOW) server.sendContent(F("<span class='pill bad'>RINGING NOW</span>"));
  else if (!ringDet.armed)               server.sendContent(F("<span class='pill warn'>Arming -- waiting for 3 s of idle line</span>"));
  else                                   server.sendContent(F("<span class='pill ok'>Idle -- armed</span>"));
  if (callPending)                       server.sendContent(F(" <span class='pill warn'>CALL alert retrying</span>"));
  if (!timeSynced())                     server.sendContent(F(" <span class='pill warn'>NTP not synced</span>"));
  server.sendContent(F("</div>"));

  // main table
  server.sendContent(F("<div class='card'><table>"));
  auto row = [&](const String& k, const String& v) {
    server.sendContent("<tr><td class='k'>" + k + "</td><td>" + v + "</td></tr>");
  };
  row(F("Current time"),  timeSynced() ? fmtEpoch((uint32_t)time(nullptr))
                                       : String(F("NTP not synced")));
  row(F("Uptime"),        fmtDuration(now));
  row(F("Total rings (boot)"), String(ringCount));
  row(F("Last ring"),
      ringCount == 0 ? String(F("none yet"))
      : (lastRingEpoch ? fmtEpoch(lastRingEpoch)
                       : fmtDuration(now - lastRingUptimeMs) + F(" ago")));
  row(F("WiFi SSID"),     wifiUp ? WiFi.SSID() : String(F("--")));
  row(F("IP address"),    wifiUp ? WiFi.localIP().toString() : String(F("--")));
  row(F("Signal (RSSI)"),
      wifiUp ? String(rssi) + " dBm -- " + rssiQuality(rssi) : String(F("--")));
  row(F("Free heap"),     String(ESP.getFreeHeap()) + F(" bytes"));
  {
    uint32_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    bool ready = (largest >= TLS_MIN_CONTIG_BLOCK);
    String v = String(F("<span class='pill ")) + (ready ? F("ok'>TLS OK") : F("warn'>TLS LOW"))
             + F("</span> ") + String(largest) + F(" bytes contiguous");
    row(F("Largest free block"), v);
  }
  row(F("Real CALL alerts delivered (lifetime)"), String((unsigned long)realCallsDelivered));
  row(F("Ring mode"), C.ringMode == RD_MODE_PATTERN
      ? String(F("pattern &mdash; pages on the 2nd ring"))
      : String(F("single &mdash; pages once a ring lasts ")) + C.ringMinMs + F(" ms"));
  row(F("Ignored line activity (not a ring)"),
      String((unsigned long)ignoredActivity) + (ringDet.armed ? F("") : F(" &mdash; detector arming (line must be idle 3 s)")));
  row(F("Boot count"),    String(bootCount));
  row(F("Last reset"),    String(gResetReason));
  {
    uint32_t since = now - lastHeartbeatMs;
    uint32_t until = (since >= HEARTBEAT_MS) ? 0 : (HEARTBEAT_MS - since);
    row(F("Heartbeat"),   String(F("last ")) + fmtDuration(since) +
                          F(" ago, next in ") + fmtDuration(until));
  }
  row(F("Firmware build"), String(FW_BUILD_MARK));
  server.sendContent(F("</table></div>"));

  // recent ring log (persistent, newest first) -- streamed one entry at a time
  server.sendContent(F("<div class='card'><b>Recent rings</b> "
         "<span class='sub'>(persists across reboots)</span><ul>"));
  {
    char line[80];
    for (int i = ringLogCount - 1; i >= 0; i--) {
      uint8_t phys = ringLogPhys((uint8_t)i);
      formatEvent(ringLog[phys], line, sizeof(line));
      String pre = ringLogSim[phys] ? F("<b>[SIM]</b> ") : F("");
      server.sendContent(String(F("<li>")) + pre + line + F("</li>"));
    }
    if (ringLogCount == 0) server.sendContent(F("<li>(no rings recorded)</li>"));
  }
  server.sendContent(F("</ul></div>"));

  // admin actions (auth-gated POST)
  server.sendContent(F("<div class='card'><b>Actions</b> "
         "<span class='sub'>(require login)</span><br><br>"
         "<form method='POST' action='/send-test' style='display:inline'>"
         "<button>Send test alert</button></form> &nbsp; "
         "<form method='POST' action='/simulate-ring' style='display:inline' "
         "onsubmit=\"var p=prompt('Page the REAL crew (CALL topic, MAX priority, "
         "[TEST]-labeled)? Type the web admin password to confirm:');if(!p)return false;"
         "this.action='/simulate-ring?topic=call&confirm='+encodeURIComponent(p);return true;\">"
         "<button>Test crew alert (pages CALL)</button></form> &nbsp; "
         "<form method='POST' action='/simulate-ring' style='display:inline' "
         "onsubmit=\"return confirm('Quiet plumbing test -> STATUS only, crew NOT paged?')\">"
         "<button>Quiet test (STATUS)</button></form> &nbsp; "
         "<form method='POST' action='/check-ota' style='display:inline' "
         "onsubmit=\"return confirm('Check GitHub for a firmware update now? If a newer "
         "signed version exists, the device will download + flash it.')\">"
         "<button>Check for update</button></form> &nbsp; "
         "<form method='POST' action='/reboot' style='display:inline' "
         "onsubmit=\"return confirm('Reboot the alerter?')\">"
         "<button>Reboot</button></form>"
         "<div class='sub' style='margin-top:8px'>Simulate ring drives the REAL "
         "record&rarr;latch&rarr;CALL&rarr;ntfy&rarr;web path, tagged [SIM]; it never pages "
         "the crew and never increments \"Real CALL alerts delivered\".</div></div>"));

  server.sendContent(F("<div class='sub'>Auto-refreshes every 10 s &bull; read-only data is "
         "unauthenticated on the LAN.</div></div></body></html>"));
  server.sendContent("");          // terminate the chunked response
  esp_task_wdt_reset();
}

// GET /status.json -- machine-readable; same data, no secrets.
static void handleStatusJson() {
  const bool wifiUp = (WiFi.status() == WL_CONNECTED);
  int rssi = wifiUp ? WiFi.RSSI() : 0;
  uint32_t now = millis();

  // Streamed in small chunks (same heap-fragmentation rationale as handleRoot).
  server.sendHeader("Cache-Control", "no-store");
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "application/json", "");

  server.sendContent(F("{\"device\":\"tapout\""));
  server.sendContent(String(F(",\"fw_version\":\""))   + FW_VERSION + "\"");
  server.sendContent(String(F(",\"fw_build\":\""))     + FW_BUILD_MARK + "\"");
  server.sendContent(String(F(",\"time_synced\":"))    + (timeSynced() ? "true" : "false"));
  server.sendContent(String(F(",\"epoch\":"))          + String((long)(timeSynced() ? time(nullptr) : 0)));
  server.sendContent(String(F(",\"uptime_ms\":"))      + String(now));
  server.sendContent(String(F(",\"boot_count\":"))     + String(bootCount));
  server.sendContent(String(F(",\"wifi_connected\":")) + (wifiUp ? "true" : "false"));
  server.sendContent(String(F(",\"ssid\":\""))         + (wifiUp ? WiFi.SSID() : String("")) + "\"");
  server.sendContent(String(F(",\"ip\":\""))           + (wifiUp ? WiFi.localIP().toString() : String("")) + "\"");
  server.sendContent(String(F(",\"rssi_dbm\":"))       + String(rssi));
  server.sendContent(String(F(",\"rssi_quality\":\"")) + String(wifiUp ? rssiQuality(rssi) : "n/a") + "\"");
  server.sendContent(String(F(",\"free_heap\":"))      + String(ESP.getFreeHeap()));
  server.sendContent(String(F(",\"reset_reason\":\"")) + String(gResetReason) + "\"");
  server.sendContent(String(F(",\"ring_count\":"))     + String(ringCount));
  server.sendContent(String(F(",\"last_ring_epoch\":")) + String((unsigned long)lastRingEpoch));
  server.sendContent(String(F(",\"last_ring_ms_ago\":")) + String(ringCount ? (now - lastRingUptimeMs) : 0));
  server.sendContent(String(F(",\"call_pending\":"))   + (callPending ? "true" : "false"));
  server.sendContent(String(F(",\"ringing_now\":"))    + (digitalRead(RING_PIN) == LOW ? "true" : "false"));
  server.sendContent(String(F(",\"heartbeat_ms_ago\":")) + String(now - lastHeartbeatMs));
  server.sendContent(String(F(",\"heartbeat_seq\":")) + String((unsigned long)heartbeatSeq));
  server.sendContent(String(F(",\"real_calls_delivered\":")) + String((unsigned long)realCallsDelivered));

  // TLS-readiness telemetry: the largest CONTIGUOUS free block is the predictive
  // metric for the mbedTLS handshake every CALL/ntfy POST needs. Watch it trend.
  uint32_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  bool frag = (largest < TLS_MIN_CONTIG_BLOCK);
  // SUSTAINED stuck (not instantaneous) -- a normal brief ring must NOT mark the device unhealthy.
  bool detectorStuck = (lineLowSinceMs != 0 && (millis() - lineLowSinceMs) >= LINE_STUCK_MS);
  server.sendContent(String(F(",\"largest_free_block\":")) + String((unsigned long)largest));
  server.sendContent(String(F(",\"min_free_heap\":")) + String((unsigned long)esp_get_minimum_free_heap_size()));
  server.sendContent(String(F(",\"tls_ready\":")) + (frag ? "false" : "true"));

  // Single machine-checkable verdict + fault list. An external monitor can alarm
  // on healthy==false OR on this page going unreachable.
  bool healthy = wifiUp && timeSynced() && !frag && !lowHeapWarned && !detectorStuck && ringDet.armed;
  server.sendContent(String(F(",\"healthy\":")) + (healthy ? "true" : "false"));
  server.sendContent(F(",\"faults\":["));
  {
    bool firstFault = true;
    auto fault = [&](const char* f) {
      if (!firstFault) server.sendContent(F(","));
      server.sendContent(String(F("\"")) + f + "\"");
      firstFault = false;
    };
    if (!wifiUp)        fault("wifi_down");
    if (!timeSynced())  fault("ntp_unsynced");
    if (frag)           fault("frag");
    if (lowHeapWarned)  fault("low_heap");
    if (detectorStuck)  fault("detector_stuck");
    if (g_onProbation)  fault("ota_probation");
    if (!ringDet.armed) fault("detector_unarmed");
  }
  server.sendContent(F("]"));

  // Dead-man's-switch state (no secret URL ever exposed).
  server.sendContent(String(F(",\"deadman_ok\":")) + (deadmanOk ? "true" : "false"));
  server.sendContent(String(F(",\"last_deadman_epoch\":")) + String((unsigned long)lastDeadmanOkEpoch));

  // ---- Provisioning + pull-OTA telemetry (no secrets) ----
  server.sendContent(String(F(",\"provisioned\":")) + (isProvisioned() ? "true" : "false"));
  server.sendContent(String(F(",\"ota_enabled\":")) + (C.otaEnabled ? "true" : "false"));
  server.sendContent(String(F(",\"on_probation\":")) + (g_onProbation ? "true" : "false"));
  server.sendContent(String(F(",\"ota_pending_version\":\"")) + otaPendingVer + "\"");
  server.sendContent(String(F(",\"ota_failed_version\":\"")) + C.otaFailedVer + "\"");  // version that flunked probation (skipped)
  server.sendContent(String(F(",\"last_ota_check_ms_ago\":")) + String(lastOtaCheckMs ? (now - lastOtaCheckMs) : 0));
  server.sendContent(String(F(",\"ota_last_result\":\"")) + otaLastResult + "\"");
  server.sendContent(String(F(",\"ota_last_result_ms_ago\":")) + String(otaLastResultMs ? (now - otaLastResultMs) : 0));
  server.sendContent(String(F(",\"rollback_possible\":")) + (esp_ota_check_rollback_is_possible() ? "true" : "false"));
  {
    const esp_partition_t* run = esp_ota_get_running_partition();
    server.sendContent(String(F(",\"running_partition\":\"")) + (run ? run->label : "") + "\"");
    esp_app_desc_t desc;
    if (run && esp_ota_get_partition_description(run, &desc) == ESP_OK)
      server.sendContent(String(F(",\"running_image_version\":\"")) + desc.version + "\"");
    else
      server.sendContent(F(",\"running_image_version\":\"\""));
  }

  // Ring-pattern detector: armed yet? how much non-ring activity was ignored?
  {
    uint32_t ign, gl, lastIgn, lastLen; BurstRec bl[BURSTLOG_N]; uint8_t bc, bh;
    portENTER_CRITICAL(&ringMux);
    ign = ignoredActivity; gl = glitchCount; lastIgn = lastIgnoredMs; lastLen = lastIgnoredLenMs;
    memcpy(bl, burstLog, sizeof(bl)); bc = burstLogCount; bh = burstLogHead;
    portEXIT_CRITICAL(&ringMux);
    const uint32_t now = millis();      // AFTER the copy, so "ago" can't underflow
    server.sendContent(String(F(",\"ring_armed\":")) + (ringDet.armed ? "true" : "false"));
    server.sendContent(String(F(",\"ring_sampler\":\"")) + (ringTimerOk ? "timer" : "loop") + "\"");
    server.sendContent(String(F(",\"ring_mode\":\"")) + (C.ringMode == RD_MODE_PATTERN ? "pattern" : "single") + "\"");
    server.sendContent(String(F(",\"ring_min_ms\":")) + String((unsigned long)C.ringMinMs));
    server.sendContent(String(F(",\"ignored_line_activity\":")) + String((unsigned long)ign));
    server.sendContent(String(F(",\"line_glitches\":")) + String((unsigned long)gl));
    server.sendContent(String(F(",\"last_ignored_ms_ago\":")) + String(lastIgn ? (now - lastIgn) : 0));
    server.sendContent(String(F(",\"last_ignored_longest_ms\":")) + String((unsigned long)lastLen));
    // Newest first: how long ago each burst (>= 30 ms) started and how long it
    // lasted -- gaps follow from consecutive ago_ms. For checking real-call and
    // real-replug timing in the field.
    server.sendContent(F(",\"recent_bursts\":["));
    for (uint8_t i = 0; i < bc; i++) {
      const BurstRec& b = bl[(bh + BURSTLOG_N - 1 - i) % BURSTLOG_N];
      if (i) server.sendContent(F(","));
      server.sendContent(String(F("{\"ago_ms\":")) + String((unsigned long)(now - b.startMs))
                         + F(",\"len_ms\":") + String((unsigned long)b.lenMs) + F("}"));
    }
    server.sendContent(F("]"));
  }

  // ---- Black box / self-heal ----
  server.sendContent(String(F(",\"restart_why\":\"")) + rebootWhy + "\"");
  server.sendContent(String(F(",\"restart_reported\":")) + (restartReported ? "true" : "false"));
  server.sendContent(String(F(",\"wifi_drops\":")) + String((unsigned)wifiDrops));
  server.sendContent(String(F(",\"last_disconnect_reason\":")) + String((unsigned)lastDiscReason));
  server.sendContent(String(F(",\"net_ok_ms_ago\":")) + String(netEverOk ? (millis() - lastNetOkMs) : 0));
  server.sendContent(String(F(",\"net_fail_probes\":")) + String((unsigned)netFailProbes));
  server.sendContent(String(F(",\"heal_streak\":")) + String((unsigned long)healStreak));
  server.sendContent(String(F(",\"crash_dump_pending\":")) + (crashPending ? "true" : "false"));

  // ring_log streamed per-event (no large String). MUST be the last field.
  server.sendContent(F(",\"ring_log\":{\"count\":"));
  server.sendContent(String(ringLogCount));
  server.sendContent(F(",\"events\":["));
  {
    char line[80];
    for (int i = ringLogCount - 1; i >= 0; i--) {
      uint8_t phys = ringLogPhys((uint8_t)i);
      const RingEvent &e = ringLog[phys];
      formatEvent(e, line, sizeof(line));
      if (i != ringLogCount - 1) server.sendContent(F(","));
      server.sendContent(String(F("{\"epoch\":")) + e.epoch);
      server.sendContent(String(F(",\"uptime_ms\":")) + e.uptimeMs);
      server.sendContent(String(F(",\"sim\":")) + (ringLogSim[phys] ? "true" : "false"));
      server.sendContent(String(F(",\"text\":\"")) + (ringLogSim[phys] ? "[SIM] " : "") + line + F("\"}"));
    }
  }
  server.sendContent(F("]}"));

  server.sendContent(F("}"));
  server.sendContent("");          // terminate the chunked response
  esp_task_wdt_reset();
}

// POST /send-test (auth). Sends to STATUS topic so it never pages the crew.
static void handleSendTest() {
  if (!requireAuth()) return;
  bool ok = sendNtfy(C.ntfyStatus.c_str(), "Tapout TEST",
                     "Manual test alert from the status page.",
                     "default", "test_tube");
  esp_task_wdt_reset();
  server.send(ok ? 200 : 502, "text/plain",
              ok ? "Test alert sent to STATUS topic.\n"
                 : "Send FAILED (check WiFi / outbound 443).\n");
}

// POST /reboot (auth, DEFERRED so the handler never blocks the watchdog).
static void handleReboot() {
  if (!requireAuth()) return;
  strncpy(pendingRebootWhy, "web /reboot button", sizeof(pendingRebootWhy) - 1);
  pendingRebootMs = millis() + 600;       // reboot shortly after replying
  server.send(200, "text/plain", "Rebooting in ~1s...\n");
}

// POST /simulate-ring (auth). Injects a SIMULATED ring through the EXACT real
// pipeline (recordRing -> NVS log w/ real NTP timestamp -> latch -> fireCallAlert
// -> ntfy -> web) so the never-once-fired chain can be proven remotely today.
// Default route = STATUS topic, tagged [SIM]; it does NOT page the crew, does
// NOT touch real dedup state, and does NOT increment real_calls_delivered.
//
// Optional deliberate commissioning page to the CALL topic (proves the crew
// subscription actually receives) is double-gated: ?topic=call AND a
// ?confirm=<WEB_ADMIN_PASS> token, on top of Basic Auth. It still records as a
// SIMULATION (dedup-safe, real_calls_delivered stays 0); only the destination
// + title change. Use rarely, from a trusted same-VLAN host.
static void handleSimulateRing() {
  if (!requireAuth()) return;                 // fail-closed on default password
  // NEVER let a TEST clobber a REAL call that is still being delivered. There is a
  // single call latch; a genuine ring sits callPending=true / callSimulated=false
  // and retries while WiFi is UP but ntfy/DNS is failing. Injecting a sim here would
  // flip callSimulated=true, reset callAttempts, and re-route the (real) dispatch to
  // the STATUS topic tagged [SIM] -- the crew is never paged and real_calls_delivered
  // never increments, violating "never lose a call". Refuse during that window. (The
  // reverse -- a real ring overwriting a pending sim -- stays allowed and correct.)
  if (callPending && !callSimulated) {
    server.send(409, "text/plain",
                "A real CALL alert is currently in flight; refusing to inject a "
                "simulation now. Retry once it has cleared.\n");
    return;
  }
  esp_task_wdt_reset();
  // SAFE DEFAULT: a bare authenticated POST goes to the STATUS topic and does NOT
  // page the crew. Crew-paging is the DOUBLE-GATED opt-in documented above:
  // ?topic=call AND a ?confirm=<web_pass> token, ON TOP of Basic Auth -- enforced
  // HERE on the server, not merely by the browser confirm() in the dashboard form
  // (a curl/script with valid creds previously paged the crew with no args).
  bool wantCall = server.hasArg("topic") && server.arg("topic") == "call";
  if (wantCall && !(server.hasArg("confirm") && server.arg("confirm") == C.webPass)) {
    server.send(403, "text/plain",
                "Crew CALL test refused: ?topic=call requires a ?confirm=<web_admin_"
                "password> token. Crew NOT paged. (Omit topic/confirm for a STATUS-only "
                "plumbing test.)\n");
    return;
  }
  callSimToCall = wantCall;                      // read inside fireCallAlert(true)
  triggerRingPipeline(/*simulated=*/true);      // ALWAYS simulated -> dedup-safe
  esp_task_wdt_reset();
  server.send(200, "text/plain",
    !wantCall
      ? "Quiet test injected -> STATUS topic ([SIM] tagged, crew NOT paged). "
        "Watch ring_count++ and the [SIM] entry; real_calls_delivered stays 0.\n"
      : "TEST ring injected -> CALL topic at MAX priority ([TEST]-labeled -- crew "
        "IS paged, this IS the real alert path). ring_count++ and a [SIM] entry "
        "appear; real_calls_delivered stays 0 (still a test).\n");
}

static void handleNotFound() {
  server.send(404, "text/plain", "Not found\n");
}

// ==================== PROVISIONING (NVS "fhacfg") ======================
// Secrets are NEVER compiled into the published image; they are written to NVS
// either by the SoftAP setup portal (fresh units) or POST /provision (deployed
// units). Both funnel through provisionFromArgs(): only fields that are PRESENT
// in the request are written, so a single-field patch works and unspecified
// fields keep their prior NVS value. Password fields are WRITE-ONLY -- they are
// never echoed back on any page or in JSON.
static void saveField(const char* k, const String& v) {
  // Write when a non-empty value is supplied, or when overwriting an existing
  // key (lets an operator deliberately blank a field, e.g. clear the deadman URL).
  if (v.length() || cfg.isKey(k)) cfg.putString(k, v);
}

static void provisionFromArgs() {
  cfg.begin("fhacfg", /*readOnly=*/false);          // RW
  if (server.hasArg("wifi_ssid"))    saveField("wifi_ssid",    server.arg("wifi_ssid"));
  if (server.hasArg("wifi_pass"))    saveField("wifi_pass",    server.arg("wifi_pass"));
  if (server.hasArg("ntfy_call"))    saveField("ntfy_call",    server.arg("ntfy_call"));
  if (server.hasArg("ntfy_status"))  saveField("ntfy_status",  server.arg("ntfy_status"));
  if (server.hasArg("ota_pass"))     saveField("ota_pass",     server.arg("ota_pass"));
  if (server.hasArg("web_user"))     saveField("web_user",     server.arg("web_user"));
  if (server.hasArg("web_pass"))     saveField("web_pass",     server.arg("web_pass"));
  if (server.hasArg("tz"))           saveField("tz",           server.arg("tz"));
  if (server.hasArg("ntp1"))         saveField("ntp1",         server.arg("ntp1"));
  if (server.hasArg("ntp2"))         saveField("ntp2",         server.arg("ntp2"));
  if (server.hasArg("ntp3"))         saveField("ntp3",         server.arg("ntp3"));
  if (server.hasArg("deadman")) {    // applied live: no reboot needed to start/stop check-ins
    saveField("deadman", server.arg("deadman"));
    C.deadman = server.arg("deadman");
  }
  if (server.hasArg("ota_manifest")) saveField("ota_manifest", server.arg("ota_manifest"));
  if (server.hasArg("ota_enabled"))  cfg.putBool("ota_enabled",  server.arg("ota_enabled") == "1");
  // Clamp to a sane floor/ceiling: toInt() yields 0 for blank/non-numeric input,
  // which would make the loop scheduler run otaCheckManifest() every pass.
  if (server.hasArg("ota_interval")) cfg.putUInt("ota_interval", clampOtaInterval((uint32_t)server.arg("ota_interval").toInt()));
  if (server.hasArg("ring_mode")) {           // "single" (default) | "pattern"
    C.ringMode = server.arg("ring_mode") == "pattern" ? RD_MODE_PATTERN : RD_MODE_SINGLE;
    cfg.putUChar("ring_mode", C.ringMode);
  }
  if (server.hasArg("ring_min_ms")) {
    C.ringMinMs = clampRingMinMs((uint32_t)server.arg("ring_min_ms").toInt());
    cfg.putUInt("ring_min_ms", C.ringMinMs);
  }
  cfg.putBool("provisioned", true);
  cfg.end();
  esp_task_wdt_reset();                              // NVS commit can take a few ms
  applyRingConfig();                                 // ring mode takes effect immediately
}

// GET / in SETUP MODE -- the SoftAP provisioning form. Password fields render
// EMPTY (write-only). No secrets are ever pre-filled.
static void handleSetupForm() {
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");
  server.sendContent(F(
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Tapout Setup</title><style>"
    "body{font-family:system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}"
    ".wrap{max-width:520px;margin:0 auto;padding:16px}"
    "h1{font-size:1.2rem}label{display:block;margin:10px 0 3px;color:#9aa3af;font-size:.85rem}"
    "input{width:100%;box-sizing:border-box;padding:8px;border-radius:8px;border:1px solid #333;"
    "background:#1a1d24;color:#e6e6e6}button{margin-top:16px;padding:10px 16px;border-radius:8px;"
    "border:0;background:#2563eb;color:#fff;font-weight:600}.sub{color:#9aa3af;font-size:.8rem}"
    "</style></head><body><div class='wrap'><h1>Tapout setup</h1>"
    "<p class='sub'>This device is UNPROVISIONED. Enter your settings; they are stored in "
    "on-device NVS, never in the firmware image. Passwords are write-only.</p>"
    "<form method='POST' action='/save'>"
    "<label>WiFi SSID</label><input name='wifi_ssid' required>"
    "<label>WiFi password</label><input name='wifi_pass' type='password'>"
    "<label>ntfy CALL url (crew is paged)</label><input name='ntfy_call' placeholder='https://ntfy.sh/...'>"
    "<label>ntfy STATUS url (monitoring)</label><input name='ntfy_status' placeholder='https://ntfy.sh/...'>"
    "<label>Web admin user</label><input name='web_user' value='crew'>"
    "<label>Web admin password</label><input name='web_pass' type='password'>"
    "<label>OTA (ArduinoOTA) password</label><input name='ota_pass' type='password'>"
    "<label>Timezone (POSIX TZ)</label><input name='tz' value='EST5EDT,M3.2.0,M11.1.0'>"
    "<label>NTP server 1</label><input name='ntp1' value='192.168.10.1'>"
    "<label>Dead-man URL (optional)</label><input name='deadman'>"
    "<label>OTA manifest url (optional)</label><input name='ota_manifest' placeholder='https://raw.githubusercontent.com/...'>"
    "<label>Enable auto pull-OTA? (1=yes,0=no)</label><input name='ota_enabled' value='0'>"
    "<label>OTA check interval (minutes)</label><input name='ota_interval' value='360'>"
    "<label>Ring mode: single = page on the 1st ring (default), pattern = only on a 2-ring pattern</label>"
    "<input name='ring_mode' value='single'>"
    "<button type='submit'>Save &amp; reboot</button></form>"
    "<p class='sub'>After saving, the device reboots and joins your WiFi.</p>"
    "</div></body></html>"));
  server.sendContent("");
  esp_task_wdt_reset();
}

// Per-device SoftAP WPA2 passphrase, derived from this chip's factory eFuse MAC.
// Stable across reboots, unique per unit, >= 8 chars (WPA2 minimum). Printed to
// the serial console at setup so the commissioning tech can join; it is NOT a
// secret on the level of the crew topics (provisioning is trust-on-first-use),
// but it stops anyone merely in RF range from silently hijacking config of a
// life-safety device (redirecting ntfy, locking out the owner, etc.).
static String setupApPassphrase() {
  uint64_t mac = ESP.getEfuseMac();
  char buf[16];
  snprintf(buf, sizeof(buf), "fh-%08X", (uint32_t)(mac & 0xFFFFFFFFULL));  // "fh-XXXXXXXX" (11 chars)
  return String(buf);
}

// SoftAP captive portal for fresh units. WPA2-protected AP "tapout-setup" at
// 192.168.4.1; DNS catch-all bounces every host to the form. handleRing() keeps
// running in the setup loop (life-safety path stays armed); ntfy delivery is
// simply suppressed because WiFi STA is not connected.
static void startSetupPortal() {
  inSetupMode = true;
  String pass = setupApPassphrase();
  Serial.println(F("[setup] UNPROVISIONED -> starting SoftAP 'tapout-setup' (192.168.4.1)"));
  Serial.printf("[setup] AP is WPA2-protected; passphrase for THIS unit: %s\n", pass.c_str());
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  WiFi.softAP("tapout-setup", pass.c_str());      // WPA2-protected (per-device key)
  dns.start(53, "*", WiFi.softAPIP());               // captive catch-all (async; do NOT poll)

  server.on("/",     HTTP_GET,  handleSetupForm);
  server.on("/save", HTTP_POST, [](){
    provisionFromArgs();
    server.send(200, "text/plain", "Saved. Rebooting...\n");
    noteReboot("setup portal: new settings saved");
    delay(300);
    ESP.restart();
  });
  server.onNotFound([](){                            // captive-portal redirect to the form
    server.sendHeader("Location", "http://192.168.4.1/", true);
    server.send(302, "text/plain", "");
  });
  server.begin();
}

// ==================== SIGNED PULL-OTA + AUTO-ROLLBACK ==================
// RAIL A (authenticity): the embedded RSA-2048 PUBLIC_KEY verifies every image's
// 512-byte RSA-PSS/SHA-256 trailer (in verifyImageSignature()) BEFORE it is ever
// made bootable. TLS stays setInsecure() (the only thing the IoT VLAN allows); the
// signature -- not the transport -- is the trust anchor. A MITM on 443 cannot
// push firmware without the private key (which lives only in the GH Actions
// secret OTA_SIGNING_KEY, never in the repo).
//
// RAIL B (availability): a freshly-flashed image boots PENDING_VERIFY and must
// prove it can reach WiFi + ntfy within ~60 s (otaServiceProbation) or the
// device AUTO-ROLLS BACK to the previous good slot. A crash/hang before that
// runs is caught by the bootloader/task WDT, which also reverts while still
// PENDING_VERIFY. The running slot is never invalidated, so a re-rollback is
// always possible.

// Signed images carry a fixed 512-byte trailer (RSA-2048 signature, zero-padded
// to 512) appended after the firmware -- matches the esp32 core's bin_signing.py.
static const size_t SIG_TRAILER_SIZE = 512;

// RAIL A signature check, done in-sketch with mbedtls instead of the core's
// -DUPDATE_SIGN path. That path is unusable on the Nano ESP32 (nano_nora): the
// variant's USB-DFU shim (dfu_callbacks.cpp) #includes Updater.cpp inside an
// anonymous namespace, so with UPDATE_SIGN defined globally it would need
// SHA2Builder's methods defined in that namespace and fails to link. Verifying
// here keeps the published .bin secret-free and the scheme byte-identical:
//   SHA-256(firmware bytes)  +  RSA-PSS(MGF1-SHA256, salt = keylen-hashlen-2).
// Fail-closed: any parse/verify error returns false and the image is rejected.
static bool verifyImageSignature(const uint8_t hash32[32], const uint8_t* sig, size_t sigLen) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  // PUBLIC_KEY is a NUL-terminated PEM; PUBLIC_KEY_LEN includes the terminator.
  if (mbedtls_pk_parse_public_key(&pk, (const uint8_t*)PUBLIC_KEY, PUBLIC_KEY_LEN) != 0) { mbedtls_pk_free(&pk); return false; }
  if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_RSA)                                        { mbedtls_pk_free(&pk); return false; }
  size_t key_len = (mbedtls_pk_get_bitlen(&pk) + 7) / 8;   // 256 bytes for RSA-2048
  if (key_len == 0 || key_len > sigLen)                                                  { mbedtls_pk_free(&pk); return false; }
  int salt = (int)key_len - 32 - 2;                        // PSS.MAX_LENGTH salt
  if (salt < 0)                                                                          { mbedtls_pk_free(&pk); return false; }
  mbedtls_pk_rsassa_pss_options opt;
  opt.mgf1_hash_id      = MBEDTLS_MD_SHA256;
  opt.expected_salt_len = salt;
  int ret = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &opt, &pk,
                                  MBEDTLS_MD_SHA256, hash32, 32, sig, key_len);
  mbedtls_pk_free(&pk);
  return ret == 0;
}

// "a.b.c" -> sortable integer; 0 on parse failure (treated as "older").
static uint32_t semver(const String& v) {
  int a = 0, b = 0, c = 0;
  if (sscanf(v.c_str(), "%d.%d.%d", &a, &b, &c) != 3) return 0;
  return (uint32_t)a * 1000000UL + (uint32_t)b * 1000UL + (uint32_t)c;
}

// Minimal JSON field extractors for the small fixed manifest (no allocator churn).
static String manifestStr(const String& body, const char* key) {
  String pat = String("\"") + key + "\"";
  int k = body.indexOf(pat); if (k < 0) return String();
  int colon = body.indexOf(':', k + pat.length()); if (colon < 0) return String();
  int q1 = body.indexOf('"', colon + 1); if (q1 < 0) return String();
  int q2 = body.indexOf('"', q1 + 1);    if (q2 < 0) return String();
  return body.substring(q1 + 1, q2);
}
static uint32_t manifestNum(const String& body, const char* key) {
  String pat = String("\"") + key + "\"";
  int k = body.indexOf(pat); if (k < 0) return 0;
  int colon = body.indexOf(':', k + pat.length()); if (colon < 0) return 0;
  int i = colon + 1;
  while (i < (int)body.length() && (body[i] == ' ' || body[i] == '\t')) i++;
  uint32_t n = 0; bool any = false;
  while (i < (int)body.length() && body[i] >= '0' && body[i] <= '9') { n = n*10 + (body[i]-'0'); i++; any = true; }
  return any ? n : 0;
}

// RAIL A precondition + provisioning gate: pull-OTA only runs when enabled, the
// device is provisioned, a manifest URL is set, AND a REAL signing key is
// embedded (the shipped placeholder public_key.h keeps OTA disabled).
static bool otaEnabledAndSafe() {
  return C.otaEnabled
      && isProvisioned()
      && !C.otaManifest.isEmpty()
      && !looksLikePlaceholder((const char*)PUBLIC_KEY)   // dummy key => OTA stays off
      && PUBLIC_KEY_LEN > 64;
}

// NEVER update during a call / unhealthy state. Also requires that the RUNNING
// image is itself a committed-VALID rollback anchor: it is the slot we fall back
// TO after the new image is flashed, so requiring a *pre-existing second* valid
// slot (esp_ota_check_rollback_is_possible) is backwards -- on a freshly
// serial-flashed unit the other slot is empty and the first pull-OTA would be
// permanently blocked. setup() commits the running image VALID at boot, so this
// passes from the first boot onward while still refusing to update from an
// UNDEFINED/PENDING image that could not serve as a fallback.
static bool otaSafeToStart() {
  if (otaState != PULL_OTA_IDLE) return false;                         // already staged, waiting to reboot
  if (callPending) return false;                                       // a call is latched/in-flight
  if (digitalRead(RING_PIN) == LOW) return false;                      // line active right now
  { uint32_t act = lastRingActiveMs;   // read BEFORE millis(): the 5 ms sampler may update it concurrently
    if (millis() - act < RING_REARM_IDLE_MS) return false; }           // just rang
  if (WiFi.status() != WL_CONNECTED) return false;
  if (heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < TLS_MIN_CONTIG_BLOCK) return false;
  const esp_partition_t* run = esp_ota_get_running_partition();
  esp_ota_img_states_t st;
  if (!run || esp_ota_get_state_partition(run, &st) != ESP_OK) return false;
  if (st != ESP_OTA_IMG_VALID) return false;       // running image must be a committed fallback
  return true;
}

// Stream the signed image, verify the signature (RAIL A), stage it, and reboot.
// Feeds the WDT and pumps handleRing() every chunk so the life-safety path is
// never starved during a multi-MB flash over slow TLS.
static bool otaDownloadAndFlash(const String& url, size_t totalSize /* firmware + 512B sig */) {
  if (!otaSafeToStart()) return false;
  Serial.printf("[ota] downloading %u B from %s\n", (unsigned)totalSize, url.c_str());
  otaState = PULL_OTA_DOWNLOADING;
  statusOta();                                       // magenta while flashing

  WiFiClientSecure net; net.setInsecure();           // signature is the trust anchor
  net.setHandshakeTimeout(TLS_HANDSHAKE_TIMEOUT_S);  // cap TLS handshake (< WDT)
  HTTPClient http;
  http.setConnectTimeout(8000);
  http.setTimeout(15000);
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);   // raw->CDN + release-asset 302s
  if (!http.begin(net, url)) { otaState = PULL_OTA_IDLE; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { Serial.printf("[ota] GET failed HTTP %d\n", code); http.end(); otaState = PULL_OTA_IDLE; return false; }
  if ((size_t)http.getSize() != totalSize) {
    Serial.printf("[ota] size mismatch: server %d vs manifest %u\n", http.getSize(), (unsigned)totalSize);
    http.end(); otaState = PULL_OTA_IDLE; return false;
  }

  // RAIL A layout: the image is firmware bytes followed by a fixed 512-byte
  // signature trailer. We hash ONLY the firmware bytes, stage ONLY the firmware
  // to flash, capture the trailer, then verify it BEFORE the slot is committed.
  if (totalSize <= SIG_TRAILER_SIZE) { Serial.println(F("[ota] image too small for sig trailer")); http.end(); otaState = PULL_OTA_IDLE; return false; }
  const size_t firmwareSize = totalSize - SIG_TRAILER_SIZE;

  if (!Update.begin(firmwareSize)) { Serial.printf("[ota] Update.begin failed: %s\n", Update.errorString()); http.end(); otaState = PULL_OTA_IDLE; return false; }

  mbedtls_sha256_context sha; mbedtls_sha256_init(&sha);
  if (mbedtls_sha256_starts(&sha, 0 /* 0 => SHA-256 */) != 0) { mbedtls_sha256_free(&sha); Update.abort(); http.end(); otaState = PULL_OTA_IDLE; return false; }
  uint8_t sigBuf[SIG_TRAILER_SIZE];
  size_t  sigGot = 0;

  WiFiClient* s = http.getStreamPtr();
  uint8_t buf[1024];
  size_t written = 0;
  uint32_t lastData = millis();
  while (http.connected() && written < totalSize) {
    size_t avail = s->available();
    if (avail) {
      int n = s->readBytes(buf, min(avail, sizeof(buf)));
      if (n <= 0) {
        Serial.println(F("[ota] read error -- aborting"));
        mbedtls_sha256_free(&sha); Update.abort(); http.end(); otaState = PULL_OTA_IDLE; return false;
      }
      size_t off = written, endo = written + (size_t)n;
      // firmware portion -> hash it AND stage it to flash
      if (off < firmwareSize) {
        size_t fwLen = (endo < firmwareSize ? endo : firmwareSize) - off;
        if (mbedtls_sha256_update(&sha, buf, fwLen) != 0 || Update.write(buf, fwLen) != fwLen) {
          Serial.println(F("[ota] write error -- aborting"));
          mbedtls_sha256_free(&sha); Update.abort(); http.end(); otaState = PULL_OTA_IDLE; return false;
        }
      }
      // signature-trailer portion -> capture only, NEVER written to flash
      if (endo > firmwareSize) {
        size_t sigStart = (off > firmwareSize ? off : firmwareSize);
        size_t bufOff   = sigStart - off;
        size_t segLen   = endo - sigStart;
        size_t dst      = sigStart - firmwareSize;
        if (dst + segLen <= SIG_TRAILER_SIZE) { memcpy(sigBuf + dst, buf + bufOff, segLen); sigGot += segLen; }
      }
      written += n;
      lastData = millis();
    } else if (millis() - lastData > 15000) {
      Serial.println(F("[ota] stream stalled -- aborting"));
      mbedtls_sha256_free(&sha); Update.abort(); http.end(); otaState = PULL_OTA_IDLE; return false;
    }
    esp_task_wdt_reset();        // a multi-MB TLS download can exceed the 30 s WDT
    handleRing();                // NEVER starve the life-safety path during a flash
    // A GENUINE ring just latched mid-download: abort the OTA and yield to the
    // life-safety path. The pending CALL is RAM-only; if we instead finished the
    // flash and ESP.restart()'d, an unsent/failed dispatch would be destroyed by
    // the reboot ("never lose a call" / "never update while a call is in-flight").
    // We keep the running image intact so serviceCallQueue() can deliver/retry.
    if (callPending && !callSimulated) {
      Serial.println(F("[ota] real CALL latched mid-download -- aborting OTA, yielding to alert"));
      mbedtls_sha256_free(&sha); Update.abort(); http.end(); otaState = PULL_OTA_IDLE;
      return false;
    }
    delay(1);
  }
  http.end();

  uint8_t imgHash[32];
  bool hashOk = (mbedtls_sha256_finish(&sha, imgHash) == 0);
  mbedtls_sha256_free(&sha);

  if (!hashOk || written != totalSize || sigGot != SIG_TRAILER_SIZE) {
    Serial.printf("[ota] incomplete download %u/%u (sig %u/%u) -- aborting\n",
                  (unsigned)written, (unsigned)totalSize, (unsigned)sigGot, (unsigned)SIG_TRAILER_SIZE);
    Update.abort(); otaState = PULL_OTA_IDLE; return false;
  }

  // RAIL A: reject unless the RSA-PSS/SHA-256 signature verifies. Fail-closed --
  // a bad/forged image is never made bootable; the running slot is untouched.
  if (!verifyImageSignature(imgHash, sigBuf, SIG_TRAILER_SIZE)) {
    Serial.println(F("[ota] signature verification FAILED -- rejecting image"));
    Update.abort();
    sendNtfy(C.ntfyStatus.c_str(), "OTA REJECTED",
             "Bad signature on pulled image -- ignored, running image untouched.",
             "high", "warning");
    otaState = PULL_OTA_IDLE;
    return false;                // bad slot NEVER made bootable
  }

  // RAIL A anti-downgrade/replay: the RSA-PSS signature only authenticates the
  // firmware BYTES, not the manifest's claimed version/url (both ride the
  // setInsecure() 443 path). A MITM can advertise version 99.0.0 but point url at
  // any genuinely-signed OLDER release; the signature would verify and we'd flash
  // a downgrade. Defend by reading the STAGED image's own embedded esp_app_desc
  // and requiring it to be strictly newer than what we run AND to match the
  // manifest's claimed version -- so the version is taken from the signed binary,
  // not the attacker-controllable manifest. Reject (no commit) on any mismatch.
  // Anti-downgrade gate. NOTE: arduino-esp32 sets esp_app_desc.version to a
  // constant build hash (e.g. "43a8f6d"), NOT our FW_VERSION semver, so the
  // staged image's descriptor cannot carry the app version. We therefore gate on
  // the MANIFEST version (otaPendingVer) being strictly newer than what we run
  // (already enforced in otaCheckManifest; re-asserted here). The image BYTES are
  // authenticated by the RSA-PSS signature, so no unsigned code can be injected;
  // the residual risk is a MITM on the setInsecure() 443 path serving an OLDER
  // genuinely-signed release under an inflated manifest version.
  // TODO(security): persist a monotonic NVS version floor to also block that.
  if (semver(otaPendingVer) <= semver(FW_VERSION)) {
    otaNote("rejected: manifest version not newer than running");
    Update.abort();
    sendNtfy(C.ntfyStatus.c_str(), "OTA REJECTED",
             (String("Manifest ") + otaPendingVer + " not newer than running "
              + FW_VERSION + " -- ignored.").c_str(), "high", "warning");
    otaState = PULL_OTA_IDLE;
    return false;
  }

  if (!Update.end(true)) {       // commit: mark the verified slot bootable
    Serial.printf("[ota] Update.end failed: %s\n", Update.errorString());
    otaState = PULL_OTA_IDLE;
    return false;
  }

  // Staged + verified. Record what we expect to be running after reboot, then WE
  // reboot (not a library). Next boot detects PENDING_VERIFY and starts probation.
  cfg.begin("fhacfg", false);
  cfg.putBool("ota_pending", true);
  cfg.putString("ota_pend_ver", otaPendingVer);
  cfg.end();
  otaState = PULL_OTA_PENDING_REBOOT;
  sendNtfy(C.ntfyStatus.c_str(), "OTA staged",
           (String("v") + otaPendingVer + " downloaded + signature verified + written to the "
            "standby slot. Rebooting into a 60s health trial...").c_str(),
           "default", "arrows_counterclockwise");
  Serial.println(F("[ota] staged + verified -- rebooting into trial"));
  // Reboot via loop()'s deferred-reboot handler, which holds while a real call is
  // confirmed/in flight (a direct ESP.restart() here would wipe it).
  snprintf(pendingRebootWhy, sizeof(pendingRebootWhy), "OTA update to v%s", otaPendingVer);
  pendingRebootMs = millis() + 500;
  return true;
}

// Fetch the manifest, gate on semver + min_supported, then download+flash.
// Record an OTA poll outcome for /status.json (LAN-visible even when the egress
// IP is ntfy-throttled). Serial mirror is for local debugging.
static void otaNote(const char* msg) {
  strncpy(otaLastResult, msg, sizeof(otaLastResult) - 1);
  otaLastResult[sizeof(otaLastResult) - 1] = 0;
  otaLastResultMs = millis();
  Serial.printf("[ota] %s\n", msg);
}

static void otaCheckManifest() {
  if (!otaEnabledAndSafe() || !otaSafeToStart()) return;
  Serial.println(F("[ota] checking manifest"));
  WiFiClientSecure net; net.setInsecure();
  net.setHandshakeTimeout(TLS_HANDSHAKE_TIMEOUT_S);  // cap TLS handshake (< WDT)
  HTTPClient http;
  http.setConnectTimeout(8000);
  http.setTimeout(8000);
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
  if (!http.begin(net, C.otaManifest)) return;
  esp_task_wdt_reset();
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    char m[72]; snprintf(m, sizeof(m), "poll: manifest fetch failed HTTP %d", code);
    otaNote(m); http.end();   // LAN-visible in /status.json only -- no ntfy ping on routine poll errors
    return;
  }
  String body = http.getString();
  http.end();
  esp_task_wdt_reset();

  String ver  = manifestStr(body, "version");
  String url  = manifestStr(body, "url");
  uint32_t sz = manifestNum(body, "size");
  String minv = manifestStr(body, "min_supported");
  if (ver.isEmpty() || url.isEmpty() || sz == 0) { otaNote("poll: manifest parse failed"); return; }

  // Monotonic anti-downgrade gate (ANTI_ROLLBACK fuse is off, so enforce here).
  if (semver(ver) <= semver(FW_VERSION)) {
    char m[88]; snprintf(m, sizeof(m), "polled: no new version (running %s, latest %s)", FW_VERSION, ver.c_str());
    otaNote(m);   // LAN-visible in /status.json only -- NO ntfy ping on routine no-update polls
    return;
  }

  // Failed-version memory: if this EXACT version already flunked its 60s health
  // probation and rolled back, refuse to re-stage it. Otherwise the old image
  // re-fetches the same manifest each interval, re-flashes the same bad image,
  // fails again, and rolls back forever -- an unbounded reflash/reboot cycle
  // (flash wear + repeated degraded probation windows). The marker is cleared
  // automatically once a successful commit or a strictly-newer version appears.
  if (C.otaFailedVer.length() && ver == C.otaFailedVer) {
    Serial.printf("[ota] version %s previously failed probation -- not re-staging\n", ver.c_str());
    return;
  }
  if (minv.length() && semver(FW_VERSION) < semver(minv)) {
    Serial.printf("[ota] manifest requires >= %s, refusing skip from %s\n", minv.c_str(), FW_VERSION);
    sendNtfy(C.ntfyStatus.c_str(), "OTA skipped",
             (String("Update ") + ver + " needs min_supported " + minv + " > running " + FW_VERSION).c_str(),
             "default", "warning");
    return;
  }

  strncpy(otaPendingVer, ver.c_str(), sizeof(otaPendingVer) - 1);
  otaPendingVer[sizeof(otaPendingVer) - 1] = 0;
  char m[110]; snprintf(m, sizeof(m), "v%s found (running v%s) -- downloading the signed image...", ver.c_str(), FW_VERSION);
  otaNote(m);
  sendNtfy(C.ntfyStatus.c_str(), "OTA update found", m, "default", "arrow_down");
  if (!otaDownloadAndFlash(url, sz)) {     // returns ONLY on failure (success reboots into the new image)
    char f[100]; snprintf(f, sizeof(f), "download/flash of %s FAILED (rejected/timeout/size) -- staying on %s", ver.c_str(), FW_VERSION);
    otaNote(f);
    sendNtfy(C.ntfyStatus.c_str(), "OTA FAILED", f, "high", "warning");
  }
}

// POST /check-ota (auth). Manual trigger + full diagnosis: reports every OTA gate
// and a read-only manifest fetch result, and -- if everything is GO and a newer
// signed version exists -- forces an immediate real check (download) next loop.
static void handleCheckOta() {
  if (!requireAuth()) return;
  esp_task_wdt_reset();

  bool enabled     = C.otaEnabled;
  bool prov        = isProvisioned();
  bool manifestSet = !C.otaManifest.isEmpty();
  bool keyReal     = !looksLikePlaceholder((const char*)PUBLIC_KEY) && PUBLIC_KEY_LEN > 64;
  bool callP       = callPending;
  bool ringActive  = (digitalRead(RING_PIN) == LOW);
  uint32_t lastAct = lastRingActiveMs;  // read before millis() (sampler writes it concurrently)
  bool justRang    = (millis() - lastAct < RING_REARM_IDLE_MS);
  bool wifi        = (WiFi.status() == WL_CONNECTED);
  bool heapOk      = (heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) >= TLS_MIN_CONTIG_BLOCK);
  const esp_partition_t* run = esp_ota_get_running_partition();
  esp_ota_img_states_t st = (esp_ota_img_states_t)0xFFFFFFFFu;
  bool stOk    = run && esp_ota_get_state_partition(run, &st) == ESP_OK;
  bool imgValid = stOk && st == ESP_OTA_IMG_VALID;

  int mhttp = -1; String mver, murl; uint32_t msz = 0;
  if (wifi && manifestSet) {
    WiFiClientSecure net; net.setInsecure();
    net.setHandshakeTimeout(TLS_HANDSHAKE_TIMEOUT_S);
    HTTPClient http;
    http.setConnectTimeout(8000); http.setTimeout(8000);
    http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
    if (http.begin(net, C.otaManifest)) {
      esp_task_wdt_reset();
      mhttp = http.GET();
      if (mhttp == HTTP_CODE_OK) {
        String body = http.getString();
        mver = manifestStr(body, "version");
        murl = manifestStr(body, "url");
        msz  = manifestNum(body, "size");
      }
      http.end();
    }
    esp_task_wdt_reset();
  }

  bool gates = enabled && prov && manifestSet && keyReal && !callP && !ringActive
            && !justRang && wifi && heapOk && imgValid;
  bool newer = mver.length() && semver(mver) > semver(FW_VERSION);
  bool wouldUpdate = gates && newer && murl.length() && msz;
  if (wouldUpdate) lastOtaCheckMs = 0;    // scheduler fires otaCheckManifest -> download next loop

  // Confirm the MANUAL check on the STATUS thread (user-initiated, so not spammy).
  // Ping ONLY when the manual check actually finds a new version (no spam on
  // no-update / gate-blocked manual checks -- the JSON response already says so).
  if (wouldUpdate) {
    char p[128]; snprintf(p, sizeof(p), "Manual check: v%s available -> starting update from v%s", mver.c_str(), FW_VERSION);
    sendNtfy(C.ntfyStatus.c_str(), "OTA check (manual)", p, "default", "mag");
  }

  String j = String(F("{\"current\":\"")) + FW_VERSION + "\",\"gates\":{";
  j += String(F("\"enabled\":"))      + (enabled?"true":"false");
  j += String(F(",\"provisioned\":")) + (prov?"true":"false");
  j += String(F(",\"manifest_set\":"))+ (manifestSet?"true":"false");
  j += String(F(",\"key_real\":"))    + (keyReal?"true":"false");
  j += String(F(",\"call_pending\":"))+ (callP?"true":"false");
  j += String(F(",\"ring_active\":")) + (ringActive?"true":"false");
  j += String(F(",\"just_rang\":"))   + (justRang?"true":"false");
  j += String(F(",\"wifi\":"))        + (wifi?"true":"false");
  j += String(F(",\"heap_ok\":"))     + (heapOk?"true":"false");
  j += String(F(",\"img_state\":"))   + (uint32_t)st;
  j += String(F(",\"img_valid\":"))   + (imgValid?"true":"false");
  j += String(F("},\"manifest_http\":")) + mhttp;
  j += String(F(",\"manifest_version\":\"")) + mver + "\"";
  j += String(F(",\"manifest_size\":")) + msz;
  j += String(F(",\"newer\":"))        + (newer?"true":"false");
  j += String(F(",\"would_update\":")) + (wouldUpdate?"true":"false") + "}";
  server.send(200, "application/json", j + "\n");
}

// RAIL B part 1: detect that we just booted a freshly-flashed (PENDING_VERIFY)
// image. Called very early in setup() so the 60 s trial clock starts at boot.
static void otaCheckProbationOnBoot() {
  const esp_partition_t* run = esp_ota_get_running_partition();
  esp_ota_img_states_t st;
  if (run && esp_ota_get_state_partition(run, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY) {
    g_onProbation   = true;
    trialDeadlineMs = millis() + 60000;     // 60 s to prove health
    Serial.println(F("[ota] booted PENDING_VERIFY -- on 60s health probation"));
    return;
  }
  // NOT on probation: commit the running image as a VALID rollback anchor. This is
  // idempotent (a no-op once already VALID) and is what BOOTSTRAPS RAIL B -- a
  // serial-flashed image boots UNDEFINED and would otherwise never be a usable
  // fallback, blocking the first pull-OTA (otaSafeToStart) AND leaving any future
  // failed update with no committed slot to revert to. Marking it VALID here makes
  // the running image both the start-gate anchor and the guaranteed rollback target.
  esp_ota_mark_app_valid_cancel_rollback();
}

// RAIL B part 2: while on probation, COMMIT once healthy (WiFi + reach ntfy), or
// ROLL BACK to the previous good image once the 60 s deadline passes. Health
// deliberately excludes NTP/web/mDNS so a perfectly good image can never
// false-revert just because an optional subsystem is degraded.
static void otaServiceProbation() {
  if (!g_onProbation) return;

  // THROTTLE the health probe. httpGetBounded() is a BLOCKING TLS GET that can
  // sit ~4s on a failed connect, during which handleRing() does not run. Firing
  // it every loop pass -- exactly when a freshly-flashed image is least healthy --
  // would punch repeated multi-second blind spots into the life-safety path across
  // the 60s trial. Probe at most once every PROBE_INTERVAL_MS, and never issue the
  // blocking GET until WiFi is actually up. handleRing() runs immediately before
  // and after the probe so a ring is sampled around the one blocking call.
  static const uint32_t PROBE_INTERVAL_MS = 5000;
  static uint32_t lastProbeMs = 0;

  if (WiFi.status() != WL_CONNECTED) {
    // Not even WiFi yet -- cheap, non-blocking. Fall through to the deadline check.
  } else if (lastProbeMs == 0 || (millis() - lastProbeMs) >= PROBE_INTERVAL_MS) {
    lastProbeMs = millis();
    handleRing();                                   // sample the line right before the blocking GET
    bool healthy = httpGetBounded(C.ntfyCall.c_str());
    handleRing();                                   // and right after it returns
    if (healthy) {
      esp_ota_mark_app_valid_cancel_rollback();     // COMMIT -> VALID
      g_onProbation = false;
      cfg.begin("fhacfg", false);
      cfg.putBool("ota_pending", false);
      cfg.remove("ota_failed_ver");                 // this version proved healthy -> clear any stale marker
      cfg.end();
      C.otaFailedVer = "";
      sendNtfy(C.ntfyStatus.c_str(), "Update successful",
               (String("Successfully updated and trialed firmware v") + FW_VERSION +
                " -- passed the 60s health trial and committed (no rollback). Now running v"
                + FW_VERSION + ".").c_str(),
               "default", "white_check_mark,tada");
      Serial.println(F("[ota] probation PASSED -- image committed"));
      return;
    }
  }

  if ((int32_t)(millis() - trialDeadlineMs) >= 0) {
    // A real call confirmed/in flight: hold the rollback so the restart doesn't wipe
    // it -- but only briefly. This image failed because it can't reach ntfy, so the
    // call may never deliver from here; after 2 min, roll back regardless.
    if ((int32_t)(millis() - trialDeadlineMs) < 120000 && realCallInFlight()) return;
    Serial.println(F("[ota] probation FAILED -- rolling back"));
    // Remember THIS version (the trial image's own FW_VERSION) as failed BEFORE we
    // revert, so the rolled-back old image refuses to re-stage it next interval and
    // the auto-update can't churn-loop on a bad-but-signed build.
    cfg.begin("fhacfg", false);
    cfg.putString("ota_failed_ver", FW_VERSION);
    cfg.end();
    sendNtfy(C.ntfyStatus.c_str(), "OTA rolled back",
             (String("Firmware v") + FW_VERSION + " FAILED its 60s health trial "
              "(WiFi/ntfy unreachable) -- auto-reverted to the previous good image.").c_str(),
             "high", "warning");
    {
      char why[72];
      snprintf(why, sizeof(why), "OTA rollback: v%s failed its 60 s health trial", FW_VERSION);
      noteReboot(why);
    }
    delay(200);
    esp_ota_mark_app_invalid_rollback_and_reboot();   // REVERT to previous good slot (no return)
  }
}

// ==================== BLACK BOX + SELF-HEAL (v2.0.10) ==================
// Why: the unit has needed manual reboots a few times and nothing recorded what
// happened. Now:
//   * A small flight recorder (checkpoint + last BOX_EVENTS events) is kept in
//     RTC memory (survives crash / watchdog / software resets; refreshed every
//     minute) AND in NVS (survives power loss; written every 5 min and before
//     every intentional restart).
//   * Every intentional restart records WHY first. After any restart, the first
//     thing sent once WiFi is back is a "Tapout restarted" report on STATUS:
//     cause (requested / power cut / brownout / crash / watchdog hang), how long
//     it was down, what it looked like just before (heap, WiFi, signal, last
//     successful send, failure streak) and the recent events. Unexpected causes
//     go out at HIGH priority. A saved crash dump is summarised in a second
//     "crash report" message, then erased.
//   * Self-heal: "WiFi connected but nothing gets through" was invisible to the
//     old code (it only reconnected when WiFi reported DISconnected) and the
//     watchdog stays happy, so the unit just went dark. Now a cheap probe runs
//     whenever nothing has succeeded for 5 min: 3 failed probes -> force a WiFi
//     reconnect; 5 -> reboot. WiFi down 15 min -> reboot (backing off to 30, 60,
//     120 min while the outage continues). Each heal is logged and reported.
//   * A real call that was detected but not yet delivered is saved, so a restart
//     can't silently eat it: it is re-sent after boot (marked delayed) if under
//     10 min old, else reported on STATUS.


static uint32_t boxCrc(const BoxRec& r) {   // FNV-1a over everything but the crc
  const uint8_t* p = (const uint8_t*)&r;
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < offsetof(BoxRec, crc); i++) { h ^= p[i]; h *= 16777619u; }
  return h;
}
static bool boxValid(const BoxRec& r) {
  return r.magic == BOX_MAGIC && r.version == BOX_VERSION && r.count <= BOX_EVENTS
      && r.head < BOX_EVENTS && r.crc == boxCrc(r);
}

static void boxFillCp() {
  BoxCp& c = box.cp;
  time_t now = time(nullptr);
  c.epoch      = now > TIME_VALID_EPOCH ? (uint32_t)now : 0;
  c.upS        = millis() / 1000;
  c.bootCount  = bootCount;
  c.freeHeap   = ESP.getFreeHeap();
  c.largest    = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  c.minFree    = esp_get_minimum_free_heap_size();
  c.sinceOkS   = netEverOk ? (millis() - lastNetOkMs) / 1000 : 0xFFFFFFFFu;
  c.ringCount  = ringCount;
  c.wifiDrops  = wifiDrops;
  c.lastDisc   = lastDiscReason;
  c.wifiUp     = WiFi.status() == WL_CONNECTED;
  c.rssi       = c.wifiUp ? (int8_t)WiFi.RSSI() : 0;
  c.failStreak = netFailStreak;
}
static void boxSyncRtc() {                  // cheap: RAM copy, no flash wear
  box.crc = boxCrc(box);
  memcpy(&boxRtc, &box, sizeof(box));
}
static void boxPersist() {
  boxFillCp();
  boxSyncRtc();
  Preferences p;
  p.begin("fhabox", false);
  p.putBytes("rec", &box, sizeof(box));
  p.end();
  lastBoxNvsMs = millis();
  esp_task_wdt_reset();
}
static void boxEvent(uint8_t code, uint16_t arg) {
  time_t now = time(nullptr);
  BoxEvt& e = box.ev[box.head];
  e.epoch = now > TIME_VALID_EPOCH ? (uint32_t)now : 0;
  e.upS   = millis() / 1000;
  e.code  = code;
  e.pad   = 0;
  e.arg   = arg;
  box.head = (box.head + 1) % BOX_EVENTS;
  if (box.count < BOX_EVENTS) box.count++;
  boxFillCp();
  boxSyncRtc();
}

// Record why we are about to restart (read back by the next boot), then flush.
static void noteReboot(const char* why) {
  Preferences p;
  p.begin("fhabox", false);
  p.putString("why", why);
  p.putUInt("why_boot", bootCount);         // only trusted by the very next boot
  p.end();
  boxEvent(EV_REBOOT_REQ, 0);
  boxPersist();
  Serial.printf("[box] restarting: %s\n", why);
}

// Network health bookkeeping, called by sendNtfy()/httpGetBounded().
static void netOk() {
  lastNetOkMs = millis();
  netEverOk = true;
  netFailStreak = 0;
  healStreak = 0;                           // healthy again: next outage starts the backoff fresh
}
static void netFail(int code) {
  if (WiFi.status() != WL_CONNECTED) return;          // offline failures are WiFi's story
  // arg: HTTP status, or 0x8000|-code for HTTPClient's negative transport errors
  if (netFailStreak == 0) boxEvent(EV_SEND_FAIL, code < 0 ? (uint16_t)(0x8000 | ((-code) & 0x7FFF)) : (uint16_t)code);
  if (netFailStreak < 255) netFailStreak++;
}

// A real call latched / delivered: persist so a restart can't silently drop it.
static void boxSaveCall() {
  time_t now = time(nullptr);
  Preferences p;
  p.begin("fhabox", false);
  p.putUInt("pcall", now > TIME_VALID_EPOCH ? (uint32_t)now : 1);   // 1 = time unknown
  p.end();
  boxEvent(EV_CALL, 0);
}
static void boxClearCall() {
  Preferences p;
  p.begin("fhabox", false);
  p.remove("pcall");
  p.end();
}

static void onWifiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) lastDiscReason = info.wifi_sta_disconnected.reason;
}

// Called early in setup(): load what the previous boot left, start this boot's record.
static void boxBoot() {
  Preferences p;
  p.begin("fhabox", true);
  BoxRec nv = {};
  bool nvOk = p.getBytes("rec", &nv, sizeof(nv)) == sizeof(nv) && boxValid(nv);
  String why = p.getString("why", "");
  uint32_t whyBoot = p.getUInt("why_boot", 0);
  savedCallEpoch = p.getUInt("pcall", 0);
  p.end();

  bool rtcOk = boxValid(boxRtc);
  // RTC is fresher (updated every minute) but only survives non-power-on resets.
  if (rtcOk && (!nvOk || boxRtc.cp.bootCount > nv.cp.bootCount
                || (boxRtc.cp.bootCount == nv.cp.bootCount && boxRtc.cp.upS >= nv.cp.upS))) {
    boxPrev = boxRtc; boxPrevFromRtc = true; boxPrevValid = true;
  } else if (nvOk) {
    boxPrev = nv; boxPrevValid = true;
  }
  // A recorded reason only explains THIS restart if the previous boot wrote it.
  if (why.length() && whyBoot + 1 == bootCount) strncpy(rebootWhy, why.c_str(), sizeof(rebootWhy) - 1);
  if (why.length()) { p.begin("fhabox", false); p.remove("why"); p.remove("why_boot"); p.end(); }

  if (healMagic != BOX_MAGIC) { healMagic = BOX_MAGIC; healStreak = 0; }

  // Keep the event history across boots: this boot appends to the same ring.
  memset(&box, 0, sizeof(box));
  if (boxPrevValid) { memcpy(box.ev, boxPrev.ev, sizeof(box.ev)); box.head = boxPrev.head; box.count = boxPrev.count; }
  box.magic = BOX_MAGIC;
  box.version = BOX_VERSION;
  boxEvent(EV_BOOT, (uint16_t)bootReason);

  // Crash dump from a panic / watchdog (saved to the coredump partition by the core).
  if (esp_core_dump_image_check() == ESP_OK && esp_core_dump_get_summary(&crashSum) == ESP_OK) {
    crashPending = true;
    if (esp_core_dump_get_panic_reason(crashReason, sizeof(crashReason)) != ESP_OK) crashReason[0] = 0;
  }
  WiFi.onEvent(onWifiEvent);
}

static const char* evName(uint8_t c) {
  switch (c) {
    case EV_BOOT:           return "boot";
    case EV_WIFI_LOST:      return "WiFi lost";
    case EV_WIFI_UP:        return "WiFi up";
    case EV_NET_DOWN:       return "no internet (WiFi up)";
    case EV_NET_UP:         return "internet back";
    case EV_SEND_FAIL:      return "send failed";
    case EV_HEAL_RECONNECT: return "self-heal: WiFi reconnect";
    case EV_HEAL_REBOOT:    return "self-heal: reboot";
    case EV_LOW_HEAP:       return "low memory";
    case EV_CALL:           return "call detected";
    case EV_REBOOT_REQ:     return "restart requested";
    default:                return "?";
  }
}
static const char* discName(uint16_t r) {
  switch (r) {
    case 2:   return "auth expired";
    case 3:   return "deauth by AP";
    case 4:   return "assoc expired";
    case 8:   return "left";
    case 15:  return "4-way handshake timeout";
    case 200: return "beacon timeout (AP gone/out of range)";
    case 201: return "AP not found";
    case 202: return "auth failed";
    case 203: return "assoc failed";
    case 204: return "handshake timeout";
    case 205: return "connection failed";
    default:  return "";
  }
}

// "Oct 04 03:55" from an epoch, or "+3h12m after boot" when the clock wasn't set.
static void fmtWhen(uint32_t epoch, uint32_t upS, char* out, size_t n) {
  if (epoch) {
    time_t t = (time_t)epoch; struct tm lt; localtime_r(&t, &lt);
    strftime(out, n, "%b %d %H:%M", &lt);
  } else {
    snprintf(out, n, "+%luh%02lum up", (unsigned long)(upS / 3600), (unsigned long)((upS % 3600) / 60));
  }
}

// The restart report: sent once per boot, as soon as WiFi is up and the clock is
// set (or 90 s after WiFi, so a broken NTP can't hold it back forever).
static void serviceRestartReport() {
  static uint32_t wifiUpAtMs = 0;
  if (restartReported) return;
  if (WiFi.status() != WL_CONNECTED) { wifiUpAtMs = 0; return; }
  if (!wifiUpAtMs) wifiUpAtMs = millis();
  if (!timeSynced() && millis() - wifiUpAtMs < 90000) return;

  bool unexpected = true;
  const char* cause;
  if (rebootWhy[0]) { cause = "requested restart"; unexpected = false; }
  else switch (bootReason) {
    case ESP_RST_POWERON:  cause = "POWER LOSS: it was unplugged, power-cycled, the reset button was pressed, or the supply cut out"; break;
    case ESP_RST_BROWNOUT: cause = "BROWNOUT: the power supply sagged too low (check the USB supply/cable)"; break;
    case ESP_RST_PANIC:    cause = "CRASH: the firmware crashed and restarted itself"; break;
    case ESP_RST_TASK_WDT:
    case ESP_RST_INT_WDT:
    case ESP_RST_WDT:      cause = "HANG: the firmware froze and the watchdog restarted it"; break;
    case ESP_RST_SW:       cause = "software restart with no recorded reason"; break;
    default:               cause = gResetReason; break;
  }
  if (!boxPrevValid && !rebootWhy[0]) { cause = "first boot with the black-box recorder (no history yet)"; unexpected = false; }

  static char msg[1400];
  int n = snprintf(msg, sizeof(msg), "Boot #%lu. Cause: %s%s%s%s.",
                   (unsigned long)bootCount, cause, rebootWhy[0] ? " (" : "", rebootWhy, rebootWhy[0] ? ")" : "");
  if (boxPrevValid) {
    const BoxCp& c = boxPrev.cp;
    char when[24]; fmtWhen(c.epoch, c.upS, when, sizeof(when));
    time_t now = time(nullptr);
    if (c.epoch && now > TIME_VALID_EPOCH && (uint32_t)now > c.epoch) {
      n += snprintf(msg + n, sizeof(msg) - n, " Last sign of life %s (%s ago)%s.", when,
                    fmtDuration(min((uint32_t)now - c.epoch, (uint32_t)(40UL * 86400UL)) * 1000UL).c_str(),
                    boxPrevFromRtc ? "" : ", within ~5 min");
    } else {
      n += snprintf(msg + n, sizeof(msg) - n, " Last checkpoint %s.", when);
    }
    char ok[32];
    if (c.sinceOkS == 0xFFFFFFFFu) snprintf(ok, sizeof(ok), "never");
    else snprintf(ok, sizeof(ok), "%s earlier", fmtDuration(c.sinceOkS * 1000UL).c_str());
    n += snprintf(msg + n, sizeof(msg) - n,
      " Just before: up %s, WiFi %s", fmtDuration(c.upS * 1000UL).c_str(), c.wifiUp ? "up" : "DOWN");
    if (c.wifiUp) n += snprintf(msg + n, sizeof(msg) - n, " %d dBm", (int)c.rssi);
    n += snprintf(msg + n, sizeof(msg) - n,
      ", last successful send %s, %u failures in a row, %u WiFi drops that boot",
      ok, (unsigned)c.failStreak, (unsigned)c.wifiDrops);
    if (c.lastDisc) n += snprintf(msg + n, sizeof(msg) - n, " (last: %u %s)", (unsigned)c.lastDisc, discName(c.lastDisc));
    n += snprintf(msg + n, sizeof(msg) - n, ", heap %lu KB free (largest %lu KB, low-water %lu KB).",
                  (unsigned long)(c.freeHeap / 1024), (unsigned long)(c.largest / 1024), (unsigned long)(c.minFree / 1024));
  }
  // Recent events, oldest first, skipping the boot we just logged.
  if (box.count > 1) {
    n += snprintf(msg + n, sizeof(msg) - n, " Recent events:");
    uint8_t shown = box.count - 1 < 8 ? box.count - 1 : 8;
    for (uint8_t i = shown; i >= 1 && n < (int)sizeof(msg) - 80; i--) {
      const BoxEvt& e = box.ev[(box.head + BOX_EVENTS - 1 - i) % BOX_EVENTS];
      char when[24]; fmtWhen(e.epoch, e.upS, when, sizeof(when));
      n += snprintf(msg + n, sizeof(msg) - n, " %s %s", when, evName(e.code));
      if (e.code == EV_WIFI_LOST && e.arg) n += snprintf(msg + n, sizeof(msg) - n, " (%u %s)", (unsigned)e.arg, discName(e.arg));
      else if (e.code == EV_BOOT) n += snprintf(msg + n, sizeof(msg) - n, " (%s)", resetReasonToStr((esp_reset_reason_t)e.arg));
      else if (e.code == EV_SEND_FAIL)
        n += snprintf(msg + n, sizeof(msg) - n, " (HTTP %d)", (e.arg & 0x8000) ? -(int)(e.arg & 0x7FFF) : (int)e.arg);
      n += snprintf(msg + n, sizeof(msg) - n, ";");
    }
  }
  if (savedCallEpoch) n += snprintf(msg + n, sizeof(msg) - n, " A call was detected before the restart (see next alert).");

  if (sendNtfy(C.ntfyStatus.c_str(), unexpected ? "Tapout restarted UNEXPECTEDLY" : "Tapout restarted",
               msg, unexpected ? "high" : "low", unexpected ? "warning,arrows_counterclockwise" : "arrows_counterclockwise")) {
    restartReported = true;
    onlineAnnounced = true;
  }
}

// One-time crash summary (task, PC, backtrace) -- decode the addresses with the
// release's tapout.ino.elf:  xtensa-esp32s3-elf-addr2line -pfiaC -e tapout.ino.elf <addrs>
static void serviceCrashReport() {
  if (!crashPending || !restartReported || WiFi.status() != WL_CONNECTED) return;
  static char msg[600];
  int n = snprintf(msg, sizeof(msg), "A crash dump was saved%s%s. Task '%s', PC 0x%08lx, exception cause %lu, addr 0x%08lx. Backtrace%s:",
                   crashReason[0] ? ": " : "", crashReason, crashSum.exc_task, (unsigned long)crashSum.exc_pc,
                   (unsigned long)crashSum.ex_info.exc_cause, (unsigned long)crashSum.ex_info.exc_vaddr,
                   crashSum.exc_bt_info.corrupted ? " (partly corrupted)" : "");
  for (uint32_t i = 0; i < crashSum.exc_bt_info.depth && i < 16 && n < (int)sizeof(msg) - 16; i++)
    n += snprintf(msg + n, sizeof(msg) - n, " 0x%08lx", (unsigned long)crashSum.exc_bt_info.bt[i]);
  snprintf(msg + n, sizeof(msg) - n, ". Firmware v%s; decode with that release's tapout.ino.elf (addr2line).", FW_VERSION);
  if (sendNtfy(C.ntfyStatus.c_str(), "Tapout crash report", msg, "high", "boom")) {
    esp_core_dump_image_erase();             // report each crash once
    crashPending = false;
  }
}

// Re-send (or report) a real call that was detected before the restart.
static void serviceSavedCall() {
  if (!savedCallEpoch || savedCallChecked || WiFi.status() != WL_CONNECTED) return;
  if (!timeSynced() && millis() < 120000) return;     // give NTP a chance to judge the age
  savedCallChecked = true;
  time_t now = time(nullptr);
  bool known = savedCallEpoch > 1 && now > TIME_VALID_EPOCH && (uint32_t)now >= savedCallEpoch;
  uint32_t ageS = known ? (uint32_t)now - savedCallEpoch : 0;
  if (known && ageS <= RESTORED_CALL_MAX_S && callPending && !callSimulated) {
    boxClearCall();                            // a newer real call is already being paged
    return;
  }
  if (known && ageS <= RESTORED_CALL_MAX_S) {
    callRestoredEpoch = savedCallEpoch;        // fireCallAlert words it as "delayed"
    callPending    = true;
    callSimulated  = false;
    callAttempts   = 0;
    callDetectedMs = millis();
    lastCallTryMs  = millis();
    fireCallAlert(false);
    return;                                    // key cleared on delivery / give-up
  }
  char when[24]; fmtWhen(known ? savedCallEpoch : 0, 0, when, sizeof(when));
  char msg[220];
  snprintf(msg, sizeof(msg), "A real call was detected %s but its alert was not delivered before the device "
           "restarted. %s, so the crew was NOT paged now.", known ? when : "(time unknown)",
           known ? "It is too old to page" : "Its age is unknown");
  if (sendNtfy(C.ntfyStatus.c_str(), "Undelivered call before restart", msg, "high", "warning")) boxClearCall();
  else savedCallChecked = false;               // retry next pass
}

// Self-restart for healing; never during OTA trial/download. A pending real call
// is already saved (boxSaveCall), so it survives this.
static void selfHealReboot(const char* why) {
  if (g_onProbation || otaState != PULL_OTA_IDLE || otaInProgress) return;
  healStreak++;
  boxEvent(EV_HEAL_REBOOT, 0);
  noteReboot(why);
  delay(100);
  ESP.restart();
}

// Loop hook: black-box checkpoints, WiFi edge events, connectivity probe, self-heal.
static void serviceBlackBox() {
  static bool wasUp = false;
  const bool up = (WiFi.status() == WL_CONNECTED);
  if (up != wasUp) {
    if (up) {
      boxEvent(EV_WIFI_UP, (uint16_t)(-WiFi.RSSI()));
      wifiDownSinceMs = 0;
    } else {
      wifiDrops++;
      boxEvent(EV_WIFI_LOST, lastDiscReason);
    }
    wasUp = up;
  }
  if (millis() - lastBoxRtcMs >= BOX_RTC_MS) { lastBoxRtcMs = millis(); boxFillCp(); boxSyncRtc(); }
  if (millis() - lastBoxNvsMs >= BOX_NVS_MS) boxPersist();

  if (up) {
    // Probe only when nothing has succeeded for a while (normal sends count).
    bool quiet = !netEverOk || millis() - lastNetOkMs >= NET_PROBE_MS;
    if (!quiet || (lastProbeMs && millis() - lastProbeMs < NET_PROBE_MS)) return;
    lastProbeMs = millis();
    if (httpGetBounded((C.ntfyStatus + "/json?poll=1&since=1s").c_str())) {   // no message is created
      if (netFailProbes) boxEvent(EV_NET_UP, netFailProbes);
      netFailProbes = 0;
      healStreak = 0;
      return;
    }
    netFailProbes++;
    if (netFailProbes == 1) boxEvent(EV_NET_DOWN, 0);
    if (netFailProbes == NET_HEAL_RECONNECT) {
      boxEvent(EV_HEAL_RECONNECT, 0);
      Serial.println(F("[heal] WiFi up but nothing gets through -- forcing a reconnect"));
      WiFi.disconnect();
      WiFi.begin(C.wifiSsid.c_str(), C.wifiPass.c_str());
    } else if (netFailProbes >= NET_HEAL_REBOOT) {
      selfHealReboot("self-heal: WiFi said connected but nothing got through for ~25 min");
    }
  } else {
    netFailProbes = 0;
    if (!wifiDownSinceMs) wifiDownSinceMs = millis();
    uint32_t limit = WIFI_DOWN_REBOOT_MS << (healStreak < 3 ? healStreak : 3);
    if (millis() - wifiDownSinceMs >= limit) {
      char why[80];
      snprintf(why, sizeof(why), "self-heal: WiFi down for %lu min", (unsigned long)(limit / 60000));
      selfHealReboot(why);
    }
  }
}

// ============================ SETUP =====================================
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println(F("[boot] Tapout starting..."));

  // ---- Boot diagnostics: reset reason + persistent boot counter ----------
  bootReason   = esp_reset_reason();
  gResetReason = resetReasonToStr(bootReason);
  bootPrefs.begin("fha", false);
  bootCount = bootPrefs.getUInt("boots", 0) + 1;
  bootPrefs.putUInt("boots", bootCount);
  realCallsDelivered = bootPrefs.getUInt("realcalls", 0);   // lifetime real CALLs
  bootPrefs.end();
  Serial.printf("[boot] boot #%lu, last reset: %s\n",
                (unsigned long)bootCount, gResetReason);

  // ---- Persistent ring log (restore history across reboot/brownout) ------
  loadRingLog();

  // ---- Black box: load what the previous boot left, start this boot's record
  boxBoot();

  // ---- Runtime config from NVS (secrets live here, not in the image) -----
  loadConfig();
  applyRingConfig();            // ring mode / min length from NVS (before the sampler starts)

  // ---- RAIL B: if we just booted a freshly-flashed image, start the 60 s
  //      health-probation clock NOW (committed/rolled-back later in loop). ---
  otaCheckProbationOnBoot();

  // RGB LED
  pinMode(LED_RED, OUTPUT);
  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_BLUE, OUTPUT);
  ledOff();
  statusBoot();

  // Ring input: idle HIGH, ELK-930 pulls LOW during a ring.
  pinMode(RING_PIN, INPUT_PULLUP);
  delay(50);   // let the internal pull-up settle before any read (avoids a transient-LOW false alarm)
  startRingSampler();           // 5 ms D4 sampler (arms after 3 s idle; see ring_detect.h)
  // No boot-time D4 read here: serviceStuckLine() monitors continuously and only
  // warns if the line stays active past LINE_STUCK_MS, so a brief startup transient
  // never false-fires and a genuinely stuck line is caught at boot OR any time after.

  // ---- Hardware watchdog -------------------------------------------------
  // arduino-esp32 v3.x uses the struct-based API. The Arduino core may have
  // already initialized the TWDT, so reconfigure rather than assuming.
  esp_task_wdt_config_t wdtConfig = {
    .timeout_ms    = WDT_TIMEOUT_S * 1000,
    .idle_core_mask = 0,        // don't watch idle tasks
    .trigger_panic = true,      // reset the chip on timeout
  };
  if (esp_task_wdt_init(&wdtConfig) == ESP_ERR_INVALID_STATE) {
    esp_task_wdt_reconfigure(&wdtConfig);  // already running -> adjust timeout
  }
  esp_task_wdt_add(NULL);       // watch the loop task
  esp_task_wdt_reset();

  // ---- UNPROVISIONED? -> SoftAP setup portal (never brick) ---------------
  // No real WiFi config in NVS (fresh unit, or wifi_ssid still CHANGE-ME): bring
  // up the captive "tapout-setup" AP and serve the provisioning form. The ring
  // detector STAYS ARMED in this loop (handleRing runs); only ntfy delivery is
  // suppressed because there is no STA link. We never fall through to normal init;
  // a successful /save reboots into normal mode.
  if (!isProvisioned()) {
    startSetupPortal();
    Serial.println(F("[setup] portal up -- join WiFi 'tapout-setup', browse to 192.168.4.1"));
    uint32_t lastBlink = 0;
    bool blinkOn = false;
    for (;;) {
      esp_task_wdt_reset();              // keep the dog fed
      handleRing();                      // life-safety path stays live (delivery suppressed)
      server.handleClient();             // serve the form / handle /save (reboots on save)
      // DNS is async (AsyncUDP) -- do NOT poll dns.processNextRequest().
      // Distinct "NEEDS SETUP" signal: blinking WHITE -- unmistakable vs the
      // steady green (normal/idle) or yellow (error) used in running mode.
      if (millis() - lastBlink >= 400) {
        lastBlink = millis();
        blinkOn = !blinkOn;
        if (blinkOn) ledSet(true, true, true); else ledOff();
      }
      delay(5);
    }
  }

  // ---- WiFi --------------------------------------------------------------
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);         // keep radio responsive; this is mains-powered
  WiFi.setHostname("tapout");  // identifiable in DHCP/firewall lists
  WiFi.begin(C.wifiSsid.c_str(), C.wifiPass.c_str());
  Serial.print(F("[wifi] connecting"));
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 20000) {
    delay(250);
    Serial.print('.');
    esp_task_wdt_reset();
  }
  Serial.println();

  // ---- Time sync (non-blocking; SNTP runs in the background and self-retries
  //      forever, including across WiFi drops). Needs OUTBOUND UDP 123. If the
  //      port stays blocked the clock simply never syncs and timestamps fall
  //      back to uptime -- nothing blocks, ring alerting is unaffected. -------
  configTzTime(C.tz.c_str(), C.ntp1.c_str(), C.ntp2.c_str(), C.ntp3.c_str());
  Serial.println(F("[time] SNTP started (non-blocking)"));

  // ---- Web server (safe to begin regardless of WiFi state; no clients until
  //      the link is up AND inbound TCP 80 is allowed on the IoT VLAN) -------
  server.on("/",            HTTP_GET,  handleRoot);
  server.on("/status.json", HTTP_GET,  handleStatusJson);
  server.on("/send-test",   HTTP_POST, handleSendTest);
  server.on("/simulate-ring", HTTP_POST, handleSimulateRing);
  server.on("/reboot",      HTTP_POST, handleReboot);
  // MIGRATION endpoint: re-provision NVS secrets over the network (authed,
  // write-only). Lets the already-deployed unit move to NVS-backed secrets
  // WITHOUT a trip into SoftAP. Optional ?reboot=1 (or reboot=1 field) reboots
  // after replying so the new config takes effect.
  server.on("/provision",   HTTP_POST, [](){
    if (!requireAuth()) return;               // fail-closed on CHANGE-ME web_pass
    provisionFromArgs();
    server.send(200, "application/json", "{\"ok\":true}");
    if (server.arg("reboot") == "1") {                 // reuse deferred reboot
      strncpy(pendingRebootWhy, "settings changed via /provision", sizeof(pendingRebootWhy) - 1);
      pendingRebootMs = millis() + 600;
    }
  });
  server.on("/check-ota",   HTTP_POST, handleCheckOta);   // manual OTA trigger + gate diagnosis
  server.onNotFound(handleNotFound);
  server.begin();
  Serial.println(F("[web] status server on :80"));

  if (WiFi.status() == WL_CONNECTED) {
    Serial.print(F("[wifi] connected, IP="));
    Serial.println(WiFi.localIP());
    statusConnected();
    armNetworkServices();       // arm OTA + advertise mDNS once WiFi is up
    announceOnlineOnce();       // boot test ping (boot count + reset reason)
  } else {
    Serial.println(F("[wifi] initial connect FAILED -- will retry in loop"));
    statusError();
  }

  lastHeartbeatMs = millis();   // start the hourly timer from boot
  lastHeapCheckMs = millis();   // start the heap-check timer from boot
}

// ============================ LOOP ======================================
void loop() {
  esp_task_wdt_reset();         // feed the dog every pass (always first)

  // Sample the ring line FIRST -- before WiFi reconnects, TLS sends, or OTA --
  // so an active edge is never missed while a network subsystem briefly stalls.
  // (serviceWifi() is now non-blocking and ntfy sends are short, but ring still
  //  gets unconditional priority on every pass.)
  handleRing();                 // THE WHOLE POINT -- runs every pass, unconditional

  // Cheap UDP poll when idle; during an actual upload it blocks internally with
  // the WDT detached (see setupOTA), so the loop body below simply pauses for
  // the attended ~10-20 s flash -- the hard-wired bell remains primary.
  ArduinoOTA.handle();

  serviceWifi();                // non-blocking reconnect w/ backoff
  serviceCallQueue();           // retry an undelivered CALL alert (never lost)
  handleHeartbeat();            // hourly "still alive" ping
  serviceStuckLine();           // continuous detector "stuck active" monitor
  serviceCredWarn();            // one-shot default-password warning
  serviceHeapCheck();           // low-heap canary (throttled)
  serviceIgnoredActivity();     // STATUS note for non-ring line activity (throttled)
  serviceArmCheck();            // STATUS warning if ring detection never armed
  serviceRestartReport();       // once per boot: why it restarted + what it looked like before
  serviceCrashReport();         // once: summary of a saved crash dump
  serviceSavedCall();           // re-send a real call saved before a restart
  serviceBlackBox();            // checkpoints, WiFi events, connectivity probe, self-heal
  serviceDeadman();             // external check-in, withheld when degraded (opt-in)
  server.handleClient();        // serve status page / json / actions (fast)

  // ---- RAIL B: commit or roll back a freshly-flashed image on probation ----
  otaServiceProbation();        // no-op unless we booted PENDING_VERIFY

  // ---- Signed pull-OTA scheduler: check the GitHub manifest on a cadence ----
  // Gated by otaEnabledAndSafe() (enabled + provisioned + real signing key) AND
  // otaSafeToStart() (no call pending/active, WiFi solid, heap OK, rollback slot
  // available). A check that finds + verifies a newer signed image reboots into
  // a 60 s trial; anything unsafe/unsigned is a no-op. NEVER starves handleRing().
  if (millis() - lastOtaCheckMs >= C.otaIntervalMin * 60000UL) {
    lastOtaCheckMs = millis();
    if (otaEnabledAndSafe() && otaSafeToStart()) otaCheckManifest();
  }

  // Non-blocking red-LED hold release after a ring.
  if (ringLedUntil && (int32_t)(millis() - ringLedUntil) >= 0) {
    ringLedUntil = 0;
    if (WiFi.status() == WL_CONNECTED) statusConnected(); else statusError();
  }

  // Deferred reboot (/reboot, OTA staged) -- lets the HTTP reply flush first.
  if (pendingRebootMs && (int32_t)(millis() - pendingRebootMs) >= 0
      && !realCallInFlight()) {                // hold while a real call is confirmed / being delivered
    Serial.println(F("[web] reboot requested"));
    noteReboot(pendingRebootWhy);
    delay(50);
    ESP.restart();
  }

  delay(5);                     // gentle; ring bursts are ~2 s wide
}

// ---------------------- WiFi maintenance --------------------------------
static void serviceWifi() {
  static bool wasConnected = false;

  if (WiFi.status() == WL_CONNECTED) {
    if (!wasConnected) {                    // edge: the link just came up
      wasConnected = true;
      wifiBackoffMs = WIFI_BACKOFF_MIN_MS;  // healthy -> reset backoff
      Serial.print(F("[wifi] connected, IP="));
      Serial.println(WiFi.localIP());
      statusConnected();
    }
    armNetworkServices();                   // idempotent; arms OTA/mDNS if not yet
    announceOnlineOnce();                   // idempotent; sends the boot ping once
    return;
  }

  // Disconnected. Kick off a reconnect on the backoff schedule but DO NOT block
  // waiting for it -- the old 8 s busy-wait paused ring sampling for seconds on
  // every attempt, most damaging during a WiFi flap. WL_CONNECTED is detected on
  // a later loop pass instead, so handleRing() keeps running unimpeded.
  wasConnected = false;
  uint32_t now = millis();
  if (now - lastWifiAttempt < wifiBackoffMs) return;
  lastWifiAttempt = now;

  Serial.printf("[wifi] reconnecting (backoff=%lus)...\n", wifiBackoffMs / 1000);
  statusError();
  WiFi.disconnect();
  WiFi.begin(C.wifiSsid.c_str(), C.wifiPass.c_str());
  wifiBackoffMs = min(wifiBackoffMs * 2, WIFI_BACKOFF_MAX_MS);  // grow until it sticks
}

// ---------------------- Ring detection ----------------------------------
// D4 is sampled every 5 ms by an esp_timer (ringSample), NOT by loop(): loop()
// blocks for seconds at a time in TLS sends, and sampling there left holes that
// could hide or split real rings. ring_detect.h decides what is a ring (see the
// rules there). Detection arms only after the line has read idle 3 s since boot,
// so the D4 blip at boot / on a power replug can never page. Then:
//   ring_mode=single (default): page once ONE ring has lasted ring_min_ms -- the
//     station line may ring only once before the call rolls to dispatch.
//   ring_mode=pattern (opt-in): page only on a 2-ring pattern (single blips of
//     any length can't page; costs the 1st ring).
// Activity that doesn't page is reported on STATUS as ignored. The bell stays primary.
//
// Dedup (one call = one alert) is decided HERE, from continuous samples, so a slow
// CALL POST can't make the sampler miss the ringing and re-page the same call.
static void ringSample() {
  const bool low = (digitalRead(RING_PIN) == LOW);
  const uint32_t now = millis();
  portENTER_CRITICAL(&ringMux);
  const uint32_t burstsBefore = ringDet.burstsSeen;
  RdEvent ev = ringStep(&ringDet, low, now);

  // "Line active" for OTA gating + call dedup: >= 30 ms of activity (a lone 5 ms
  // glitch on a noisy line shouldn't hold off OTA or re-arming forever).
  if (low && ringDet.armed && ringDet.inBurst && now - ringDet.burstStart >= 30) lastRingActiveMs = now;
  if (!low && now - lastRingActiveMs >= RING_REARM_IDLE_MS) idleSinceAlert = true;

  if (ringDet.burstsSeen != burstsBefore && ringDet.lastBurstLen >= 30) {
    burstLog[burstLogHead] = { ringDet.lastBurstStart, ringDet.lastBurstLen };
    burstLogHead = (burstLogHead + 1) % BURSTLOG_N;
    if (burstLogCount < BURSTLOG_N) burstLogCount++;
  }

  if (ev == RD_RING) {
    // COOLDOWN_MS remains an absolute ceiling so a line that keeps ringing re-alerts.
    bool newCall = !everAlerted || idleSinceAlert || (now - lastAlertMs >= COOLDOWN_MS);
    if (newCall) {
      lastAlertMs    = now;
      everAlerted    = true;
      idleSinceAlert = false;
      ringPagesPending++;
      ringPageAtMs   = now;
    }
  } else if (ev == RD_IGNORED) {
    ignoredActivity++;
    ignoredPending++;
    lastIgnoredMs     = now;
    lastIgnoredLenMs  = ringDet.ignoredMs;
    lastIgnoredBursts = ringDet.ignoredBursts;
  } else if (ev == RD_GLITCH) {
    glitchCount++;
  }
  portEXIT_CRITICAL(&ringMux);
}

static void ringTimerCb(void*) { ringSample(); }

// Push the configured ring mode / threshold into the detector (live; under the
// sampler's lock so a mode change can't land mid-step).
static void applyRingConfig() {
  portENTER_CRITICAL(&ringMux);
  ringDet.mode  = C.ringMode;
  ringDet.minMs = C.ringMinMs;
  portEXIT_CRITICAL(&ringMux);
}

// Start the 5 ms sampler. If the timer can't start, loop() samples inline
// (the pre-2.0.10 behaviour, still pattern-checked) and STATUS says so.
static void startRingSampler() {
  const esp_timer_create_args_t args = {
    .callback = ringTimerCb,
    .arg = nullptr,
    .dispatch_method = ESP_TIMER_TASK,
    .name = "ring",
    .skip_unhandled_events = true,
  };
  ringTimerOk = esp_timer_create(&args, &ringTimer) == ESP_OK
             && esp_timer_start_periodic(ringTimer, 5000) == ESP_OK;
  Serial.println(ringTimerOk ? F("[ring] 5 ms sampler running")
                             : F("[ring] sampler timer FAILED -- sampling from loop()"));
}

// loop()-side: hand confirmed calls to the alert pipeline. Cheap; call it often
// (loop, OTA download pump, setup portal).
static void handleRing() {
  if (!ringTimerOk) ringSample();
  uint32_t pages, at, ign;
  portENTER_CRITICAL(&ringMux);
  pages = ringPagesPending; ringPagesPending = 0;
  at    = ringPageAtMs;
  ign   = ignoredPending;   ignoredPending   = 0;
  portEXIT_CRITICAL(&ringMux);

  if (ign) {
    ignoredPingPending = true;
    Serial.println(F("[ring] ignored line activity (not a ring pattern)"));
  }
  if (pages) {
    ringDetectedAtMs = at;
    triggerRingPipeline(/*simulated=*/false);
  }
}

// True while a REAL call is confirmed but not yet handed to the pipeline, or still
// being delivered. Every intentional restart checks this first: a reboot wipes the
// RAM-only call latch AND the sampler's pending page, so the crew would never hear
// about that call (and the detector would have to re-arm and see 2 more rings).
static bool realCallInFlight() {
  handleRing();                         // hand any confirmed page to the pipeline first
  return callPending && !callSimulated;
}

// STATUS note (at most one ATTEMPT per IGNORED_PING_MS -- throttled on attempts,
// not successes, so an ntfy outage can't turn it into a send-every-loop storm)
// when line activity was ignored: a replug/brownout is visible without paging
// anyone, and a real call that somehow didn't match the pattern shows up too.
static void serviceIgnoredActivity() {
  if (!ignoredPingPending || WiFi.status() != WL_CONNECTED || callPending) return;
  if (lastIgnoredPingMs && millis() - lastIgnoredPingMs < IGNORED_PING_MS) return;
  lastIgnoredPingMs  = millis();
  ignoredPingPending = false;
  uint32_t lenMs, bursts, count, agoS;
  portENTER_CRITICAL(&ringMux);
  lenMs = lastIgnoredLenMs; bursts = lastIgnoredBursts; count = ignoredActivity;
  agoS = (millis() - lastIgnoredMs) / 1000;
  portEXIT_CRITICAL(&ringMux);
  char msg[360];
  snprintf(msg, sizeof(msg),
    "%lus ago the detector line was active (%lu burst%s, longest %lu.%lu s) without a ring "
    "pattern, so the crew was NOT paged. Usually a power/phone-cord replug or a brownout. "
    "If the station phone really rang then, report it: the detector may need tuning. "
    "Ignored since boot: %lu.",
    (unsigned long)agoS, (unsigned long)bursts, bursts == 1 ? "" : "s",
    (unsigned long)(lenMs / 1000), (unsigned long)((lenMs % 1000) / 100), (unsigned long)count);
  sendNtfy(C.ntfyStatus.c_str(), "Line activity ignored (not a ring)", msg, "default", "shield");
}

// Loud STATUS warning if detection hasn't armed a minute after boot (the line
// never read idle for 3 s straight): until it arms, a real call would NOT page.
// Attempt-throttled; re-arms the warning if it ever disarms again (it doesn't today).
static void serviceArmCheck() {
  static bool samplerWarned = false;
  if (!ringTimerOk && !samplerWarned && WiFi.status() == WL_CONNECTED) {
    samplerWarned = sendNtfy(C.ntfyStatus.c_str(), "Ring sampler degraded",
      "The 5 ms ring-sampling timer failed to start, so D4 is sampled from the main loop. "
      "Network sends can now hide or split rings. Reboot the device; report it if this repeats.",
      "high", "warning");
  }
  static uint32_t lastTryMs = 0;
  static bool     warned    = false;
  if (ringDet.armed) { warned = false; return; }
  if (warned || millis() < 60000 || WiFi.status() != WL_CONNECTED) return;
  if (lastTryMs && millis() - lastTryMs < 30UL * 60UL * 1000UL) return;
  lastTryMs = millis();
  if (sendNtfy(C.ntfyStatus.c_str(), "Ring detector NOT armed",
        "The detector line has not read idle for 3 s straight since boot, so ring detection "
        "is not armed and a call would NOT page. Check the ELK-930 and the phone cord. "
        "(The bell is unaffected.)", "high", "warning")) {
    warned = true;
  }
}

// Shared post-debounce pipeline for BOTH a real ring (handleRing) and the
// auth-gated /simulate-ring endpoint. Reusing the SAME code is the whole point:
// it proves the genuine record->latch->alert chain, not a parallel copy.
//
// CRITICAL dedup safety: the simulated path must NOT touch lastAlertMs,
// everAlerted, or lastRingActiveMs (those stay in ringSample's real branch),
// so a test can never suppress a subsequent REAL ring via cooldown/re-arm.
static void triggerRingPipeline(bool simulated) {
  uint32_t now = millis();

  Serial.println(simulated ? F("[sim] SIMULATED ring -> running real pipeline")
                           : F("[ring] RING DETECTED -> alerting"));
  statusRing();
  ringLedUntil = now + RING_LED_HOLD_MS;   // non-blocking red hold (loop releases)

  recordRing(simulated);                   // persist to NVS log (also resets WDT)
  if (!simulated) boxSaveCall();           // survives a restart until delivered
  callRestoredEpoch = 0;                   // a fresh ring supersedes any restored one

  // Latch the call and fire immediately; serviceCallQueue() retries on failure
  // so a WiFi/ntfy blip can never silently drop a real call.
  callPending    = true;
  callSimulated  = simulated;
  callDetectedMs = simulated ? now : ringDetectedAtMs;   // real: when the pattern was confirmed
  callAttempts   = 0;
  lastCallTryMs  = now;
  fireCallAlert(simulated);
}

// ---------------------- Hourly heartbeat --------------------------------
static void handleHeartbeat() {
  if (millis() - lastHeartbeatMs < HEARTBEAT_MS) return;
  lastHeartbeatMs = millis();
  heartbeatSeq++;               // monotonic -> a gap on STATUS reveals a missed beat
  Serial.println(F("[heartbeat] hourly ping"));
  char ts[48];
  formatTimestamp(ts, sizeof(ts));
  uint32_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
  char msg[320];
  snprintf(msg, sizeof(msg),
           "Ring detector still online (hourly check-in, seq %lu). %s. Rings since "
           "boot: %lu (ignored non-ring line activity: %lu). Free heap %u B, largest block %u B "
           "(low-water %u B). WiFi %d dBm, %u drops since boot.",
           (unsigned long)heartbeatSeq, ts, (unsigned long)ringCount, (unsigned long)ignoredActivity,
           (unsigned)ESP.getFreeHeap(), (unsigned)largest, (unsigned)esp_get_minimum_free_heap_size(),
           (int)WiFi.RSSI(), (unsigned)wifiDrops);
  sendNtfy(C.ntfyStatus.c_str(), "Tapout heartbeat",
           msg, "min", "green_heart");
}

// ---------------------- ntfy notification -------------------------------
static bool sendNtfy(const char* url, const char* title, const char* message,
                     const char* priority, const char* tags) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(F("[ntfy] skipped -- WiFi down"));
    return false;
  }

  WiFiClientSecure client;
  // TLS is INTENTIONALLY not certificate-validated here. Trade-off, deliberate:
  // the firewall already pins outbound 443 to ntfy.sh's single IP, and on this
  // unattended, safety-adjacent device a hard cert/CA pin that breaks on a
  // Let's Encrypt rotation would FAIL the CALL alert path CLOSED -- worse than
  // the residual MITM risk. Consequence: topic confidentiality depends on the
  // network path, so if you ever suspect the 443 path was tampered with, ROTATE
  // the ntfy topics (NTFY_*_URL). To opt into pinning instead, replace the
  // setInsecure() call below with client.setCACert(<ISRG Root X1 PEM>) and accept
  // that you must reflash whenever the upstream chain changes.
  client.setInsecure();
  client.setHandshakeTimeout(TLS_HANDSHAKE_TIMEOUT_S);  // cap TLS handshake (< WDT)

  HTTPClient http;
  if (!http.begin(client, url)) {
    Serial.println(F("[ntfy] http.begin failed"));
    netFail(-1);
    return false;
  }
  // Bound the TLS POST so a dead/slow ntfy socket can't stall ring detection
  // or trip the 30 s watchdog (handshake + connect + read each < WDT_TIMEOUT_S).
  http.setConnectTimeout(HTTP_CONNECT_TIMEOUT_MS);
  http.setTimeout(HTTP_READ_TIMEOUT_MS);
  http.addHeader("Title", title);
  http.addHeader("Priority", priority);
  http.addHeader("Tags", tags);

  esp_task_wdt_reset();                 // fresh 30 s window before the blocking POST
  int code = http.POST((uint8_t*)message, strlen(message));
  esp_task_wdt_reset();
  http.end();

  if (code > 0 && code < 300) {
    Serial.printf("[ntfy] sent OK (HTTP %d)\n", code);
    netOk();
    return true;
  }
  Serial.printf("[ntfy] send failed (HTTP %d)\n", code);
  netFail(code);
  return false;
}

// ---------------------- Dead-man's-switch -------------------------------
// Bounded HTTPS GET, mirroring sendNtfy()'s client setup exactly (setInsecure,
// 4 s connect/read timeouts). Used only for the external check-in URL; a DNS or
// 443 failure to that host fails silently like NTP and never touches alerting.
static bool httpGetBounded(const char* url) {
  if (WiFi.status() != WL_CONNECTED) return false;
  WiFiClientSecure client;
  client.setInsecure();
  client.setHandshakeTimeout(TLS_HANDSHAKE_TIMEOUT_S);  // cap TLS handshake (< WDT)
  HTTPClient http;
  if (!http.begin(client, url)) return false;
  http.setConnectTimeout(HTTP_CONNECT_TIMEOUT_MS);
  http.setTimeout(HTTP_READ_TIMEOUT_MS);
  esp_task_wdt_reset();
  int code = http.GET();
  http.end();
  bool ok = (code > 0 && code < 400);
  if (ok) netOk(); else netFail(code);
  return ok;
}

// Periodic external check-in. Inverts the failure mode: the device cannot
// announce its own death, so an external monitor pages when this check-in goes
// SILENT. Crucially the ping is WITHHELD when the device is degraded (WiFi down,
// detector stuck LOW, or heap too fragmented for a TLS handshake), so the
// monitor fires even when the device is "degraded but not dead". Runs only on
// the optional-subsystem side of loop(), never before handleRing().
static void serviceDeadman() {
  if (C.deadman.isEmpty()) return;                  // disabled -> v1.1.0 behavior
  if (WiFi.status() != WL_CONNECTED) return;
  if (millis() - lastDeadmanMs < DEADMAN_PING_MS) return;
  lastDeadmanMs = millis();

  // Gate on real HEALTH, not merely "the loop is running".
  bool healthy = (WiFi.status() == WL_CONNECTED)
              && (digitalRead(RING_PIN) == HIGH)     // detector not stuck active
              && (heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) >= TLS_MIN_CONTIG_BLOCK)
              && ringDet.armed;                      // unarmed => a call would not page
  if (!healthy) return;   // withhold the check-in -> external monitor pages on silence

  bool ok = httpGetBounded(C.deadman.c_str());
  if (ok) {
    deadmanOk = true;
    lastDeadmanOkEpoch = timeSynced() ? (uint32_t)time(nullptr) : 0;
  }
  esp_task_wdt_reset();   // a bounded GET can take up to the read timeout
}

/* ----------------------------------------------------------------------
 * Pushover alternative (priority 2 = emergency, re-alerts until acked).
 * Replace sendNtfy() calls with sendPushover() and fill in the keys.
 *
 * static const char* PO_TOKEN = "YOUR_APP_TOKEN";
 * static const char* PO_USER  = "YOUR_USER_KEY";
 *
 * static bool sendPushover(const char* title, const char* message, int priority) {
 *   if (WiFi.status() != WL_CONNECTED) return false;
 *   WiFiClientSecure client; client.setInsecure();
 *   HTTPClient http;
 *   http.begin(client, "https://api.pushover.net/1/messages.json");
 *   http.addHeader("Content-Type", "application/x-www-form-urlencoded");
 *   String body = String("token=") + PO_TOKEN + "&user=" + PO_USER +
 *                 "&title=" + title + "&message=" + message +
 *                 "&priority=" + priority;
 *   // priority 2 also requires &retry=30&expire=3600
 *   if (priority == 2) body += "&retry=30&expire=3600";
 *   int code = http.POST(body);
 *   http.end();
 *   return (code > 0 && code < 300);
 * }
 * -------------------------------------------------------------------- */
