/*
 * ring_detect.h -- decide "is the station phone actually ringing?" from D4.
 * -------------------------------------------------------------------------
 * Pure C (no Arduino calls) so tools/test_ring_detect.cpp can replay simulated
 * waveforms on a dev host. tapout.ino feeds it one D4 sample every 5 ms from a
 * dedicated esp_timer (NOT from loop(), whose blocking TLS sends would leave
 * multi-second holes in the samples).
 *
 * Why: the ELK-930 output follows the ring CADENCE (US: ~2 s ringing, ~4 s
 * silent, repeating). Things that are NOT a call -- the D4 blip while the board
 * boots, a brownout while someone unplugs/replugs the USB power or the phone
 * cord, a WiFi-reconnect current spike -- show up as ONE isolated burst of line
 * activity (a few ms up to a couple of seconds). v2.0.9 paged the crew on any
 * LOW lasting > 25 ms, so every unplug/replug paged everyone.
 *
 * Rules (a "burst" = line activity, merged across idle gaps < 150 ms):
 *   * Arm only after the line has read idle for 3 s continuously (boot). This
 *     alone stops the boot/replug pages: the blip happens before arming.
 *   * RD_MODE_SINGLE (default): page as soon as ONE burst has lasted minMs
 *     (default 500 ms) -- i.e. on the FIRST ring. Needed because the station
 *     line may ring only once before the call rolls to county dispatch.
 *     Shorter activity is a glitch; nothing else is required.
 *   * RD_MODE_PATTERN (opt-in): page only on a RING PATTERN:
 *       A) two ring-shaped bursts (0.3-3.5 s each), the 2nd starting within
 *          8 s of the 1st ending -- normal US ringing, paged on the 2nd ring; or
 *       B) three or more bursts of >= 0.3 s (any length), each within 8 s of
 *          the previous -- a fallback in case the detector stretches rings
 *          past 3.5 s; a single replug can't produce it.
 *   * A single burst of any length never pages (reported as RD_IGNORED);
 *     a burst < 0.3 s is a glitch (RD_GLITCH, counted, never reported).
 * Pattern-mode cost: the page fires on the 2nd ring (~4-6 s in) and a call
 * that rings only once does not page. Single-mode cost: a >= minMs brownout
 * while the board stays powered (and armed) can still page. The bell is
 * unaffected and stays primary.
 *
 * ASSUMPTION: the ELK-930 output follows the ring cadence. If it instead held
 * D4 low for the whole call, calls would be reported as RD_IGNORED (one long
 * burst) and NOT paged -- verify with a real call (see README).
 * -------------------------------------------------------------------------
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>

#define RD_ARM_IDLE_MS   3000UL  // line must read idle this long, continuously, before detection arms
#define RD_BURST_END_MS   150UL  // idle this long ends a burst (merges chatter / contact bounce)
#define RD_MIN_BURST_MS   300UL  // shorter activity is a glitch, never a ring
#define RD_MAX_BURST_MS  3500UL  // longer is not a normal ring (US ~2 s); only counts toward rule B
#define RD_MAX_GAP_MS    8000UL  // next burst must start within this of the previous ending (US gap ~4 s)
#define RD_RULE_B_BURSTS    3    // rule B: this many >= 0.3 s bursts in a row
#define RD_SINGLE_MIN_DEFAULT_MS 500UL   // single mode: page once a burst lasts this long
                                         // (firmware caps it at 1500: a US ring is ~2 s)

#define RD_MODE_SINGLE   0       // page on the first ring (default; zero-initialised)
#define RD_MODE_PATTERN  1       // page only on a 2-ring pattern

typedef enum {
  RD_NONE = 0,
  RD_RING,      // ring pattern confirmed (fires on EVERY qualifying burst of a call; caller dedups)
  RD_IGNORED,   // a run of >= 0.3 s activity ended without forming a ring pattern
  RD_GLITCH     // an isolated < 0.3 s blip
} RdEvent;

typedef struct {
  uint8_t  mode;                              // RD_MODE_SINGLE (0) | RD_MODE_PATTERN; may change live
  uint32_t minMs;                             // single mode threshold; 0 = RD_SINGLE_MIN_DEFAULT_MS
  bool     armed;
  bool     idleSeen;  uint32_t idleSince;     // arming: continuous-idle timer
  bool     inBurst;   uint32_t burstStart, lastLow;
  bool     confirmedThisBurst;
  uint32_t run;                               // bursts >= MIN in the current run (each within MAX_GAP of the last)
  bool     prevShaped;                        // the last burst in the run was 0.3-3.5 s
  uint32_t prevEnd;                           // when the last burst in the run ended
  bool     runConfirmed;
  uint32_t runMaxMs;
  // Reporting (read by the caller after an event):
  uint32_t ignoredMs, ignoredBursts;          // last RD_IGNORED: longest burst, burst count
  uint32_t lastBurstStart, lastBurstLen;      // last completed burst of any length
  uint32_t burstsSeen;                        // increments at every completed burst (for a burst log)
} RingDet;

static inline RdEvent rdEndRun(RingDet* d) {
  RdEvent ev = (d->run && !d->runConfirmed) ? RD_IGNORED : RD_NONE;
  if (ev == RD_IGNORED) { d->ignoredMs = d->runMaxMs; d->ignoredBursts = d->run; }
  d->run = 0;
  d->prevShaped = false;
  d->runConfirmed = false;
  d->runMaxMs = 0;
  return ev;
}

// Feed one D4 sample (low = line active). Returns what, if anything, just happened.
static inline RdEvent ringStep(RingDet* d, bool low, uint32_t now) {
  if (!d->armed) {
    if (low) { d->idleSeen = false; return RD_NONE; }
    if (!d->idleSeen) { d->idleSeen = true; d->idleSince = now; }
    if (now - d->idleSince >= RD_ARM_IDLE_MS) d->armed = true;
    return RD_NONE;
  }

  if (low) {
    if (!d->inBurst) {
      d->inBurst = true;
      d->burstStart = now;
      d->confirmedThisBurst = false;
    }
    d->lastLow = now;
    uint32_t len = now - d->burstStart;
    if (d->mode != RD_MODE_PATTERN) {        // single: the first ring that lasts minMs pages
      uint32_t need = d->minMs ? d->minMs : RD_SINGLE_MIN_DEFAULT_MS;
      if (!d->confirmedThisBurst && len >= need) {
        d->confirmedThisBurst = true;
        return RD_RING;
      }
      return RD_NONE;
    }
    if (!d->confirmedThisBurst && len >= RD_MIN_BURST_MS && d->run > 0
        && d->burstStart - d->prevEnd <= RD_MAX_GAP_MS
        && (d->prevShaped || d->run + 1 >= RD_RULE_B_BURSTS)) {
      d->confirmedThisBurst = true;
      d->runConfirmed = true;
      return RD_RING;
    }
    return RD_NONE;
  }

  // Line idle.
  RdEvent ev = RD_NONE;
  if (d->inBurst && now - d->lastLow >= RD_BURST_END_MS) {
    d->inBurst = false;
    uint32_t len = d->lastLow - d->burstStart;
    d->lastBurstStart = d->burstStart;
    d->lastBurstLen = len;
    d->burstsSeen++;
    if (d->mode != RD_MODE_PATTERN) {        // single: every burst stands alone
      d->run = 0;                            // (drop any pattern run if the mode just changed)
      if (d->confirmedThisBurst) return RD_NONE;
      if (len >= RD_MIN_BURST_MS) { d->ignoredMs = len; d->ignoredBursts = 1; return RD_IGNORED; }
      return RD_GLITCH;
    }
    if (len >= RD_MIN_BURST_MS) {
      bool chained = d->run > 0 && d->burstStart - d->prevEnd <= RD_MAX_GAP_MS;
      if (!chained) {
        if (d->run) ev = rdEndRun(d);      // (defensive; the gap check below normally ends runs first)
        d->run = 0;
      }
      d->run++;
      d->prevShaped = (len <= RD_MAX_BURST_MS);
      d->prevEnd = d->lastLow;
      if (len > d->runMaxMs) d->runMaxMs = len;
    } else if (d->run == 0) {
      return RD_GLITCH;                     // isolated blip; inside a run it's simply ignored
    }
  }
  // Run over: no further burst within the gap window.
  if (!d->inBurst && d->run && now - d->prevEnd > RD_MAX_GAP_MS) {
    RdEvent e2 = rdEndRun(d);
    if (ev == RD_NONE) ev = e2;
  }
  return ev;
}
