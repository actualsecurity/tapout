// Replay simulated D4 waveforms through tapout/ring_detect.h at the esp_timer's
// 5 ms sample rate and check when (or whether) a ring is confirmed.
// Build + run: c++ -std=c++17 -o /tmp/trd tools/test_ring_detect.cpp && /tmp/trd
#include <cstdio>
#include <vector>
#include "../tapout/ring_detect.h"

struct Seg { bool low; uint32_t ms; };
using Wave = std::vector<Seg>;

static const uint32_t STEP = 5;   // ms between samples (esp_timer period)

struct Result { int rings = 0; long firstRingMs = -1; int ignored = 0; int glitches = 0; bool armed = false; };

// Run a waveform starting at millis() == t0 (boot), then idle for tailIdleMs.
// Default mode is PATTERN for the original suite; single-mode cases use runS().
static Result run(const Wave& w, uint32_t tailIdleMs = 12000, uint32_t t0 = 0,
                  uint8_t mode = RD_MODE_PATTERN, uint32_t minMs = 0) {
  RingDet d = {};
  d.mode = mode;
  d.minMs = minMs;
  Result r;
  uint32_t t = t0;
  auto feed = [&](bool low, uint32_t ms) {
    for (uint32_t e = 0; e < ms; e += STEP, t += STEP) {
      RdEvent ev = ringStep(&d, low, t);
      if (ev == RD_RING) { r.rings++; if (r.firstRingMs < 0) r.firstRingMs = (long)(t - t0); }
      if (ev == RD_IGNORED) r.ignored++;
      if (ev == RD_GLITCH) r.glitches++;
    }
  };
  for (const Seg& s : w) feed(s.low, s.ms);
  feed(false, tailIdleMs);
  r.armed = d.armed;
  return r;
}

static Result runS(const Wave& w, uint32_t minMs = 0) { return run(w, 12000, 0, RD_MODE_SINGLE, minMs); }

// Chattering burst: the detector output flickering at ~20 Hz for `ms`.
static void chatter(Wave& w, uint32_t ms) {
  for (uint32_t e = 0; e < ms; e += 50) { w.push_back({true, 25}); w.push_back({false, 25}); }
}

// `n` rings of onMs on / offMs off after `leadIdle` ms of idle.
static Wave ring(int n, uint32_t onMs = 2000, uint32_t offMs = 4000, uint32_t leadIdle = 5000) {
  Wave w{{false, leadIdle}};
  for (int i = 0; i < n; i++) { w.push_back({true, onMs}); w.push_back({false, offMs}); }
  return w;
}

int main() {
  int fails = 0;
  auto check = [&](const char* name, bool ok, const Result& r) {
    printf("%s  %-64s rings=%d first=%ldms ignored=%d glitches=%d\n",
           ok ? "PASS" : "FAIL", name, r.rings, r.firstRingMs, r.ignored, r.glitches);
    if (!ok) fails++;
  };

  printf("== PATTERN mode (opt-in: page on the 2nd ring) ==\n");
  printf("-- must NEVER page --\n");
  { Result r = run({{true, 40}, {false, 20000}});
    check("boot: D4 low for 40 ms at power-up", r.rings == 0, r); }
  { Result r = run({{true, 2000}, {false, 20000}});
    check("boot: D4 low for 2 s at power-up", r.rings == 0, r); }
  { Result r = run({{false, 200}, {true, 2000}, {false, 20000}});
    check("boot: idle 200 ms, then a 2 s low (not armed yet)", r.rings == 0, r); }
  { Result r = run({{false, 5000}, {true, 2000}, {false, 20000}});
    check("armed: single 2 s blip (brownout / replug)", r.rings == 0 && r.ignored == 1, r); }
  { Result r = run({{false, 5000}, {true, 8}, {false, 20000}});
    check("armed: single 8 ms glitch (counted, not reported)", r.rings == 0 && r.ignored == 0 && r.glitches == 1, r); }
  { Result r = run({{false, 5000}, {true, 3000}, {false, 20000}});
    check("armed: single 3 s blip", r.rings == 0 && r.ignored == 1, r); }
  { Wave w{{false, 5000}};
    for (int i = 0; i < 6; i++) { w.push_back({true, 120}); w.push_back({false, 1500}); }
    Result r = run(w);
    check("armed: six 120 ms plug/unplug glitches", r.rings == 0 && r.ignored == 0, r); }
  { Result r = run({{false, 5000}, {true, 2000}, {false, 20000}, {true, 2000}, {false, 20000}});
    check("armed: two 2 s blips 20 s apart", r.rings == 0 && r.ignored == 2, r); }
  { Result r = run({{false, 5000}, {true, 30000}, {false, 20000}});
    check("armed: line stuck low 30 s", r.rings == 0 && r.ignored == 1, r); }
  { Result r = run({{true, 10000}, {false, 20000}});
    check("boot: line held low 10 s (no line / stuck), then idle", r.rings == 0, r); }
  { int total = 0;
    for (int i = 0; i < 3; i++) total += run({{true, 1500}, {false, 1000}, {true, 500}, {false, 15000}}).rings;
    Result r; r.rings = total;
    check("3x power replug: 1.5 s low, 1 s idle, 0.5 s low at each boot", total == 0, r); }
  { Result r = run({{false, 5000}, {true, 3600}, {false, 8100}, {true, 3600}, {false, 20000}});
    check("armed: two 3.6 s blips 8.1 s apart (gap too long)", r.rings == 0, r); }

  printf("-- real calls MUST page --\n");
  { Result r = run(ring(4));
    check("US ring x4 (2 s on / 4 s off): pages on the 2nd ring", r.rings >= 1 && r.firstRingMs == 5000 + 6000 + 300, r); }
  { Result r = run(ring(2));
    check("US ring x2 (caller hangs up after 2 rings)", r.rings == 1, r); }
  { Wave w{{false, 5000}};
    for (int i = 0; i < 3; i++) { chatter(w, 2000); w.push_back({false, 4000}); }
    Result r = run(w);
    check("US ring x3 with 20 Hz chatter inside each burst", r.rings >= 1, r); }
  { Wave w{{false, 5000}};   // distinctive ring: 0.8 on, 0.4 off, 0.8 on, 4 off
    for (int i = 0; i < 2; i++) { w.push_back({true, 800}); w.push_back({false, 400}); w.push_back({true, 800}); w.push_back({false, 4000}); }
    Result r = run(w);
    check("distinctive ring (0.8/0.4/0.8 on-off pattern)", r.rings >= 1 && r.firstRingMs <= 5000 + 1200 + 400, r); }
  { Wave w{{false, 5000}, {true, 8}, {false, 3000}};
    for (int i = 0; i < 3; i++) { w.push_back({true, 2000}); w.push_back({false, 4000}); }
    Result r = run(w);
    check("glitch then real call 3 s later", r.rings >= 1, r); }
  { Wave w{{false, 5000}, {true, 2000}, {false, 1200}, {true, 60}, {false, 2700}, {true, 2000}, {false, 4000}};
    Result r = run(w);
    check("real ring with a 60 ms glitch in the silent gap", r.rings >= 1, r); }
  { Result r = run({{true, 30}, {false, 3200}, {true, 2000}, {false, 4000}, {true, 2000}, {false, 4000}});
    check("call arriving right after boot (arms at 3 s, pages 2nd ring)", r.rings >= 1, r); }
  { Result r = run(ring(3, 3600, 2400));
    check("stretched rings 3.6 s on / 2.4 s off (rule B, 3rd burst)", r.rings >= 1 && r.firstRingMs == 5000 + 12000 + 300, r); }
  { Result r = run(ring(4, 5000, 1000));
    check("stretched rings 5 s on / 1 s off (rule B)", r.rings >= 1, r); }
  { Result r = run(ring(4), 12000, 0xFFFFFFFFu - 9000);
    check("US ring x4 across the millis() 2^32 wraparound", r.rings >= 1 && r.firstRingMs == 5000 + 6000 + 300, r); }

  printf("-- boundaries --\n");
  { Result r = run({{false, 5000}, {true, 295}, {false, 4000}, {true, 2000}, {false, 4000}});
    check("1st burst 0.295 s (just under min) -> no page on 2nd", r.rings == 0, r); }
  { Result r = run({{false, 5000}, {true, 305}, {false, 4000}, {true, 2000}, {false, 4000}});
    check("1st burst 0.305 s (just over min) -> page", r.rings == 1, r); }
  { Result r = run({{false, 5000}, {true, 2000}, {false, 7900}, {true, 2000}, {false, 4000}});
    check("gap 7.9 s -> page", r.rings == 1, r); }
  { Result r = run({{false, 5000}, {true, 2000}, {false, 8100}, {true, 2000}, {false, 4000}});
    check("gap 8.1 s -> no page (two separate blips)", r.rings == 0 && r.ignored == 2, r); }

  printf("-- documented limitations (asserted so a behaviour change is noticed) --\n");
  { Result r = run({{false, 5000}, {true, 500}, {false, 3000}, {true, 500}, {false, 20000}});
    check("LIMIT: phone-cord jiggle, two 0.5 s lows 3 s apart, board powered -> pages", r.rings == 1, r); }
  { Result r = run({{false, 5000}, {true, 30000}, {false, 20000}});
    check("LIMIT: detector held LOW for a whole 30 s call -> ignored, not paged", r.rings == 0 && r.ignored == 1, r); }
  { Result r = run(ring(1));
    check("LIMIT: call abandoned after one ring -> not paged", r.rings == 0 && r.ignored == 1, r); }
  { Wave w;
    for (int i = 0; i < 240; i++) { w.push_back({false, 2490}); w.push_back({true, 10}); }
    Result r = run(w, 0);
    check("LIMIT: noisy idle (glitch every 2.5 s) never arms (firmware warns)", !r.armed, r); }

  printf("== SINGLE mode (default: page on the 1st ring) ==\n");
  { RingDet d = {};
    Result r; r.rings = d.mode == RD_MODE_SINGLE;
    check("zero-initialised detector defaults to SINGLE mode", d.mode == RD_MODE_SINGLE, r); }
  printf("-- must NEVER page --\n");
  { Result r = runS({{true, 40}, {false, 20000}});
    check("single: boot, D4 low for 40 ms at power-up", r.rings == 0, r); }
  { Result r = runS({{true, 2000}, {false, 20000}});
    check("single: boot, D4 low for 2 s at power-up", r.rings == 0, r); }
  { Result r = runS({{false, 200}, {true, 2000}, {false, 20000}});
    check("single: boot, idle 200 ms then a 2 s low (not armed yet)", r.rings == 0, r); }
  { int total = 0;
    for (int i = 0; i < 3; i++) total += runS({{true, 1500}, {false, 1000}, {true, 500}, {false, 15000}}).rings;
    Result r; r.rings = total;
    check("single: 3x power replug (1.5 s low, 1 s idle, 0.5 s low at boot)", total == 0, r); }
  { Result r = runS({{true, 10000}, {false, 20000}});
    check("single: boot with line held low 10 s, then idle", r.rings == 0, r); }
  { Result r = runS({{false, 5000}, {true, 8}, {false, 20000}});
    check("single: armed 8 ms glitch", r.rings == 0 && r.glitches == 1, r); }
  { Result r = runS({{false, 5000}, {true, 400}, {false, 20000}});
    check("single: armed 0.4 s blip (under 0.5 s min) -> ignored", r.rings == 0 && r.ignored == 1, r); }
  { Wave w{{false, 5000}};
    for (int i = 0; i < 6; i++) { w.push_back({true, 120}); w.push_back({false, 1500}); }
    Result r = runS(w);
    check("single: six 120 ms plug/unplug glitches", r.rings == 0, r); }
  { Result r = runS({{false, 5000}, {true, 1000}, {false, 20000}}, 1500);
    check("single, min 1.5 s: a 1.0 s blip -> ignored", r.rings == 0 && r.ignored == 1, r); }
  printf("-- real calls MUST page (on the FIRST ring) --\n");
  { Result r = runS(ring(1));
    check("single: ONE ring, then the call rolls to dispatch", r.rings == 1 && r.firstRingMs == 5000 + 500, r); }
  { Result r = runS({{false, 5000}, {true, 900}, {false, 20000}});
    check("single: transferred mid-ring (0.9 s of ringing)", r.rings == 1, r); }
  { Result r = runS(ring(4));
    check("single: US ring x4 -> pages at 0.5 s into ring 1", r.rings >= 1 && r.firstRingMs == 5000 + 500, r); }
  { Wave w{{false, 5000}};
    chatter(w, 2000); w.push_back({false, 4000});
    Result r = runS(w);
    check("single: one ring with 20 Hz chatter", r.rings == 1, r); }
  { Result r = runS({{true, 30}, {false, 3200}, {true, 2000}, {false, 4000}});
    check("single: one ring 3.2 s after boot (armed at 3 s)", r.rings == 1, r); }
  { Result r = runS({{false, 5000}, {true, 2000}, {false, 20000}}, 1500);
    check("single, min 1.5 s: a 2 s ring -> page", r.rings == 1 && r.firstRingMs == 5000 + 1500, r); }
  { Result r = run(ring(4), 12000, 0xFFFFFFFFu - 9000, RD_MODE_SINGLE);
    check("single: across the millis() 2^32 wraparound", r.rings >= 1 && r.firstRingMs == 5000 + 500, r); }
  printf("-- documented limitations --\n");
  { Result r = runS({{false, 5000}, {true, 2000}, {false, 20000}});
    check("LIMIT single: a 2 s brownout while powered + armed -> pages", r.rings == 1, r); }
  { Wave w;
    for (int i = 0; i < 240; i++) { w.push_back({false, 2490}); w.push_back({true, 10}); }
    Result r = run(w, 0, 0, RD_MODE_SINGLE);
    check("LIMIT single: noisy idle never arms (firmware warns)", !r.armed, r); }
  printf("-- switching modes live --\n");
  { RingDet d = {}; d.mode = RD_MODE_PATTERN; uint32_t t = 0; int rings = 0;
    for (; t < 5000; t += STEP) ringStep(&d, false, t);
    for (uint32_t e = 0; e < 2000; e += STEP, t += STEP) rings += ringStep(&d, true, t) == RD_RING;   // ring 1 (pattern: no page)
    d.mode = RD_MODE_SINGLE;                                                                    // switched mid-gap
    for (uint32_t e = 0; e < 4000; e += STEP, t += STEP) ringStep(&d, false, t);
    for (uint32_t e = 0; e < 2000; e += STEP, t += STEP) rings += ringStep(&d, true, t) == RD_RING;   // ring 2: single pages
    Result r; r.rings = rings;
    check("pattern -> single switch mid-call: next ring pages once", rings == 1, r); }

  printf("%s\n", fails ? "SOME TESTS FAILED" : "all ring-detector tests passed");
  return fails ? 1 : 0;
}
