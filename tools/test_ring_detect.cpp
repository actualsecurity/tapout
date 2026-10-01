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
static Result run(const Wave& w, uint32_t tailIdleMs = 12000, uint32_t t0 = 0) {
  RingDet d = {};
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

  printf("%s\n", fails ? "SOME TESTS FAILED" : "all ring-detector tests passed");
  return fails ? 1 : 0;
}
