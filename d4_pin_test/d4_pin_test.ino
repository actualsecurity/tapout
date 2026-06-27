/*
 * D4 ring-pin test sketch
 * -------------------------------------------------------------------------
 * Open item #2 from the project notes: confirm the ELK-930 actually pulls D4
 * LOW during a real ring before trusting the main firmware.
 *
 * Upload this, open Serial Monitor @ 115200, then call the station line.
 * You should see the state flip 1 -> 0 during each ~2 s ring burst, in the
 * US cadence (2 s on / 4 s off). The onboard LED also lights on LOW.
 *
 * Reminder: reference the pin as D4, never a bare 4 (Nano ESP32 gotcha).
 * -------------------------------------------------------------------------
 */

static const int RING_PIN = D4;

void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(RING_PIN, INPUT_PULLUP);
  pinMode(LED_RED, OUTPUT);
  digitalWrite(LED_RED, HIGH);   // active-low: off
  Serial.println(F("[test] reading D4 -- idle should be 1, ring should be 0"));
}

void loop() {
  int v = digitalRead(RING_PIN);
  Serial.printf("D4 = %d  %s\n", v, v == LOW ? "<<< RING (LOW)" : "");
  digitalWrite(LED_RED, v == LOW ? LOW : HIGH);  // light red on ring
  delay(100);
}
