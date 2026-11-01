# ESP32 Wiring Connections

## Components

| Component | ESP32 Pin | Notes |
|---|---|---|
| **LED** (with resistor) | GPIO 1 | Anode → GPIO1, cathode → 220–330 Ω → GND |
| **Buzzer** (active) | GPIO 25 | Positive → GPIO25, negative → GND |
| **Boot / Factory Reset button** | GPIO 0 | One leg → GPIO0, other leg → GND (internal pull-up used) |

---

## Detailed wiring

### 1. LED (deauth alert indicator)
```
GPIO1 ──►[ 220–330 Ω ]──►│◄│──► GND
                        (LED anode = long leg)
```
- GPIO1 is UART0 TX, repurposed as LED output (serial TX is disabled by design in this firmware).
- If using a bare LED: 220 Ω for a 3.3 V supply, 330 Ω for safety margin.
- For a 5 V LED strip / module with its own resistor, connect directly.

### 2. Buzzer (deauth alert buzzer)
```
GPIO25 ──►(+) Buzzer (-)──► GND
```
- Use an **active** buzzer (with internal oscillator) — the firmware drives it with a simple HIGH/LOW square wave at 5 Hz.
- If using a **passive** buzzer, add a small transistor driver (2N2222 / BC547) with a 1 kΩ base resistor, because GPIO25 cannot source enough current for a passive piezo at volume.
- If the buzzer is **active-low** (common on some modules), invert the two `digitalWrite` calls in `alert_tick()`.

### 3. Boot / Factory Reset button
```
GPIO0 ──►[ push button ]──► GND
```
- **No external pull-up needed** — the firmware uses `INPUT_PULLUP`.
- Hold for **5 seconds** while running → wipes NVS + Wi-Fi driver cache + reboots.
- ⚠️ Do **not** hold this button while powering on — the ESP32 bootloader will enter **download mode** instead of running the sketch.

---

## Power

```
ESP32 3V3  ──► LED anode resistor, buzzer (+ if 3.3 V type)
ESP32 GND  ──► LED cathode, buzzer (–), button leg
ESP32 VIN / 5V ──► USB or 5 V supply (if using a 5 V buzzer or LED module)
```

- Total current draw: LED (~10 mA) + active buzzer (~30 mA) = well within the ESP32's regulator budget.
- Do **not** power the ESP32 from the 3V3 pin while also using USB — use one source.

---

## Optional — status LED on the dev board

Most ESP32 dev boards have a built-in LED on **GPIO2**. This firmware does **not** use it. If you want a secondary indicator, wire a second LED to GPIO2 the same way as GPIO1, but note GPIO2 must be **low or floating** at boot (it is a strapping pin) — a plain LED with series resistor is safe because it does not pull the pin high hard enough to affect boot mode.

---

## Quick-reference table

| Signal | GPIO | Direction | Purpose |
|---|---|---|---|
| LED | 1 | Output | Blinks 5 Hz during 1.5 s alert on deauth |
| Buzzer | 25 | Output | Sounds 5 Hz during 1.5 s alert on deauth |
| Boot button | 0 | Input (pull-up) | 5 s hold → factory reset |
| GND | — | — | Common ground for all three |
| 3V3 | — | Power | LED anode resistor, buzzer V+ (if 3.3 V) |
