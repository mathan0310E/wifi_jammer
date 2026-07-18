
## 1. Arduino IDE setup

1. Install **Arduino IDE** (2.x).
2. `File > Preferences > Additional Boards Manager URLs`, add:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. `Tools > Board > Boards Manager` -> install **esp32 by Espressif Systems**.
4. Select board: `Tools > Board > ESP32 Arduino > ESP32 Dev Module`.
5. (Only if using NRF24) `Tools > Manage Libraries` -> install **RF24 by TMRh20**.

## 2. Flash

1. Open `esp32_deauther.ino`.
2. Plug in the ESP32, pick the COM port under `Tools > Port`.
3. Click **Upload**. If it hangs on "Connecting...", hold the **BOOT** button
   on the ESP32 while it starts uploading.

## 3. Use

1. On your phone/laptop, connect to WiFi:
   - **SSID:** `Wolf Attacker`
   - **Password:** `Tamil123`  
     (WPA2 needs at least 8 characters, so `Tamil` is stored as `Tamil123`)
2. Open a browser to **http://google.com**  
   (captive portal — also works with **http://192.168.4.1**)
3. Press **SCAN WIFI**, then press **JAM / DEAUTH** on your target row.
4. Press **STOP** to end.

Change `AP_SSID` / `AP_PASS` at the top of the `.ino` if you want.

---

## 4. NRF24L01 wiring (optional)

The NRF24L01 uses SPI. Set `#define USE_NRF24 1` at the top of the sketch to
enable it. **Power the module from 3.3V only** (5V will destroy it). A 10uF
capacitor across VCC/GND close to the module greatly improves stability.

```
        NRF24L01 (top view, pins facing you)
        +-----------------------+
        |  GND   VCC            |   1 GND   2 VCC(3V3)
        |  CE    CSN            |   3 CE    4 CSN
        |  SCK   MOSI           |   5 SCK   6 MOSI
        |  MISO  IRQ            |   7 MISO  8 IRQ (not used)
        +-----------------------+

   NRF24L01 pin      ->   ESP32 pin
   ------------------------------------
   1  GND            ->   GND
   2  VCC (3.3V)     ->   3V3   (NEVER 5V)
   3  CE             ->   GPIO 22
   4  CSN            ->   GPIO 21
   5  SCK            ->   GPIO 18   (VSPI SCK)
   6  MOSI           ->   GPIO 23   (VSPI MOSI)
   7  MISO           ->   GPIO 19   (VSPI MISO)
   8  IRQ            ->   (leave unconnected)

   Recommended: 10uF capacitor between VCC and GND at the module.
```

Wiring diagram (ASCII):

```
   ESP32                         NRF24L01
 +---------+                    +----------+
 |     3V3 |--------------------| VCC      |
 |     GND |----------+---------| GND      |
 |         |          |         |          |
 |  GPIO22 |----------|---------| CE       |
 |  GPIO21 |----------|---------| CSN      |
 |  GPIO18 |----------|---------| SCK      |
 |  GPIO23 |----------|---------| MOSI     |
 |  GPIO19 |----------|---------| MISO     |
 +---------+          |         | IRQ  (nc)|
                      |         +----------+
                    [10uF]  (VCC <-> GND at module)
```

CE/CSN pins are configurable via `NRF_CE_PIN` / `NRF_CSN_PIN` in the sketch.
The SPI pins (18/19/23) are the ESP32 default VSPI bus.

---

