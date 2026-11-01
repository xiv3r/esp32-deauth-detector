/*
 * ESP32 WiFi Deauthentication Frames Detector
*/

#include <WiFi.h>
#include <WebServer.h>
#include <WiFiUdp.h>
#include <Preferences.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>

// ---------------- Pins ----------------
static constexpr uint8_t PIN_LED    = 1;
static constexpr uint8_t PIN_BUZZER = 25;
static constexpr uint8_t PIN_BOOT   = 0;

// ---------------- Timing ----------------
static constexpr uint32_t ALERT_MS          = 1500;
static constexpr uint32_t FACTORY_HOLD_MS   = 5000;
static constexpr uint32_t NVS_FLUSH_MS      = 60000;
static constexpr uint32_t STA_RETRY_MIN_MS  = 5000;
static constexpr uint32_t STA_RETRY_MAX_MS  = 120000;
static constexpr uint32_t AP_CHECK_MS       = 5000;
static constexpr uint32_t DEAUTH_WINDOW_MS  = 10000;
static constexpr uint32_t DNS_MS            = 100;
static constexpr uint32_t HTTP_BODY_MAX     = 2048;

// ---------------- Config ----------------
static constexpr uint32_t CFG_MAGIC   = 0x45535033u;
static constexpr uint16_t CFG_VERSION = 3;
static constexpr size_t   SSID_MAX    = 32;
static constexpr size_t   PASS_MAX    = 64;
static constexpr size_t   HOST_MAX    = 32;
static constexpr size_t   IP_MAX      = 16;

struct Config {
  uint32_t magic;
  uint16_t version;
  uint16_t crc;
  uint32_t seq;
  char    ap_ssid[SSID_MAX + 1];
  char    ap_pass[PASS_MAX + 1];
  uint8_t ap_channel;
  uint8_t ap_txpower;
  uint8_t ap_hidden;
  uint8_t sta_enabled;
  uint8_t sta_dhcp;
  char    sta_ssid[SSID_MAX + 1];
  char    sta_pass[PASS_MAX + 1];
  char    sta_host[HOST_MAX + 1];
  char    sta_ip[IP_MAX + 1];
  char    sta_gw[IP_MAX + 1];
  char    sta_mask[IP_MAX + 1];
  char    sta_dns[IP_MAX + 1];
  char    sta_mac[18];
  uint8_t portal_enabled;
};

static Config    cfg;
static Config    cfg_work;
static bool      cfg_dirty       = false;
static uint32_t  cfg_last_flush  = 0;
static Preferences prefs;

// ---------------- Runtime ----------------
static WebServer   server(80);
static WiFiUDP     dns_udp;
static bool        ap_up           = false;
static bool        sta_up          = false;
static uint32_t    sta_last_retry  = 0;
static uint32_t    sta_retry_backoff = STA_RETRY_MIN_MS;
static uint32_t    ap_last_check   = 0;

static volatile uint32_t deauth_count         = 0;
static volatile uint32_t deauth_window_start  = 0;
static volatile uint32_t deauth_window_count  = 0;
static volatile uint32_t last_deauth_ms       = 0;
static volatile uint32_t sniffer_drops        = 0;
static volatile uint32_t last_sniffer_pkt_ms  = 0;

static bool      alert_active      = false;
static uint32_t  alert_start       = 0;
static uint32_t  boot_hold_start   = 0;
static bool      boot_held         = false;
static uint32_t  last_dns_pump     = 0;

static bool      dns_running       = false;
static bool      sta_mac_ok        = true;
static uint8_t   applied_tx_power  = 84;

// ---------------- CRC16 ----------------
static uint16_t crc16(const uint8_t* d, size_t n) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= (uint16_t)d[i] << 8;
    for (int b = 0; b < 8; b++)
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  }
  return crc;
}
static size_t cfg_payload_off() { return offsetof(Config, ap_ssid); }
static size_t cfg_payload_len() { return sizeof(Config) - cfg_payload_off(); }
static uint16_t cfg_compute_crc(const Config& c) {
  return crc16(reinterpret_cast<const uint8_t*>(&c) + cfg_payload_off(), cfg_payload_len());
}
static_assert(offsetof(Config, ap_ssid) == 12, "Config layout changed; bump CFG_VERSION");

// ---------------- Safe copy ----------------
static void copy_str(char* dst, size_t cap, const char* src) {
  if (!dst || cap == 0) return;
  if (!src) { dst[0] = 0; return; }
  size_t n = 0;
  while (n < cap - 1 && src[n]) { dst[n] = src[n]; n++; }
  dst[n] = 0;
}

// ---------------- Channel clamp (single source of truth) ----------------
static uint8_t safe_channel(uint8_t ch) {
  return (ch >= 1 && ch <= 13) ? ch : 6;
}

static uint8_t current_radio_channel() {
  uint8_t primary = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  if (esp_wifi_get_channel(&primary, &second) == ESP_OK && primary >= 1 && primary <= 13) {
    return primary;
  }
  return safe_channel(cfg.ap_channel);
}

// ---------------- Defaults ----------------
static void cfg_defaults(Config& c) {
  memset(&c, 0, sizeof(c));
  c.magic = CFG_MAGIC;
  c.version = CFG_VERSION;
  copy_str(c.ap_ssid, sizeof(c.ap_ssid), "ESP32-Setup");
  c.ap_channel = 6;
  c.ap_txpower = 84;
  c.ap_hidden = 0;
  c.sta_enabled = 0;
  c.sta_dhcp = 1;
  copy_str(c.sta_host, sizeof(c.sta_host), "esp32");
  copy_str(c.sta_ip,   sizeof(c.sta_ip),   "192.168.4.50");
  copy_str(c.sta_gw,   sizeof(c.sta_gw),   "192.168.4.1");
  copy_str(c.sta_mask, sizeof(c.sta_mask), "255.255.255.0");
  copy_str(c.sta_dns,  sizeof(c.sta_dns),  "192.168.4.1");
  c.portal_enabled = 1;
  c.seq = 0;
  c.crc = cfg_compute_crc(c);
}

// ---------------- NVS A/B with repair-on-load ----------------
static bool nvs_load_slot(const char* key, Config& out) {
  size_t len = prefs.getBytesLength(key);
  if (len != sizeof(Config)) return false;
  if (prefs.getBytes(key, &out, sizeof(Config)) != sizeof(Config)) return false;
  if (out.magic != CFG_MAGIC) return false;
  if (out.version != CFG_VERSION) return false;
  if (out.crc != cfg_compute_crc(out)) return false;
  return true;
}
static bool nvs_save_slot(const char* key, Config& c) {
  c.magic = CFG_MAGIC;
  c.version = CFG_VERSION;
  c.crc = cfg_compute_crc(c);
  return prefs.putBytes(key, &c, sizeof(Config)) == sizeof(Config);
}

static void cfg_load() {
  prefs.begin("esp32cfg", false);
  Config a, b;
  bool ok_a = nvs_load_slot("cfgA", a);
  bool ok_b = nvs_load_slot("cfgB", b);
  bool repaired = false;

  if (ok_a && ok_b) {
    cfg = (a.seq >= b.seq) ? a : b;
  } else if (ok_a) {
    cfg = a;
    nvs_save_slot("cfgB", cfg);
    repaired = true;
  } else if (ok_b) {
    cfg = b;
    nvs_save_slot("cfgA", cfg);
    repaired = true;
  } else {
    cfg_defaults(cfg);
    nvs_save_slot("cfgA", cfg);
    nvs_save_slot("cfgB", cfg);
    repaired = true;
  }
  cfg_work = cfg;
  cfg_dirty = false;
  cfg_last_flush = millis();
  (void)repaired;
}

static void cfg_commit() {
  cfg_work.magic = CFG_MAGIC;
  cfg_work.version = CFG_VERSION;
  cfg_work.seq = cfg.seq + 1;
  cfg_work.crc = cfg_compute_crc(cfg_work);
  nvs_save_slot("cfgB", cfg_work);
  nvs_save_slot("cfgA", cfg_work);
  cfg = cfg_work;
  cfg_dirty = false;
  cfg_last_flush = millis();
}
static void cfg_mark_dirty() { cfg_dirty = true; }

// ---------------- IP / MAC parsing ----------------
static bool parse_ip(const char* s, IPAddress& out) {
  if (!s || !s[0]) return false;
  return out.fromString(s);
}
static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static bool parse_mac(const char* s, uint8_t out[6]) {
  if (!s || strlen(s) != 17) return false;
  for (int i = 0; i < 6; i++) {
    int hi = hexval(s[i*3]);
    int lo = hexval(s[i*3 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
    if (i < 5 && s[i*3 + 2] != ':') return false;
  }
  if (out[0] & 0x01) return false;
  bool all_zero = true;
  for (int i = 0; i < 6; i++) if (out[i]) { all_zero = false; break; }
  return !all_zero;
}

// ---------------- AP ----------------
static void ap_start() {
  WiFi.mode(WIFI_AP_STA);
  IPAddress ip(192, 168, 4, 1), gw(192, 168, 4, 1), mask(255, 255, 255, 0);
  WiFi.softAPConfig(ip, gw, mask);
  uint8_t ch = safe_channel(cfg.ap_channel);
  const char* pass = (strlen(cfg.ap_pass) >= 8) ? cfg.ap_pass : nullptr;
  bool ok = WiFi.softAP(cfg.ap_ssid, pass, ch, cfg.ap_hidden != 0, 4);
  ap_up = ok;
  if (ok) {
    WiFi.softAPsetHostname("esp32-ap");
    uint8_t p = cfg.ap_txpower;
    if (p < 8)  p = 8;
    if (p > 84) p = 84;
    if (esp_wifi_set_max_tx_power(p) == ESP_OK) applied_tx_power = p;
  }
  applied_tx_power = (uint8_t)((cfg.ap_txpower < 8) ? 8 : (cfg.ap_txpower > 84 ? 84 : cfg.ap_txpower));
}

// ---------------- STA ----------------
static void sta_apply() {
  if (!cfg.sta_enabled || cfg.sta_ssid[0] == 0) {
    WiFi.disconnect(false, false);
    sta_up = false;
    return;
  }

  if (cfg.sta_host[0]) WiFi.setHostname(cfg.sta_host);

  sta_mac_ok = true;
  if (cfg.sta_mac[0]) {
    uint8_t mac[6];
    if (parse_mac(cfg.sta_mac, mac)) {
      esp_err_t e = esp_wifi_set_mac(WIFI_IF_STA, mac);
      if (e != ESP_OK) sta_mac_ok = false;
    } else {
      sta_mac_ok = false;
    }
  }

  if (!cfg.sta_dhcp) {
    IPAddress ip, gw, mask, dns;
    bool ok = parse_ip(cfg.sta_ip, ip) && parse_ip(cfg.sta_gw, gw) &&
              parse_ip(cfg.sta_mask, mask) && parse_ip(cfg.sta_dns, dns);
    if (ok) WiFi.config(ip, gw, mask, dns);
    else    WiFi.config(IPAddress(0,0,0,0), IPAddress(0,0,0,0), IPAddress(0,0,0,0));
  } else {
    WiFi.config(IPAddress(0,0,0,0), IPAddress(0,0,0,0), IPAddress(0,0,0,0));
  }

  WiFi.begin(cfg.sta_ssid, cfg.sta_pass);
  sta_last_retry = millis();
  sta_retry_backoff = STA_RETRY_MIN_MS;
}

// ---------------- Sniffer ----------------
static void IRAM_ATTR sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* p = pkt->payload;
  if (pkt->rx_ctrl.sig_len < 24) { sniffer_drops++; return; }
  uint8_t fc0 = p[0];
  uint8_t subtype = (fc0 >> 4) & 0x0F;
  bool is_mgmt_type = ((fc0 >> 2) & 0x03) == 0x00;
  if (subtype != 0x0C && subtype != 0x0A) return;
  if (type == WIFI_PKT_DATA && !is_mgmt_type) return;

  uint32_t now = millis();
  deauth_count++;
  last_deauth_ms = now;
  last_sniffer_pkt_ms = now;
  if ((uint32_t)(now - deauth_window_start) > DEAUTH_WINDOW_MS) {
    deauth_window_start = now;
    deauth_window_count = 1;
  } else {
    deauth_window_count++;
  }
}

static void sniffer_start() {
  wifi_promiscuous_filter_t filt = {};
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  if (WiFi.status() != WL_CONNECTED) {
    uint8_t want = safe_channel(cfg.ap_channel);
    if (current_radio_channel() != want) {
      esp_wifi_set_channel(want, WIFI_SECOND_CHAN_NONE);
    }
  }
  esp_wifi_set_promiscuous(true);
}

// ---------------- Alerts ----------------
static void alert_trigger() {
  alert_active = true;
  alert_start = millis();
}
static void alert_tick() {
  if (!alert_active) return;
  uint32_t dt = (uint32_t)(millis() - alert_start);
  if (dt >= ALERT_MS) {
    alert_active = false;
    digitalWrite(PIN_LED, LOW);
    digitalWrite(PIN_BUZZER, LOW);
    return;
  }
  bool on = ((dt / 100) & 1) == 0;
  digitalWrite(PIN_LED, on ? HIGH : LOW);
  digitalWrite(PIN_BUZZER, on ? HIGH : LOW);
}

// ---------------- Boot button ----------------
static void boot_button_tick() {
  bool pressed = (digitalRead(PIN_BOOT) == LOW);
  uint32_t now = millis();
  if (pressed && !boot_held) { boot_held = true; boot_hold_start = now; }
  else if (!pressed) { boot_held = false; }
  if (boot_held && (uint32_t)(now - boot_hold_start) >= FACTORY_HOLD_MS) {
    digitalWrite(PIN_LED, LOW);
    digitalWrite(PIN_BUZZER, LOW);
    prefs.clear();
    prefs.end();
    nvs_flash_erase();
    nvs_flash_init();
    delay(50);
    ESP.restart();
  }
}

// ---------------- Captive DNS (non-blocking) ----------------
static void dns_start() {
  if (!cfg.portal_enabled || dns_running) return;
  dns_running = dns_udp.begin(53);
}
static void dns_stop() {
  if (!dns_running) return;
  dns_udp.stop();
  dns_running = false;
}
static void dns_tick() {
  if (!cfg.portal_enabled || !ap_up || !dns_running) return;
  uint32_t now = millis();
  if ((uint32_t)(now - last_dns_pump) < DNS_MS) return;
  last_dns_pump = now;

  int sz = dns_udp.parsePacket();
  if (sz <= 0) return;
  if (sz > 512) { dns_udp.flush(); return; }

  uint8_t buf[512];
  int n = dns_udp.read(buf, sizeof(buf));
  if (n < 12) return;

  uint16_t flags = (uint16_t)((buf[2] << 8) | buf[3]);
  if (flags & 0x8000) return;
  uint16_t qd = (uint16_t)((buf[4] << 8) | buf[5]);
  if (qd != 1) return;

  int off = 12;
  while (off < n && buf[off] != 0) {
    if ((buf[off] & 0xC0) == 0xC0) { off += 1; break; }
    off += buf[off] + 1;
  }
  off += 1;
  if (off + 4 > n) return;
  uint16_t qtype  = (uint16_t)((buf[off] << 8) | buf[off + 1]);
  uint16_t qclass = (uint16_t)((buf[off + 2] << 8) | buf[off + 3]);
  off += 4;
  if (qclass != 1 || (qtype != 1 && qtype != 28 && qtype != 255)) return;

  IPAddress ap = WiFi.softAPIP();

  uint8_t out[512];
  int o = 0;
  out[o++] = buf[0]; out[o++] = buf[1];
  uint16_t rflags = 0x8400 | (flags & 0x0100);
  out[o++] = (uint8_t)(rflags >> 8); out[o++] = (uint8_t)(rflags & 0xFF);
  out[o++] = 0; out[o++] = 1;
  out[o++] = 0; out[o++] = 1;
  out[o++] = 0; out[o++] = 0;
  out[o++] = 0; out[o++] = 0;

  int qlen = off - 12;
  if (o + qlen + 16 > (int)sizeof(out)) return;
  memcpy(out + o, buf + 12, qlen);
  o += qlen;

  if (qtype == 1 || qtype == 255) {
    out[o++] = 0xC0; out[o++] = 0x0C;
    out[o++] = 0x00; out[o++] = 0x01;
    out[o++] = 0x00; out[o++] = 0x01;
    out[o++] = 0x00; out[o++] = 0x00; out[o++] = 0x00; out[o++] = 0x3C;
    out[o++] = 0x00; out[o++] = 0x04;
    out[o++] = ap[0]; out[o++] = ap[1]; out[o++] = ap[2]; out[o++] = ap[3];
  } else {
    out[o++] = 0xC0; out[o++] = 0x0C;
    out[o++] = 0x00; out[o++] = 0x1C;
    out[o++] = 0x00; out[o++] = 0x01;
    out[o++] = 0x00; out[o++] = 0x00; out[o++] = 0x00; out[o++] = 0x3C;
    out[o++] = 0x00; out[o++] = 0x10;
    for (int i = 0; i < 10; i++) out[o++] = 0x00;
    out[o++] = 0xFF; out[o++] = 0xFF;
    out[o++] = ap[0]; out[o++] = ap[1]; out[o++] = ap[2]; out[o++] = ap[3];
  }

  dns_udp.beginPacket(dns_udp.remoteIP(), dns_udp.remotePort());
  dns_udp.write(out, o);
  dns_udp.endPacket();
}

// ---------------- HTTP ----------------
static const char* HTML_HEAD =
  "<!doctype html><html><head><meta charset='utf-8'>"
  "<meta name='viewport' content='width=device-width,initial-scale=1'>"
  "<title>ESP32</title>"
  "<style>body{font-family:system-ui,Arial,sans-serif;margin:0;padding:16px;background:#111;color:#eee}"
  "a{color:#6cf}table{border-collapse:collapse;width:100%}td,th{border:1px solid #333;padding:6px;text-align:left}"
  "input,select{width:100%;box-sizing:border-box;padding:8px;margin:4px 0;background:#222;color:#eee;border:1px solid #444;border-radius:6px}"
  "button{padding:10px 16px;margin:6px 4px 6px 0;background:#2a6;color:#fff;border:0;border-radius:6px;cursor:pointer}"
  "button.warn{background:#a33}.card{background:#1a1a1a;border:1px solid #333;border-radius:10px;padding:12px;margin:12px 0}"
  "nav a{margin-right:12px}.bad{color:#f66}.good{color:#6f6}</style></head><body>"
  "<nav><a href='/'>Home</a><a href='/ap'>AP</a><a href='/sta'>STA</a><a href='/portal'>Portal</a><a href='/deauth'>Deauth</a></nav>";

static void send_html(int code, const String& body) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(code, "text/html; charset=utf-8", body);
}

static bool reject_if_big() {
  if (server.hasHeader("Content-Length")) {
    long cl = server.header("Content-Length").toInt();
    if (cl > (long)HTTP_BODY_MAX) {
      send_html(413, String(HTML_HEAD) + "<div class='card'><h2>Payload too large</h2></div>");
      return true;
    }
  }
  if (server.hasArg("plain") && server.arg("plain").length() > HTTP_BODY_MAX) {
    send_html(413, String(HTML_HEAD) + "<div class='card'><h2>Payload too large</h2></div>");
    return true;
  }
  return false;
}

// --- Home ---
static void page_home() {
  String b = HTML_HEAD;
  b += "<div class='card'><h2>Status</h2><table>";
  b += "<tr><th>AP</th><td class='"; b += ap_up ? "good" : "bad"; b += "'>";
  b += ap_up ? "UP" : "DOWN"; b += " — "; b += cfg.ap_ssid;
  b += " (ch "; b += String(safe_channel(cfg.ap_channel)); b += ", tx "; b += String(applied_tx_power); b += ")</td></tr>";
  b += "<tr><th>STA</th><td class='"; b += sta_up ? "good" : "bad"; b += "'>";
  b += sta_up ? "UP" : "DOWN";
  if (sta_up) { b += " — "; b += WiFi.localIP().toString(); }
  if (cfg.sta_enabled && !sta_mac_ok) b += " <span class='bad'>(custom MAC rejected)</span>";
  b += "</td></tr>";
  b += "<tr><th>AP IP</th><td>"; b += WiFi.softAPIP().toString(); b += "</td></tr>";
  b += "<tr><th>Deauths</th><td>"; b += String((unsigned)deauth_count);
  b += " (last 10s: "; b += String((unsigned)deauth_window_count); b += ")";
  b += "</td></tr>";
  b += "<tr><th>Sniffer drops</th><td>"; b += String((unsigned)sniffer_drops); b += "</td></tr>";
  b += "<tr><th>Heap free</th><td>"; b += String((unsigned)ESP.getFreeHeap()); b += "</td></tr>";
  b += "<tr><th>Uptime</th><td>"; b += String((unsigned long)(millis() / 1000)); b += " s</td></tr>";
  b += "</table></div>";
  send_html(200, b);
}

// --- AP ---
static void page_ap() {
  String b = HTML_HEAD;
  b += "<div class='card'><h2>AP Settings</h2><form method='POST' action='/ap'>";
  b += "<label>SSID<input name='ssid' maxlength='32' value='"; b += cfg_work.ap_ssid; b += "'></label>";
  b += "<label>Password (8+ chars for WPA2; empty or &lt;8 = open)<input name='pass' maxlength='64' value='"; b += cfg_work.ap_pass; b += "'></label>";
  b += "<label>Channel (1-13)<input name='ch' type='number' min='1' max='13' value='"; b += String(cfg_work.ap_channel); b += "'></label>";
  b += "<label>TX power (8-84, 84=20dBm)<input name='tx' type='number' min='8' max='84' value='"; b += String(cfg_work.ap_txpower); b += "'></label>";
  b += "<label>Hidden SSID<input name='hidden' type='checkbox' "; b += cfg_work.ap_hidden ? "checked" : ""; b += "></label>";
  b += "<button type='submit'>Save &amp; Apply</button></form></div>";
  send_html(200, b);
}
static void page_ap_post() {
  if (reject_if_big()) return;
  copy_str(cfg_work.ap_ssid, sizeof(cfg_work.ap_ssid), server.arg("ssid").c_str());
  copy_str(cfg_work.ap_pass, sizeof(cfg_work.ap_pass), server.arg("pass").c_str());
  int ch = server.arg("ch").toInt(); cfg_work.ap_channel = (uint8_t)safe_channel((uint8_t)ch);
  int tx = server.arg("tx").toInt(); if (tx < 8) tx = 8; if (tx > 84) tx = 84; cfg_work.ap_txpower = (uint8_t)tx;
  cfg_work.ap_hidden = server.hasArg("hidden") ? 1 : 0;
  cfg_mark_dirty();
  cfg_commit();

  server.sendHeader("Connection", "close");
  server.sendHeader("Location", "/ap");
  server.send(303, "text/plain", "");
  server.client().stop();
  delay(100);

  ap_start();
  sniffer_start();
  server.begin();
}

// --- STA ---
static void page_sta() {
  String b = HTML_HEAD;
  b += "<div class='card'><h2>STA Settings</h2><form method='POST' action='/sta'>";
  b += "<label>Enable STA<input name='en' type='checkbox' "; b += cfg_work.sta_enabled ? "checked" : ""; b += "></label>";
  b += "<label>SSID<input name='ssid' maxlength='32' value='"; b += cfg_work.sta_ssid; b += "'></label>";
  b += "<label>Password<input name='pass' maxlength='64' value='"; b += cfg_work.sta_pass; b += "'></label>";
  b += "<label>Hostname<input name='host' maxlength='32' value='"; b += cfg_work.sta_host; b += "'></label>";
  b += "<label>Use DHCP<input name='dhcp' type='checkbox' "; b += cfg_work.sta_dhcp ? "checked" : ""; b += "></label>";
  b += "<label>IP<input name='ip' value='"; b += cfg_work.sta_ip; b += "'></label>";
  b += "<label>Gateway<input name='gw' value='"; b += cfg_work.sta_gw; b += "'></label>";
  b += "<label>Subnet mask<input name='mask' value='"; b += cfg_work.sta_mask; b += "'></label>";
  b += "<label>DNS<input name='dns' value='"; b += cfg_work.sta_dns; b += "'></label>";
  b += "<label>MAC (AA:BB:CC:DD:EE:FF or empty)<input name='mac' maxlength='17' value='"; b += cfg_work.sta_mac; b += "'></label>";
  b += "<button type='submit'>Save &amp; Apply</button></form></div>";
  send_html(200, b);
}
static void page_sta_post() {
  if (reject_if_big()) return;
  cfg_work.sta_enabled = server.hasArg("en") ? 1 : 0;
  copy_str(cfg_work.sta_ssid, sizeof(cfg_work.sta_ssid), server.arg("ssid").c_str());
  copy_str(cfg_work.sta_pass, sizeof(cfg_work.sta_pass), server.arg("pass").c_str());
  copy_str(cfg_work.sta_host, sizeof(cfg_work.sta_host), server.arg("host").c_str());
  cfg_work.sta_dhcp = server.hasArg("dhcp") ? 1 : 0;
  copy_str(cfg_work.sta_ip,   sizeof(cfg_work.sta_ip),   server.arg("ip").c_str());
  copy_str(cfg_work.sta_gw,   sizeof(cfg_work.sta_gw),   server.arg("gw").c_str());
  copy_str(cfg_work.sta_mask, sizeof(cfg_work.sta_mask), server.arg("mask").c_str());
  copy_str(cfg_work.sta_dns,  sizeof(cfg_work.sta_dns),  server.arg("dns").c_str());
  copy_str(cfg_work.sta_mac,  sizeof(cfg_work.sta_mac),  server.arg("mac").c_str());
  cfg_mark_dirty();
  cfg_commit();
  WiFi.disconnect(false, false);
  sta_apply();
  if (WiFi.softAPIP() == IPAddress(0, 0, 0, 0)) {
    ap_start();
    sniffer_start();
  }
  server.sendHeader("Location", "/sta");
  server.send(303, "text/plain", "");
}

// --- Portal ---
static void page_portal() {
  String b = HTML_HEAD;
  b += "<div class='card'><h2>Captive Portal</h2><form method='POST' action='/portal'>";
  b += "<label>Enabled<input name='en' type='checkbox' "; b += cfg_work.portal_enabled ? "checked" : ""; b += "></label>";
  b += "<button type='submit'>Save</button></form></div>";
  send_html(200, b);
}
static void page_portal_post() {
  if (reject_if_big()) return;
  cfg_work.portal_enabled = server.hasArg("en") ? 1 : 0;
  cfg_mark_dirty();
  cfg_commit();
  if (cfg.portal_enabled) dns_start(); else dns_stop();
  server.sendHeader("Location", "/portal");
  server.send(303, "text/plain", "");
}

// --- Deauth ---
static void page_deauth() {
  uint32_t dc    = deauth_count;
  uint32_t wc    = deauth_window_count;
  uint32_t ldm   = last_deauth_ms;
  uint32_t drops = sniffer_drops;
  uint32_t age   = ldm ? (uint32_t)(millis() - ldm) : 0;
  uint8_t  actual_ch = current_radio_channel();
  uint8_t  cfg_ch    = safe_channel(cfg.ap_channel);

  String b = HTML_HEAD;
  b += "<div class='card'><h2>Deauth Detector</h2><table>";
  b += "<tr><th>Total detected</th><td>"; b += String((unsigned)dc); b += "</td></tr>";
  b += "<tr><th>Last 10s</th><td>"; b += String((unsigned)wc); b += "</td></tr>";
  b += "<tr><th>Last seen (ms ago)</th><td>"; b += String((unsigned)age); b += "</td></tr>";
  b += "<tr><th>Sniffer drops</th><td>"; b += String((unsigned)drops); b += "</td></tr>";
  b += "<tr><th>Radio channel (actual)</th><td>"; b += String(actual_ch);
  b += " (AP setting: "; b += String(cfg_ch); b += ")";
  if (actual_ch != cfg_ch) {
    b += " <span class='bad'>(STA forced a different channel)</span>";
  }
  b += "</td></tr>";
  b += "</table><p>Sniffer observes the radio's current channel. "
       "Deauths on other channels are not visible on a single radio.</p></div>";
  send_html(200, b);
}

// --- Captive probes ---
static void send_redirect_captive() {
  String target = "http://" + WiFi.softAPIP().toString() + "/";
  server.sendHeader("Location", target);
  server.send(302, "text/plain", "");
}

static void setup_routes() {
  server.on("/", HTTP_GET, page_home);
  server.on("/ap", HTTP_GET, page_ap);
  server.on("/ap", HTTP_POST, page_ap_post);
  server.on("/sta", HTTP_GET, page_sta);
  server.on("/sta", HTTP_POST, page_sta_post);
  server.on("/portal", HTTP_GET, page_portal);
  server.on("/portal", HTTP_POST, page_portal_post);
  server.on("/deauth", HTTP_GET, page_deauth);

  server.on("/generate_204", HTTP_GET, send_redirect_captive);
  server.on("/gen_204", HTTP_GET, send_redirect_captive);
  server.on("/hotspot-detect.html", HTTP_GET, send_redirect_captive);
  server.on("/library/test/success.html", HTTP_GET, send_redirect_captive);
  server.on("/connecttest.txt", HTTP_GET, send_redirect_captive);
  server.on("/redirect", HTTP_GET, send_redirect_captive);
  server.on("/ncsi.txt", HTTP_GET, send_redirect_captive);

  server.onNotFound([]() {
    if (cfg.portal_enabled) send_redirect_captive();
    else send_html(404, String(HTML_HEAD) + "<div class='card'><h2>404</h2></div>");
  });
}

// ---------------- Cooperative tick ----------------
static void tick() {
  uint32_t now = millis();

  server.handleClient();
  dns_tick();
  alert_tick();
  boot_button_tick();

  uint32_t ld = last_deauth_ms;
  static uint32_t seen_deauth_ms = 0;
  if (ld != 0 && ld != seen_deauth_ms) {
    seen_deauth_ms = ld;
    alert_trigger();
  }

  if (cfg.sta_enabled && cfg.sta_ssid[0] && WiFi.status() != WL_CONNECTED) {
    sta_up = false;
    if ((uint32_t)(now - sta_last_retry) >= sta_retry_backoff) {
      sta_last_retry = now;
      wl_status_t st = WiFi.status();
      if (st == WL_CONNECT_FAILED || st == WL_NO_SSID_AVAIL || st == WL_IDLE_STATUS) {
        WiFi.disconnect(false, false);
        WiFi.begin(cfg.sta_ssid, cfg.sta_pass);
        if (sta_retry_backoff < STA_RETRY_MAX_MS) {
          sta_retry_backoff *= 2;
          if (sta_retry_backoff > STA_RETRY_MAX_MS) sta_retry_backoff = STA_RETRY_MAX_MS;
        }
      }
    }
  } else {
    sta_up = (cfg.sta_enabled && cfg.sta_ssid[0] && WiFi.status() == WL_CONNECTED);
    if (sta_up) sta_retry_backoff = STA_RETRY_MIN_MS;
  }

  if ((uint32_t)(now - ap_last_check) >= AP_CHECK_MS) {
    ap_last_check = now;
    if (WiFi.softAPIP() == IPAddress(0, 0, 0, 0)) {
      ap_up = false;
      ap_start();
      sniffer_start();
    } else {
      ap_up = true;
    }
    if (!sta_up) {
      uint8_t want = safe_channel(cfg.ap_channel);
      if (current_radio_channel() != want) {
        esp_wifi_set_channel(want, WIFI_SECOND_CHAN_NONE);
      }
    }
    {
      uint8_t want_p = cfg.ap_txpower;
      if (want_p < 8)  want_p = 8;
      if (want_p > 84) want_p = 84;
      if (applied_tx_power != want_p) {
        if (esp_wifi_set_max_tx_power(want_p) == ESP_OK) applied_tx_power = want_p;
      }
    }
    if (cfg.portal_enabled && ap_up) {
      if (!dns_running) dns_start();
    } else if (!cfg.portal_enabled && dns_running) {
      dns_stop();
    }
  }

  if (cfg_dirty && (uint32_t)(now - cfg_last_flush) >= NVS_FLUSH_MS) {
    cfg_commit();
  }
}

// ---------------- setup / loop ----------------
void setup() {
  esp_log_level_set("*", ESP_LOG_NONE);

  pinMode(PIN_LED, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_BOOT, INPUT_PULLUP);
  digitalWrite(PIN_LED, LOW);
  digitalWrite(PIN_BUZZER, LOW);

  cfg_load();

  ap_start();
  sta_apply();
  sniffer_start();
  if (cfg.portal_enabled) dns_start();

  setup_routes();
  server.begin();

  cfg_last_flush = millis();
  last_dns_pump = millis();
  ap_last_check = millis();
  sta_last_retry = millis();
}

void loop() {
  tick();
  delay(1);
}
