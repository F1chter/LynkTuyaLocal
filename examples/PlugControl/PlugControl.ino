/*
  PlugControl - switch a Tuya smart plug on and off over the local network.

  Control commands carry a Unix timestamp; the library reads it from the
  system clock, which just needs to be synced once - timeBegin() from the
  bundled LynkTime helper does that over NTP.

  Use TinyTuya (https://github.com/jasonacox/tinytuya/) to find the device IP,
  Local Key and protocol version, then fill in the values below.
*/

#include <WiFi.h>
#include <LynkTuya.h>

#define WIFI_SSID "MY_WIFI"
#define WIFI_PASS "MY_PASSWORD"
#define NTP_SERVER "pool.ntp.org"

IPAddress plugIP(192, 168, 1, 11);          // device IP, recommended to make it predefined on router
#define PLUG_KEY "0123456789abcdef"         // 16-byte Local Key from TinyTuya

// Pick the template parameter that matches your device: TUYA_V34 or TUYA_V35
LynkTuyaDevice<TUYA_V35> plug(plugIP, PLUG_KEY);

void setup() {
  Serial.begin(115200);
  delay(3000);
  connectWifi();
  timeBegin();  // sync the system clock over NTP once

  plug.getStatus();
  delay(5000);

  plug.turnOn();
  delay(5000);

  plug.turnOff();

  // Other data points can be set directly, e.g. for a dimmer on dps 2:
  //   plug.setDps("2", 500);
  // or a relay on another gang of a multi-socket device:
  //   plug.turnOn(true, "2");
}

void loop() {
  delay(100);
}

void connectWifi() {
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print(F("Connecting to WiFi"));
  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    Serial.print('.');
  }
  Serial.println();
  Serial.print("WiFi connected, IP: ");
  Serial.println(WiFi.localIP());
  WiFi.setSleep(false);  // power-save mode can delay/drop fast LAN replies
}

void timeBegin() {
  configTime(0, 0, NTP_SERVER);

  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    Serial.println("Failed to obtain time");
  }
}
