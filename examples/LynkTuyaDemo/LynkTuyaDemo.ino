/*
  GetStatus - read the current status of a Tuya device over the local network.

  Use TinyTuya (https://github.com/jasonacox/tinytuya/) to find the device IP,
  Local Key and protocol version, then fill in the values below.
*/

#include <WiFi.h>
#include "time.h"
#include <LynkTuya.h>

#define WIFI_SSID "MY_WIFI"
#define WIFI_PASS "MY_PASSWORD"
#define NTP_SERVER "pool.ntp.org"

IPAddress plugIP(192, 168, 1, 11);          // device IP, recommended to make it predefined on router
#define PLUG_KEY "0123456789abcdef"         // 16-byte Local Key from TinyTuya

// Pick the template parameter that matches your device: TUYA_V34 or TUYA_V35
LynkTuyaDevice<TUYA_V35> plug(plugIP, PLUG_KEY);
uint32_t lastHeartbeatMillis;

void onDpsUpdate(const String &json) {
  Serial.print("Device pushed an update: ");
  Serial.println(json);
}

void setup() {
  Serial.begin(115200);
  delay(3000);
  connectWifi();
  timeBegin();

  // Full status JSON
  String json;
  if (plug.getStatus(json)) {
    Serial.print("Device status: ");
    Serial.println(json);
  } else {
    Serial.println("Status request failed");
  }

  // Or just the relay state of one dps id
  bool on;
  if (plug.getRelayState(on)) {
    Serial.print("Relay is ");
    Serial.println(on ? "ON" : "OFF");
  }

  delay(5000);
  plug.turnOn();
  delay(5000);
  plug.turnOff();
  
  plug.onDpsUpdate(onDpsUpdate);
  if (!plug.connectToPlug() || !plug.handshake()) {
    Serial.println("Could not open a session to the plug");
    return;
  }
  Serial.println("Listening for device updates...");
}

void loop() {
  plug.poll();  // dispatches pushed dps updates to the callback

  if (millis() - lastHeartbeatMillis > 10000) {
    lastHeartbeatMillis = millis();
    if (!plug.heartbeat()) {
      Serial.println("Heartbeat failed, reconnecting...");
      plug.closeConnection();
      if (plug.connectToPlug()) plug.handshake();
    }
  }
  delay(50);
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