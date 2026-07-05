// WiFi stub for host-side tests: WiFiClient exists but never connects;
// tests always inject a MockClient instead.
#ifndef WIFI_STUB_H
#define WIFI_STUB_H

#include "Arduino.h"

class WiFiClient : public Client {
public:
  int connect(IPAddress, uint16_t) override { return 0; }
  size_t write(const uint8_t*, size_t) override { return 0; }
  int available() override { return 0; }
  int read(uint8_t*, size_t) override { return -1; }
  void stop() override {}
  uint8_t connected() override { return 0; }
  void setNoDelay(bool) {}
};

#endif  // WIFI_STUB_H
