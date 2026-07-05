// Minimal Arduino API stub so LynkTuya.h can be compiled and tested on a
// desktop machine. Only the pieces the library actually uses are provided.
#ifndef ARDUINO_STUB_H
#define ARDUINO_STUB_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <chrono>
#include <thread>

#define PROGMEM
#define F(x) x
#define HEX 16
#define pgm_read_byte(addr) (*(const uint8_t*)(addr))

inline void memcpy_P(void* dst, const void* src, size_t n) {
  memcpy(dst, src, n);
}

inline unsigned long millis() {
  using namespace std::chrono;
  static const steady_clock::time_point start = steady_clock::now();
  return (unsigned long)duration_cast<milliseconds>(steady_clock::now() - start).count();
}

inline void delay(unsigned long ms) {
  std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

class String {
public:
  String() {}
  String(const char* c) : _s(c ? c : "") {}
  String(char c) : _s(1, c) {}
  String(int v) : _s(std::to_string(v)) {}
  String(unsigned int v) : _s(std::to_string(v)) {}
  String(long v) : _s(std::to_string(v)) {}
  String(unsigned long v) : _s(std::to_string(v)) {}

  String& operator+=(const char* c) { _s += c; return *this; }
  String& operator+=(char c) { _s += c; return *this; }
  String& operator+=(const String& o) { _s += o._s; return *this; }
  String& operator+=(int v) { _s += std::to_string(v); return *this; }
  String& operator+=(unsigned int v) { _s += std::to_string(v); return *this; }
  String& operator+=(long v) { _s += std::to_string(v); return *this; }
  String& operator+=(unsigned long v) { _s += std::to_string(v); return *this; }

  bool operator==(const char* c) const { return _s == c; }
  bool operator==(const String& o) const { return _s == o._s; }
  char operator[](unsigned int i) const { return i < _s.size() ? _s[i] : 0; }

  unsigned int length() const { return (unsigned int)_s.size(); }
  const char* c_str() const { return _s.c_str(); }

  int indexOf(const String& p) const {
    size_t pos = _s.find(p._s);
    return pos == std::string::npos ? -1 : (int)pos;
  }
  int indexOf(const char* p) const { return indexOf(String(p)); }

  String substring(unsigned int from, unsigned int to) const {
    if (from > _s.size()) from = (unsigned int)_s.size();
    if (to > _s.size()) to = (unsigned int)_s.size();
    if (to < from) to = from;
    String r;
    r._s = _s.substr(from, to - from);
    return r;
  }

private:
  std::string _s;
};

struct SerialStub {
  template<typename T> void print(const T&) {}
  template<typename T, typename U> void print(const T&, const U&) {}
  template<typename T> void println(const T&) {}
  void println() {}
};
extern SerialStub Serial;

class IPAddress {
public:
  IPAddress() : octets{0, 0, 0, 0} {}
  IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d) : octets{a, b, c, d} {}
  uint8_t octets[4];
};

class Client {
public:
  virtual ~Client() {}
  virtual int connect(IPAddress ip, uint16_t port) = 0;
  virtual size_t write(const uint8_t* buf, size_t size) = 0;
  virtual int available() = 0;
  virtual int read(uint8_t* buf, size_t size) = 0;
  virtual void stop() = 0;
  virtual uint8_t connected() = 0;
};

#endif  // ARDUINO_STUB_H
