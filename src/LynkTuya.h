#ifndef LYNK_TUYA_H
#define LYNK_TUYA_H

#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

// Define LYNKTUYA_DEBUG as 1 before including this header to enable verbose
// Serial logging of the handshake and packet contents (this also prints the
// derived session key, so keep it disabled in production builds).
#ifndef LYNKTUYA_DEBUG
#define LYNKTUYA_DEBUG 0
#endif

#if LYNKTUYA_DEBUG
#define LYNK_LOG(...) Serial.print(__VA_ARGS__)
#define LYNK_LOGLN(...) Serial.println(__VA_ARGS__)
#define LYNK_LOG_HEX(...) printHex(__VA_ARGS__)
#else
#define LYNK_LOG(...)
#define LYNK_LOGLN(...)
#define LYNK_LOG_HEX(...)
#endif

enum TuyaProtocolVersion {
  TUYA_V34,
  TUYA_V35
};
#define TUYA_PORT 6668
#define RESPONSE_BUFFER_SIZE 256
#define PAYLOAD_BUFFER_SIZE 256
#define POLL_FRAME_TIMEOUT_MS 300  // max wait to finish an in-flight frame during poll(0)

/* CLASS DEFINITION*/
template<TuyaProtocolVersion _VERSION>
class LynkTuyaDevice {
public:
  typedef void (*DpsCallback)(const String &json);

  LynkTuyaDevice(IPAddress ipAdress, const char* localKey)
    : _ipAddress(ipAdress), _client(&_ownClient) {
    _init(localKey);
  }

  // Use an externally managed Client (e.g. an EthernetClient or a mock in
  // tests) instead of the built-in WiFiClient.
  LynkTuyaDevice(IPAddress ipAdress, const char* localKey, Client &client)
    : _ipAddress(ipAdress), _client(&client) {
    _init(localKey);
  }

  // How long to wait for a device response (default 5000 ms).
  void setTimeout(uint32_t timeoutMs) {
    _timeoutMs = timeoutMs;
  }

  // Called whenever the device pushes a dps update (command 8) on an open
  // connection - e.g. when the physical button is pressed. Received frames
  // are processed during poll() and while waiting for command responses.
  void onDpsUpdate(DpsCallback callback) {
    _pushCallback = callback;
  }

  // ---------- Networking ----------
  bool connectToPlug() {
    LYNK_LOG("Connecting to plug ");
    LYNK_LOG(_ipAddress);
    LYNK_LOG(':');
    LYNK_LOG(TUYA_PORT);
    if (!_client->connect(_ipAddress, TUYA_PORT)) {
      LYNK_LOGLN(" - failed");
      return false;
    }
    if (_client == &_ownClient)
      _ownClient.setNoDelay(true);
    LYNK_LOGLN(" - connected");
    return true;
  }

  bool closeConnection() {
    _client->stop();
    return true;
  }

  bool handshake() {
    _sendCommand3();
    if (_readFrame(_timeoutMs) != 0x04 || !_parseCommand3Response())
      return false;
    _sendCommand5();
    _calculateSessionKey();
    _seqNo = 3;
    return true;
  }

  // ---------- Status ----------
  bool getStatus(bool autoCloseConnection = true) {
    if (!_ensureSession()) {
      if (autoCloseConnection) closeConnection();
      return false;
    }
    const uint8_t emptyJson[2] = { '{', '}' };
    bool ok = _sendSessionFrame(0x10, emptyJson, 2) && _awaitResponse(0x10) && _parseCommandResponse();
    if (autoCloseConnection) closeConnection();
    return ok;
  }

  // Same as getStatus() but also copies the device's decrypted status JSON
  // (e.g. {"dps":{"1":true,"9":0}}) into jsonOut.
  bool getStatus(String &jsonOut, bool autoCloseConnection = true) {
    if (!getStatus(autoCloseConnection)) return false;
    jsonOut = _lastJson;
    return true;
  }

  // Reads the device status and extracts the boolean state of one dps id.
  // Returns false if the request failed or the dps id is not a boolean.
  bool getRelayState(bool &isOn, const char* dpsId = "1", bool autoCloseConnection = true) {
    if (!getStatus(autoCloseConnection)) return false;
    return _dpsBoolFromJson(_lastJson, dpsId, isOn);
  }

  // Decrypted JSON payload of the last successful response or push.
  const String& lastJson() const {
    return _lastJson;
  }

  // ---------- Control ----------
  bool turnOn(uint32_t timestamp, bool autoCloseConnection = true, const char* dpsId = "1") {
    return turn(timestamp, true, autoCloseConnection, dpsId);
  }

  bool turnOff(uint32_t timestamp, bool autoCloseConnection = true, const char* dpsId = "1") {
    return turn(timestamp, false, autoCloseConnection, dpsId);
  }

  bool turn(uint32_t timestamp, bool on, bool autoCloseConnection = true, const char* dpsId = "1") {
    return setDps(dpsId, on, autoCloseConnection, timestamp);
  }

  // Variants that read the current time from the system clock; the clock must be synced first.
  bool turnOn(bool autoCloseConnection = true, const char* dpsId = "1") {
    return turn(true, autoCloseConnection, dpsId);
  }

  bool turnOff(bool autoCloseConnection = true, const char* dpsId = "1") {
    return turn(false, autoCloseConnection, dpsId);
  }

  bool turn(bool on, bool autoCloseConnection = true, const char* dpsId = "1") {
    return setDps(dpsId, on, autoCloseConnection);
  }

  // Set an arbitrary data point: boolean, integer or string value.
  // timestamp = 0 means "use the system clock".
  bool setDps(const char* dpsId, bool value, bool autoCloseConnection = true, uint32_t timestamp = 0) {
    return _setDpsLiteral(dpsId, value ? String(F("true")) : String(F("false")), autoCloseConnection, timestamp);
  }

  bool setDps(const char* dpsId, int value, bool autoCloseConnection = true, uint32_t timestamp = 0) {
    return _setDpsLiteral(dpsId, String(value), autoCloseConnection, timestamp);
  }

  bool setDps(const char* dpsId, const char* value, bool autoCloseConnection = true, uint32_t timestamp = 0) {
    String literal(F("\""));
    literal += value;
    literal += F("\"");
    return _setDpsLiteral(dpsId, literal, autoCloseConnection, timestamp);
  }

  // ---------- Persistent connections ----------
  // Keeps a long-lived connection alive (command 9). Call every ~10 s when
  // holding a connection open, otherwise the device drops it.
  bool heartbeat(bool autoCloseConnection = false) {
    if (!_ensureSession()) {
      if (autoCloseConnection) closeConnection();
      return false;
    }
    bool ok = _sendSessionFrame(0x09, nullptr, 0) && _awaitResponse(0x09);
    if (autoCloseConnection) closeConnection();
    return ok;
  }

  // Processes one pending frame on an open connection, dispatching dps
  // pushes to the onDpsUpdate callback. With waitMs = 0 it returns
  // immediately when no data is pending. Returns true if a frame was read.
  bool poll(uint32_t waitMs = 0) {
    if (!_client->connected()) return false;
    if (waitMs == 0 && !_client->available()) return false;
    // With waitMs = 0 a frame has already started arriving; give it a short,
    // bounded window to finish rather than the full response timeout, so a
    // stalled or partial frame can't block the caller's loop() for seconds.
    uint32_t frameTimeout = (waitMs == 0) ? POLL_FRAME_TIMEOUT_MS : waitMs;
    int cmd = _readFrame(frameTimeout);
    if (cmd < 0) return false;
    if (cmd == 0x08) _handlePush();
    return true;
  }

private:
  void _init(const char* localKey) {
    size_t keyLen = strnlen(localKey, sizeof(_localKey));
    if (keyLen < sizeof(_localKey)) {
      Serial.println(F("LynkTuyaDevice: localKey must be 16 bytes, got fewer - padding with zeros"));
    }
    memset(_localKey, 0, sizeof(_localKey));
    memcpy(_localKey, localKey, keyLen);
    if (_VERSION == TUYA_V34)
      _prepareCmd03Request();  //prepare once, use in every handshake
    else if (_VERSION == TUYA_V35)
      _prepareCmd03RequestV35();
  }

  bool _ensureSession() {
    if (_client->connected()) return true;
    return connectToPlug() && handshake();
  }

  bool _setDpsLiteral(const char* dpsId, const String &valueLiteral, bool autoCloseConnection, uint32_t timestamp) {
    if (timestamp == 0) {
      timestamp = (uint32_t)time(nullptr);
      if (timestamp < 1000000000UL)
        Serial.println(F("LynkTuya: system clock is not set, call timeBegin() first"));
    }
    String json = String(F("{\"protocol\":5,\"t\":"));
    json += timestamp;
    json += F(",\"data\":{\"dps\":{\"");
    json += dpsId;
    json += F("\":");
    json += valueLiteral;
    json += F("}}}");
    LYNK_LOG("json =");
    LYNK_LOGLN(json);
    if (!_ensureSession()) {
      if (autoCloseConnection) closeConnection();
      return false;
    }
    bool ok = _sendCommand0d(json) && _awaitResponse(0x0d) && _parseCommandResponse(true);
    if (autoCloseConnection) closeConnection();
    return ok;
  }

  /*====================================HELPERS====================================*/
  void writeU32BE(uint8_t* buf, uint32_t v) {
    buf[0] = (v >> 24) & 0xFF;
    buf[1] = (v >> 16) & 0xFF;
    buf[2] = (v >> 8) & 0xFF;
    buf[3] = v & 0xFF;
  }

  uint32_t readU32BE(const uint8_t* buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
  }

  // PKCS7 padding: always adds at least 1 byte, up to a full 16-byte block
  // if the input is already a multiple of 16 (matches Tuya's own padding) add more 16 bytes
  size_t pkcs7Pad(uint8_t* buf, size_t len) {
    uint8_t padLen = 16 - (len % 16);
    for (uint8_t i = 0; i < padLen; i++) buf[len + i] = padLen;
    return len + padLen;
  }

  /*ECB for v34*/

  // AES-128-ECB encrypt in place, len must be a multiple of 16
  void aesEcbEncrypt(const uint8_t* key, uint8_t* buf, size_t len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    for (size_t i = 0; i < len; i += 16) {
      mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, buf + i, buf + i);
    }
    mbedtls_aes_free(&aes);
  }

  // AES-128-ECB decrypt in place, len must be a multiple of 16
  void aesEcbDecrypt(const uint8_t* key, uint8_t* buf, size_t len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);
    for (size_t i = 0; i < len; i += 16) {
      mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, buf + i, buf + i);
    }
    mbedtls_aes_free(&aes);
  }

  /*GCM for v35*/

  void aesGcmEncrypt(const uint8_t* key,
                     const uint8_t* plaintext,
                     size_t plaintextLen,
                     const uint8_t* iv,
                     size_t ivLen,
                     const uint8_t* authD,
                     size_t authDLen,
                     uint8_t* ciphertext,
                     uint8_t* tag,
                     size_t tagLen) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
    int rc = mbedtls_gcm_starts(&gcm, MBEDTLS_GCM_ENCRYPT, iv, ivLen);
    if (rc == 0) rc = mbedtls_gcm_update_ad(&gcm, authD, authDLen);
    if (rc == 0 && plaintextLen > 0) {
      size_t outLen = 0;
      rc = mbedtls_gcm_update(&gcm, plaintext, plaintextLen, ciphertext, plaintextLen, &outLen);
    }
    if (rc == 0) {
      size_t finishLen = 0;
      rc = mbedtls_gcm_finish(&gcm, nullptr, 0, &finishLen, tag, tagLen);
    }
    mbedtls_gcm_free(&gcm);
    LYNK_LOG("Encrypt result code:");
    LYNK_LOGLN(rc);
    (void)rc;
  }

  bool aesGcmDecrypt(const uint8_t* key,
                     const uint8_t* ciphertext,
                     size_t ciphertextLen,
                     const uint8_t* iv,
                     size_t ivLen,
                     const uint8_t* authD,
                     size_t authDLen,
                     const uint8_t* tag,
                     size_t tagLen,
                     uint8_t* plaintext) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
    int rc = mbedtls_gcm_starts(&gcm, MBEDTLS_GCM_DECRYPT, iv, ivLen);
    if (rc == 0) rc = mbedtls_gcm_update_ad(&gcm, authD, authDLen);
    if (rc == 0 && ciphertextLen > 0) {
      size_t outLen = 0;
      rc = mbedtls_gcm_update(&gcm, ciphertext, ciphertextLen, plaintext, ciphertextLen, &outLen);
    }
    uint8_t computedTag[16];
    if (rc == 0) {
      size_t finishLen = 0;
      rc = mbedtls_gcm_finish(&gcm, nullptr, 0, &finishLen, computedTag, tagLen);
    }
    mbedtls_gcm_free(&gcm);
    bool ok = (rc == 0) && memcmp(computedTag, tag, tagLen) == 0;
    LYNK_LOG("Decrypt ok:");
    LYNK_LOGLN(ok);
    return ok;
  }

  //return 32 byte signature hash
  void hmacSha256(const uint8_t* key, size_t keyLen,
                  const uint8_t* data, size_t dataLen, uint8_t* out32) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLen);
    mbedtls_md_hmac_update(&ctx, data, dataLen);
    mbedtls_md_hmac_finish(&ctx, out32);
    mbedtls_md_free(&ctx);
  }

  void printHex(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
      if (buf[i] < 0x10) LYNK_LOG('0');
      LYNK_LOG(buf[i], HEX);
    }
    LYNK_LOGLN();
  }

  /*====================================FRAME READING====================================*/

  // Reads exactly `need` bytes into dst, tolerating TCP fragmentation.
  bool _readExact(uint8_t* dst, size_t need, unsigned long start, uint32_t timeoutMs) {
    size_t got = 0;
    while (got < need) {
      if (millis() - start > timeoutMs) {
        LYNK_LOG(F("timeout reading frame, connected="));
        LYNK_LOGLN(_client->connected());
        return false;
      }
      int avail = _client->available();
      if (avail > 0) {
        size_t want = need - got;
        if ((size_t)avail < want) want = avail;
        int n = _client->read(dst + got, want);
        if (n > 0) got += n;
      } else {
        delay(1);
      }
    }
    return true;
  }

  // Reads one complete Tuya frame (header + declared length) into
  // _response_buffer, waiting out split TCP segments. Returns the frame's
  // command id, or -1 on timeout / malformed data.
  int _readFrame(uint32_t timeoutMs) {
    const size_t headerLen = (_VERSION == TUYA_V34) ? 16 : 18;
    unsigned long start = millis();
    memset(_response_buffer, 0, RESPONSE_BUFFER_SIZE);
    _responseSize = 0;
    if (!_readExact(_response_buffer, headerLen, start, timeoutMs)) return -1;

    const uint8_t* prefix = (_VERSION == TUYA_V34) ? V34_PREFIX_MAGIC : V35_PREFIX_MAGIC;
    for (int i = 0; i < 4; i++) {
      if (_response_buffer[i] != pgm_read_byte(prefix + i)) {
        LYNK_LOGLN("Frame with unexpected prefix, dropping");
        return -1;
      }
    }

    uint32_t length = readU32BE(_response_buffer + headerLen - 4);
    uint32_t cmd = readU32BE(_response_buffer + (_VERSION == TUYA_V34 ? 8 : 10));
    // v3.4 length covers everything after the header; v3.5 excludes the suffix.
    // Bound the attacker-controlled length against the buffer BEFORE adding it,
    // so a near-UINT32_MAX value can't wrap `total` to a small number and slip
    // an unbounded read past the check below.
    const size_t suffix = (_VERSION == TUYA_V35) ? 4 : 0;
    if (length < 8 || length > RESPONSE_BUFFER_SIZE - headerLen - suffix) {
      LYNK_LOGLN("Frame length out of range");
      return -1;
    }
    size_t total = headerLen + length + suffix;
    if (!_readExact(_response_buffer + headerLen, total - headerLen, start, timeoutMs)) return -1;
    _responseSize = total;

    LYNK_LOG("Got frame cmd ");
    LYNK_LOG(cmd);
    LYNK_LOG(", ");
    LYNK_LOG((uint32_t)total);
    LYNK_LOGLN(" bytes:");
    LYNK_LOG_HEX(_response_buffer, _responseSize);
    return (int)cmd;
  }

  // Waits for a frame with the expected command id, dispatching any dps
  // pushes (command 8) that arrive in between to the callback.
  bool _awaitResponse(uint32_t expectedCmd) {
    unsigned long start = millis();
    for (;;) {
      unsigned long elapsed = millis() - start;
      if (elapsed >= _timeoutMs) return false;
      int cmd = _readFrame(_timeoutMs - elapsed);
      if (cmd < 0) return false;
      if ((uint32_t)cmd == expectedCmd) return true;
      if (cmd == 0x08) {
        _handlePush();
        continue;
      }
      LYNK_LOG("Ignoring unexpected frame, cmd ");
      LYNK_LOGLN(cmd);
    }
  }

  void _handlePush() {
    // A dps push (command 8) uses the same envelope as command responses.
    bool ok = (_VERSION == TUYA_V34) ? _parseCommandResponseV34(true) : _parseCommandResponseV35(true);
    if (ok && _lastJson.length() && _pushCallback) _pushCallback(_lastJson);
  }

  void _calculateSessionKey() {
    uint8_t xorNonce[16];
    for (int i = 0; i < 16; i++) {
      xorNonce[i] = pgm_read_byte(LOCAL_NONCE_PADDED + i) ^ _deviceNonce[i];
    }
    LYNK_LOGLN("xor nonce:");
    LYNK_LOG_HEX(xorNonce, 16);

    if (_VERSION == TUYA_V34) {
      memcpy(_sessionKey, xorNonce, 16);
      aesEcbEncrypt(_localKey, _sessionKey, 16);
    } else if (_VERSION == TUYA_V35) {
      uint8_t iv[12];
      memcpy_P(iv, LOCAL_NONCE_PADDED, 12);
      uint8_t tag[16];
      aesGcmEncrypt(_localKey, xorNonce, 16, iv, 12, nullptr, 0, _sessionKey, tag, 16);
    }
    LYNK_LOGLN("Session Key:");
    LYNK_LOG_HEX(_sessionKey, 16);
  }

  /*====================================PREPARE REQUESTS====================================*/
  void _prepareCmd03Request() {
    if (_VERSION == TUYA_V34) {
      _prepareCmd03RequestV34();
    } else if (_VERSION == TUYA_V35) {
      _prepareCmd03RequestV35();
    }
  }

  void _prepareCmd03RequestV34() {
    uint8_t payload[32];
    memcpy_P(payload, LOCAL_NONCE_PADDED, 32);  //Payload = local nonce, PKCS7-padded (16 -> 32 bytes)
    aesEcbEncrypt(_localKey, payload, 32);      //encrypt with localKey
    LYNK_LOGLN("Encrypted payload: ");
    LYNK_LOG_HEX(payload, 32);

    uint8_t hmacInput[48];  // header 16 + payload 32
    memcpy_P(hmacInput, V34_CMD3_HEADER, 16);
    memcpy(hmacInput + 16, payload, 32);
    uint8_t hmac[32];
    hmacSha256(_localKey, 16, hmacInput, 48, hmac);

    //Assemble full message: header + encrypted payload + hmac + suffix
    memcpy_P(_cmd3_request, V34_CMD3_HEADER, 16);
    memcpy(_cmd3_request + 16, payload, 32);
    memcpy(_cmd3_request + 48, hmac, 32);
    memcpy_P(_cmd3_request + 80, V34_SUFFIX_MAGIC, 4);
  }

  void _prepareCmd03RequestV35() {
    uint8_t payload[16];
    memcpy_P(payload, LOCAL_NONCE_PADDED, 16);  //without pad
    uint8_t iv[12];
    memcpy(iv, payload, 12);
    uint8_t authD[14];
    memcpy_P(authD, V35_CMD3_HEADER, 14);
    uint8_t tag[16];
    memset(tag, 0, 16);
    uint8_t encBuf[16];
    memset(encBuf, 0, 16);
    aesGcmEncrypt(_localKey, payload, 16, iv, 12, authD, 14, encBuf, tag, 16);

    memcpy_P(_cmd3_request, V35_PREFIX_MAGIC, 4);
    memcpy_P(_cmd3_request + 4, V35_CMD3_HEADER, 14);
    memcpy(_cmd3_request + 18, iv, 12);
    memcpy(_cmd3_request + 30, encBuf, 16);
    memcpy(_cmd3_request + 46, tag, 16);
    memcpy_P(_cmd3_request + 62, V35_SUFFIX_MAGIC, 4);

    LYNK_LOG_HEX(_cmd3_request, 66);
  }
  /*====================================PARSE RESPONSES====================================*/
  bool _parseCommand3Response() {
    if (_VERSION == TUYA_V34) {
      return _parseCommand3ResponseV34();
    } else if (_VERSION == TUYA_V35) {
      return _parseCommand3ResponseV35();
    }
    return false;
  }

  bool _parseCommand3ResponseV34() {  //tuya device sent packet with command 04 as response on packet with command 03
    uint8_t payload[16];              //use only 16/64 that contain remote nonce
    if (_responseSize < 36)  //header + payload
      return false;
    memcpy(payload, _response_buffer + 20, 16);
    LYNK_LOGLN("Encrypted response payload");
    LYNK_LOG_HEX(payload, 16);
    //decrypt only first block, that contain remote nonce
    aesEcbDecrypt(_localKey, payload, 16);
    LYNK_LOGLN("Decrypted response payload");
    LYNK_LOG_HEX(payload, 16);

    memcpy(_deviceNonce, payload, 16);
    LYNK_LOGLN("Device Nonce:");
    LYNK_LOG_HEX(_deviceNonce, 16);
    return true;
  }

  bool _parseCommand3ResponseV35() {  //tuya device sent packet with command 04 as response on packet with command 03
    if (_responseSize < 98)           //header + iv 12 + payload 52 + tag +16
      return false;
    uint8_t iv[12];
    memcpy(iv, _response_buffer + 18, 12);
    uint8_t payload[52];
    memcpy(payload, _response_buffer + 30, 52);
    uint8_t tag[16];
    memcpy(tag, _response_buffer + 82, 16);
    uint8_t authD[14];
    memcpy(authD, _response_buffer + 4, 14);
    uint8_t decPayload[52];
    memset(decPayload, 0, 52);

    aesGcmDecrypt(_localKey, payload, 52, iv, 12,
                  authD, 14, tag, 16,
                  decPayload);
    LYNK_LOG("Decrypted Payload: ");
    LYNK_LOG_HEX(decPayload, 52);

    memcpy(_deviceNonce, decPayload + 4, 16);
    LYNK_LOGLN("Device Nonce:");
    LYNK_LOG_HEX(_deviceNonce, 16);
    return true;
  }

  bool _parseCommandResponse(bool allowEmptyPayload = false) {
    if (_VERSION == TUYA_V34) {
      return _parseCommandResponseV34(allowEmptyPayload);
    } else if (_VERSION == TUYA_V35) {
      return _parseCommandResponseV35(allowEmptyPayload);
    }
    return false;
  }

  // Copies the decrypted JSON into _lastJson, stripping the 15-byte
  // "3.x" version header that some payloads (dps pushes) are prefixed with.
  void _storeJson(const uint8_t* buf, size_t len) {
    size_t start = 0;
    if (len >= 15 && buf[0] == '3' && buf[1] == '.') start = 15;
    _lastJson = "";
    for (size_t i = start; i < len; i++) _lastJson += (char)buf[i];
  }

  static bool _dpsBoolFromJson(const String &json, const char* dpsId, bool &out) {
    String pattern(F("\""));
    pattern += dpsId;
    pattern += F("\":");
    int idx = json.indexOf(pattern);
    if (idx < 0) return false;
    unsigned int v = idx + pattern.length();
    if (json.substring(v, v + 4) == "true") {
      out = true;
      return true;
    }
    if (json.substring(v, v + 5) == "false") {
      out = false;
      return true;
    }
    LYNK_LOGLN("dpsBool not found");
    return false;
  }

  bool _parseCommandResponseV34(bool allowEmptyPayload = false) {
    _lastJson = "";
    if (_responseSize < 56) {  //header 16 + retcode 4 + hmac 32 + suffix 4
      LYNK_LOGLN("Response too short to parse");
      return false;
    }

    uint32_t retcode = readU32BE(_response_buffer + 16);
    LYNK_LOG("retcode = ");
    LYNK_LOGLN(retcode);
    (void)retcode;

    if (_responseSize == 56) {
      LYNK_LOGLN("No payload");
      return allowEmptyPayload;
    }

    size_t pLen = _responseSize - 56;
    // AES-ECB only operates on whole 16-byte blocks; a device (or corrupted
    // frame) that isn't block-aligned would otherwise decrypt a partial block
    // from uninitialised bytes past the payload.
    if (pLen % 16 != 0) {
      LYNK_LOGLN("Response payload not block-aligned");
      return false;
    }
    uint8_t payload[RESPONSE_BUFFER_SIZE - 56];
    memcpy(payload, _response_buffer + 20, pLen);
    aesEcbDecrypt(_sessionKey, payload, pLen);

    // Strip PKCS7 padding (last byte = padding length)
    uint8_t padLen = payload[pLen - 1];
    size_t jsonLen = (padLen <= pLen) ? pLen - padLen : pLen;

    _storeJson(payload, jsonLen);
    LYNK_LOG("Decrypted JSON: ");
    LYNK_LOGLN(_lastJson);
    return true;
  }

  bool _parseCommandResponseV35(bool allowEmptyPayload = false) {
    _lastJson = "";
    if (_responseSize < 18) {
      LYNK_LOGLN("Response with invalid header");
      return false;
    }
    uint32_t length = readU32BE(_response_buffer + 14);
    if (_responseSize < 18 + length || length < 28) {  //iv + retcode/payload + tag
      LYNK_LOGLN("Response with invalid payload");
      return false;
    }
    uint8_t iv[12];
    memcpy(iv, _response_buffer + 18, 12);
    size_t pLen = length - 12 - 16;
    uint8_t payload[RESPONSE_BUFFER_SIZE];
    memcpy(payload, _response_buffer + 30, pLen);
    uint8_t tag[16];
    memcpy(tag, _response_buffer + 30 + pLen, 16);

    uint8_t authD[14];
    memcpy(authD, _response_buffer + 4, 14);
    uint8_t decPayload[RESPONSE_BUFFER_SIZE];
    memset(decPayload, 0, sizeof(decPayload));

    aesGcmDecrypt(_sessionKey, payload, pLen, iv, 12,
                  authD, 14, tag, 16,
                  decPayload);

    LYNK_LOG("Decrypted Payload: ");
    LYNK_LOG_HEX(decPayload, pLen);

    if (pLen < 4) return allowEmptyPayload;
    uint32_t retcode = readU32BE(decPayload);
    LYNK_LOG("Return code: ");
    LYNK_LOGLN(retcode);
    (void)retcode;

    if (pLen == 4) {
      LYNK_LOGLN("No payload");
      return allowEmptyPayload;
    }

    _storeJson(decPayload + 4, pLen - 4);
    LYNK_LOG("Decrypted JSON: ");
    LYNK_LOGLN(_lastJson);
    return true;
  }

  /*====================================COMMANDS====================================*/

  void _sendCommand3() {
    if (_VERSION == TUYA_V34) {
      LYNK_LOGLN("Sending command 3 ( 84 ) bytes");
      LYNK_LOG_HEX(_cmd3_request, 84);
    } else {
      LYNK_LOGLN("Sending command 3 ( 66 ) bytes");
      LYNK_LOG_HEX(_cmd3_request, 66);
    }
    size_t written = _client->write(_cmd3_request, _VERSION == TUYA_V34 ? 84 : 66);
    LYNK_LOG("Bytes actually written: ");
    LYNK_LOGLN(written);
    (void)written;
  }

  void _sendCommand5() {
    if (_VERSION == TUYA_V34) {
      _sendCommand5V34();
    } else if (_VERSION == TUYA_V35) {
      _sendCommand5V35();
    }
  }

  void _sendCommand5V34() {
    uint8_t payload[48];
    hmacSha256(_localKey, 16, _deviceNonce, 16, payload);  //fill first 32byte
    pkcs7Pad(payload, 32);                                 //pad to 48bytes
    aesEcbEncrypt(_localKey, payload, 48);
    LYNK_LOGLN("Encrypted payload: ");
    LYNK_LOG_HEX(payload, 48);

    uint8_t hmacInput[64];  //16 + 48
    memcpy_P(hmacInput, V34_CMD5_HEADER, 16);
    memcpy(hmacInput + 16, payload, 48);
    uint8_t hmac[32];
    hmacSha256(_localKey, 16, hmacInput, 64, hmac);

    uint8_t _cmd5_request[100];
    memcpy_P(_cmd5_request, V34_CMD5_HEADER, 16);
    memcpy(_cmd5_request + 16, payload, 48);
    memcpy(_cmd5_request + 64, hmac, 32);
    memcpy_P(_cmd5_request + 96, V34_SUFFIX_MAGIC, 4);

    LYNK_LOGLN("Sending command 5 ( 100 ) bytes");
    LYNK_LOG_HEX(_cmd5_request, 100);
    size_t written = _client->write(_cmd5_request, 100);
    LYNK_LOG("Bytes actually written: ");
    LYNK_LOGLN(written);
    (void)written;
    // The plug does not reply to command 5 - the handshake is considered
    // complete once this is sent. The next message (a status query
    // or control command) should be encrypted/HMAC'd with the session key.
  }

  void _sendCommand5V35() {
    uint8_t payload[32];
    hmacSha256(_localKey, 16, _deviceNonce, 16, payload);
    uint8_t iv[12];
    memcpy_P(iv, LOCAL_NONCE_PADDED, 12);
    uint8_t authD[14];
    memcpy_P(authD, V35_CMD5_HEADER, 14);
    uint8_t tag[16];
    memset(tag, 0, 16);
    uint8_t encBuf[32];
    aesGcmEncrypt(_localKey, payload, 32, iv, 12, authD, 14, encBuf, tag, 16);
    LYNK_LOGLN("Encrypted CMD5 Payload GCM:");
    LYNK_LOG_HEX(encBuf, 32);
    uint8_t _cmd5_request[82];
    memcpy_P(_cmd5_request, V35_PREFIX_MAGIC, 4);
    memcpy_P(_cmd5_request + 4, V35_CMD5_HEADER, 14);
    memcpy(_cmd5_request + 18, iv, 12);
    memcpy(_cmd5_request + 30, encBuf, 32);
    memcpy(_cmd5_request + 62, tag, 16);
    memcpy_P(_cmd5_request + 78, V35_SUFFIX_MAGIC, 4);

    LYNK_LOGLN("Sending command 5 ( 82 ) bytes");
    LYNK_LOG_HEX(_cmd5_request, 82);
    size_t written = _client->write(_cmd5_request, 82);
    LYNK_LOG("Bytes actually written: ");
    LYNK_LOGLN(written);
    (void)written;
    // The plug does not reply to command 5 - the handshake is considered
    // complete once this is sent. The next message (a status query
    // or control command) should be encrypted/HMAC'd with the session key.
  }

  // ---------- Session-key frames (status / control / heartbeat) ----------

  bool _sendCommand0d(const String &json) {
    if (json.length() + 15 > PAYLOAD_BUFFER_SIZE - 16) {
      Serial.println(F("Payload buffer is not enough to store json, increase PAYLOAD_BUFFER_SIZE"));
      return false;
    }
    uint8_t plain[PAYLOAD_BUFFER_SIZE];
    memcpy_P(plain, _VERSION == TUYA_V34 ? V34_PAYLOAD_PREFIX_MAGIC : V35_PAYLOAD_PREFIX_MAGIC, 15);
    memcpy(plain + 15, json.c_str(), json.length());
    return _sendSessionFrame(0x0d, plain, 15 + json.length());
  }

  // Builds and sends one session-key encrypted frame for any command.
  bool _sendSessionFrame(uint32_t cmd, const uint8_t* plain, size_t plainLen) {
    if (_VERSION == TUYA_V34) {
      return _sendSessionFrameV34(cmd, plain, plainLen);
    }
    return _sendSessionFrameV35(cmd, plain, plainLen);
  }

  bool _sendSessionFrameV34(uint32_t cmd, const uint8_t* plain, size_t plainLen) {
    if (plainLen + 16 > PAYLOAD_BUFFER_SIZE) {
      Serial.println(F("Payload too large, increase PAYLOAD_BUFFER_SIZE"));
      return false;
    }
    uint8_t payload[PAYLOAD_BUFFER_SIZE];
    if (plainLen) memcpy(payload, plain, plainLen);
    size_t payloadLen = pkcs7Pad(payload, plainLen);
    aesEcbEncrypt(_sessionKey, payload, payloadLen);

    uint8_t frame[PAYLOAD_BUFFER_SIZE + 52];  //header(16) + payload + hmac(32) + suffix(4)
    memcpy_P(frame, V34_PREFIX_MAGIC, 4);
    writeU32BE(frame + 4, _seqNo++);
    writeU32BE(frame + 8, cmd);
    writeU32BE(frame + 12, payloadLen + 36);  // payload + hmac(32) + suffix(4)
    memcpy(frame + 16, payload, payloadLen);

    uint8_t hmac[32];
    hmacSha256(_sessionKey, 16, frame, 16 + payloadLen, hmac);
    memcpy(frame + 16 + payloadLen, hmac, 32);
    memcpy_P(frame + 48 + payloadLen, V34_SUFFIX_MAGIC, 4);

    size_t frameLen = payloadLen + 52;
    LYNK_LOG("Sending cmd ");
    LYNK_LOG(cmd);
    LYNK_LOG(" (");
    LYNK_LOG((uint32_t)frameLen);
    LYNK_LOGLN(" bytes):");
    LYNK_LOG_HEX(frame, frameLen);
    size_t written = _client->write(frame, frameLen);
    LYNK_LOG("Bytes actually written: ");
    LYNK_LOGLN(written);
    return written == frameLen;
  }

  bool _sendSessionFrameV35(uint32_t cmd, const uint8_t* plain, size_t plainLen) {
    if (plainLen > PAYLOAD_BUFFER_SIZE) {
      Serial.println(F("Payload too large, increase PAYLOAD_BUFFER_SIZE"));
      return false;
    }
    uint8_t header[14];
    memset(header, 0, 2);
    writeU32BE(header + 2, _seqNo++);
    writeU32BE(header + 6, cmd);
    writeU32BE(header + 10, plainLen + 28);  // iv(12) + payload + tag(16)

    uint8_t iv[12];
    memcpy_P(iv, LOCAL_NONCE_PADDED, 12);
    uint8_t tag[16];
    memset(tag, 0, 16);
    uint8_t encBuf[PAYLOAD_BUFFER_SIZE];
    aesGcmEncrypt(_sessionKey, plain, plainLen, iv, 12, header, 14, encBuf, tag, 16);
    
    LYNK_LOGLN("_sessionKey bytes");
    LYNK_LOG_HEX(_sessionKey, 16);

    LYNK_LOGLN("GCM encrypted bytes");
    LYNK_LOG_HEX(encBuf, PAYLOAD_BUFFER_SIZE);

    LYNK_LOGLN("tag bytes");
    LYNK_LOG_HEX(tag, 16);

    uint8_t frame[PAYLOAD_BUFFER_SIZE + 50];  //prefix(4) + header(14) + iv(12) + payload + tag(16) + suffix(4)
    memcpy_P(frame, V35_PREFIX_MAGIC, 4);
    memcpy(frame + 4, header, 14);
    memcpy(frame + 18, iv, 12);
    if (plainLen) memcpy(frame + 30, encBuf, plainLen);
    memcpy(frame + 30 + plainLen, tag, 16);
    memcpy_P(frame + 46 + plainLen, V35_SUFFIX_MAGIC, 4);

    size_t frameLen = plainLen + 50;
    LYNK_LOG("Sending cmd ");
    LYNK_LOG(cmd);
    LYNK_LOG(" (");
    LYNK_LOG((uint32_t)frameLen);
    LYNK_LOGLN(" bytes):");
    LYNK_LOG_HEX(frame, frameLen);
    size_t written = _client->write(frame, frameLen);
    LYNK_LOG("Bytes actually written: ");
    LYNK_LOGLN(written);
    return written == frameLen;
  }

  /* VARIABLES*/
  IPAddress _ipAddress;
  uint8_t _localKey[16];

  uint8_t _cmd3_request[84];  //84 v34; 66 v35
  uint8_t _response_buffer[RESPONSE_BUFFER_SIZE];
  size_t _responseSize = 0;
  uint8_t _deviceNonce[16];
  uint8_t _sessionKey[16];
  WiFiClient _ownClient;  // used when no external Client is injected
  Client* _client;
  uint32_t _seqNo = 3;  //1-cmd3,2-cmd5
  uint32_t _timeoutMs = 5000;
  String _lastJson;
  DpsCallback _pushCallback = nullptr;
  const uint8_t V35_CMD3_HEADER[14] PROGMEM = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x2c };
  const uint8_t V35_PREFIX_MAGIC[4] PROGMEM = { 0x00, 0x00, 0x66, 0x99 };
  const uint8_t V35_SUFFIX_MAGIC[4] PROGMEM = { 0x00, 0x00, 0x99, 0x66 };
  const uint8_t V35_CMD5_HEADER[14] PROGMEM = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x3c };
  const uint8_t V34_PREFIX_MAGIC[4] PROGMEM = { 0x00, 0x00, 0x55, 0xAA };
  const uint8_t V34_SUFFIX_MAGIC[4] PROGMEM = { 0x00, 0x00, 0xAA, 0x55 };
  const uint8_t V34_PAYLOAD_PREFIX_MAGIC[15] PROGMEM = { 0x33, 0x2e, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };  //3.4 00 00 00 ...
  const uint8_t V35_PAYLOAD_PREFIX_MAGIC[15] PROGMEM = { 0x33, 0x2e, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };  //3.5 00 00 00 ...
  const uint8_t LOCAL_NONCE_PADDED[32] PROGMEM = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                                   0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                                                   0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                                                   0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 };  //local nonce, PKCS7-padded (16 -> 32 bytes)
  const uint8_t V34_CMD3_HEADER[16] PROGMEM = { 0x00, 0x00, 0x55, 0xaa, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x44 };
  const uint8_t V34_CMD5_HEADER[16] PROGMEM = { 0x00, 0x00, 0x55, 0xaa, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x54 };
};

#endif  // LYNK_TUYA_H
