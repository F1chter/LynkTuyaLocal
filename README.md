# LynkTuyaLocal

Arduino library to control Tuya devices from ESP32 over the local network, without the Tuya cloud.

Supported v3.4 and v3.5 devices.

By default the library is silent. Define `LYNKTUYA_DEBUG` as `1` before including
`LynkTuya.h` (e.g. `#define LYNKTUYA_DEBUG 1`) to enable verbose Serial logging of
the handshake and packet contents — useful for debugging, but it also prints the
derived session key, so keep it disabled in production.

## Installation

### Arduino IDE (ZIP)
1. Download this repository as a ZIP (Code → Download ZIP)
2. In the Arduino IDE: **Sketch → Include Library → Add .ZIP Library...**

### Manual
Clone this repository into your Arduino libraries folder:

```
cd ~/Documents/Arduino/libraries
git clone https://github.com/F1chter/lynk-tuya-esp-local.git LynkTuya
```

## Setup

1. Use [TinyTuya](https://github.com/jasonacox/tinytuya/) to find the device IP, Local Key and protocol version.

2. Open one of the bundled examples (**File → Examples → LynkTuya**):
   * `GetStatus` — reads the current device status and relay state
   * `PlugControl` — switches a plug on and off, sets other data points
   * `StatusPush` — keeps a connection open and reacts instantly to device-side changes (physical button presses)
   * `LynkTuyaDemo` — all actions described above
3. Fill in your WiFi credentials, device IP and Local Key:

```cpp
#define WIFI_SSID "MY_WIFI"
#define WIFI_PASS "MY_PASSWORD"

IPAddress plugIP(192, 168, 1, 11);   // device ip, recommended to make it predefined on router
#define PLUG_KEY "1234567890abcdef"  // local key from TinyTuya
```

## `LynkTuya.h`

`LynkTuyaDevice` is a template class for controlling Tuya LAN devices that use the **3.4** or **3.5** protocol directly over TCP without relying on the Tuya cloud.

The class implements the complete LAN communication flow:

* TCP connection management
* Tuya authentication handshake
* Session key generation
* AES encryption/decryption
* HMAC-SHA256 authentication (v3.4)
* AES-GCM authenticated encryption (v3.5)
* Device status requests
* Power on/off commands

## Template Parameter

```cpp
template<TuyaProtocolVersion VERSION>
class LynkTuyaDevice;
```

Supported protocol versions:

```cpp
enum TuyaProtocolVersion {
    TUYA_V34,
    TUYA_V35
};
```

Example:

```cpp
LynkTuyaDevice<TUYA_V34> plug1(ip1, localKey1);
LynkTuyaDevice<TUYA_V35> plug2(ip2, localKey2);

// Optional: use a custom Client (Ethernet, a mock in tests, ...)
EthernetClient eth;
LynkTuyaDevice<TUYA_V35> plug3(ip3, localKey3, eth);
```

| Parameter   | Description                                            |
| ----------- | ------------------------------------------------------ |
| `ipAddress` | IP address of the Tuya device.                         |
| `localKey`  | 16-byte Local Key obtained from tinyTuya.              |
| `client`    | Optional: externally managed `Client` used instead of the built-in `WiFiClient`. |

The constructor prepares the protocol-specific handshake packet, so it only needs to be generated once.

---

## Public API

```cpp
bool connectToPlug();
```

Opens a TCP connection to the device.

Returns `true` on success.

```cpp
bool closeConnection();
```

Closes the TCP connection.

```cpp
bool handshake();
```

Performs the Tuya authentication handshake.

This method:

1. Sends Command 3
2. Receives the device nonce
3. Sends Command 5
4. Generates the session key

Must be completed before encrypted commands can be sent.

Returns `true` on success.

```cpp
bool getStatus(bool autoCloseConnection = true);
bool getStatus(String &jsonOut, bool autoCloseConnection = true);
```

Requests the current device status. The second form also copies the device's
decrypted status JSON (e.g. `{"dps":{"1":true,"9":0}}`) into `jsonOut`.

If no TCP connection exists, the class automatically:

1. Connects
2. Performs the handshake
3. Sends the status request

Returns `true` if a valid response is received.

```cpp
bool getRelayState(bool &isOn,
                   const char* dpsId = "1",
                   bool autoCloseConnection = true);
```

Reads the device status and extracts the boolean state of one dps id.
Returns `false` if the request failed or that dps id is not a boolean.

```cpp
const String& lastJson();
```

The decrypted JSON payload of the last successful response or push.

```cpp
bool turnOn(uint32_t timestamp, bool autoCloseConnection = true, const char* dpsId = "1");
bool turnOn(bool autoCloseConnection = true, const char* dpsId = "1");
```

Turns the device ON. The timestamp is the current Unix time in seconds; the
overload without it reads the system clock, which must be synced first
(`configTime()` or LynkTime's `timeBegin()`).

```cpp
bool turnOff(uint32_t timestamp, bool autoCloseConnection = true, const char* dpsId = "1");
bool turnOff(bool autoCloseConnection = true, const char* dpsId = "1");
```

Turns the device OFF.

```cpp
bool turn(uint32_t timestamp, bool on, bool autoCloseConnection = true, const char* dpsId = "1");
bool turn(bool on, bool autoCloseConnection = true, const char* dpsId = "1");
```

Generic method for changing the relay state.

Parameters:

| Parameter             | Description                                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `timestamp`           | Current Unix timestamp (seconds).                                                              |
| `on`                  | `true` to switch ON, `false` to switch OFF.                                                    |
| `autoCloseConnection` | Automatically closes the TCP connection after the command completes.                           |
| `dpsId`               | Tuya data point (DP) id to set. Defaults to `"1"` (the first relay); pass another id for multi-gang devices. |

```cpp
bool setDps(const char* dpsId, bool value,        bool autoCloseConnection = true, uint32_t timestamp = 0);
bool setDps(const char* dpsId, int value,         bool autoCloseConnection = true, uint32_t timestamp = 0);
bool setDps(const char* dpsId, const char* value, bool autoCloseConnection = true, uint32_t timestamp = 0);
```

Sets an arbitrary data point — boolean, integer or string — e.g. brightness
of a dimmer or the mode of a thermostat. `timestamp = 0` means "use the
system clock".

```cpp
bool heartbeat(bool autoCloseConnection = false);
```

Keeps a long-lived connection alive (Tuya command 9). Call every ~10 seconds
when holding a connection open, otherwise the device drops it.

```cpp
bool poll(uint32_t waitMs = 0);
```

Processes one pending frame on an open connection, dispatching dps pushes to
the `onDpsUpdate` callback. With `waitMs = 0` it returns immediately when no
data is pending. Call it from `loop()` — see the `StatusPush` example.

```cpp
void onDpsUpdate(void (*callback)(const String &json));
```

Registers a callback invoked whenever the device pushes a dps update
(command 8) on an open connection — e.g. when its physical button is pressed.
Pushes are dispatched during `poll()` and while waiting for command responses.

```cpp
void setTimeout(uint32_t timeoutMs);
```

How long to wait for a device response (default 5000 ms).

---

## Connection Behaviour

By default every public command:

1. Opens a TCP connection (if necessary)
2. Performs the handshake
3. Executes the command
4. Closes the connection

To execute multiple commands without reconnecting:

```cpp
plug.connectToPlug();
plug.handshake();

plug.getStatus(false);
plug.turnOn(timestamp, false);
plug.turnOff(timestamp, false);

plug.closeConnection();
```

---

## Protocol Support

### Tuya v3.4

* AES-128 ECB encryption
* HMAC-SHA256 packet authentication
* PKCS#7 padding

### Tuya v3.5

* AES-128 GCM authenticated encryption
* No PKCS#7 padding
* Built-in authentication tag

The template selects the appropriate implementation at compile time.

---

## Example

```cpp
#include <LynkTuya.h>

IPAddress ip(192,168,1,100);

LynkTuyaDevice<TUYA_V35> plug(
    ip,
    "0123456789abcdef"
);

plug.turnOn();          // uses the synced system clock

bool on;
plug.getRelayState(on); // read the relay state back

plug.setDps("2", 500);  // set another data point, e.g. dimmer brightness
```

---

