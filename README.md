# Modbus Detection Scanner

A multithreaded C scanner for detecting Modbus/TCP services using `libmodbus`.

The scanner does not rely only on TCP port `502` being open. Instead, it establishes a Modbus/TCP connection and sends an application layer Modbus request. A valid Modbus response is used as the primary indicator that a Modbus service is present.

---

## Modbus/TCP

Modbus is an industrial communication protocol commonly used by PLCs, RTUs, HMIs, SCADA systems, sensors, meters, and other industrial devices.

Modbus/TCP transports the Modbus application protocol over TCP.

The standard Modbus/TCP port is:

```text
TCP/502
```

A typical communication flow is:

```text
Scanner
   |
   | TCP connection → 502
   |
   | Modbus/TCP request
   v
Modbus Device
   |
   | Modbus/TCP response
   v
Scanner
```

Unlike protocols that provide a banner immediately after connecting, Modbus/TCP generally requires the client to send a valid Modbus request before the device produces an application layer response.

---

# Detection Method

The scanner performs detection in two stages.

### 1. TCP connection

The scanner attempts to establish a TCP connection to:

```text
<target>:502
```

If the connection cannot be established, the target is treated as not responding to Modbus/TCP.

However, an open TCP/502 port by itself is **not considered sufficient evidence** of Modbus.

### 2. Modbus application-layer probe

After connecting, the scanner sends a Modbus request using `libmodbus`.

The primary probe is:

```c
modbus_read_input_registers(ctx, 0, 1, &reg);
```

This generates a Modbus Function Code:

```text
0x04 - Read Input Registers
```

The request asks the target for one input register starting at address `0`.

If the target returns a valid Modbus response, the scanner considers the service detected.

---

# Modbus/TCP Packet Structure

A Modbus/TCP packet consists of:

```text
+----------------------+----------------------+
| MBAP Header          | PDU                  |
+----------------------+----------------------+

MBAP Header:
+------------------+
| Transaction ID   | 2 bytes
| Protocol ID      | 2 bytes
| Length           | 2 bytes
| Unit Identifier  | 1 byte
+------------------+

PDU:
+------------------+
| Function Code    | 1 byte
| Data             | N bytes
+------------------+
```

The MBAP header is specific to Modbus/TCP.

---

# Primary Detection Packet

The scanner's first probe uses Function Code `0x04`.

A representative request is:

```text
00 01 00 00 00 06 01 04 00 00 00 01
```

Breaking this down:

```text
00 01        Transaction Identifier
00 00        Protocol Identifier
00 06        Length
01           Unit Identifier
04           Function Code
00 00        Starting Address
00 01        Quantity
```

### Transaction Identifier

```text
00 01
```

Identifies the transaction.

The value can vary because the transaction identifier is normally managed by the Modbus client library.

### Protocol Identifier

```text
00 00
```

A value of `0` identifies Modbus.

### Length

```text
00 06
```

Specifies the number of bytes following the length field.

### Unit Identifier

```text
01
```

Identifies the target Modbus unit.

### Function Code

```text
04
```

Function Code `0x04` means:

```text
Read Input Registers
```

### Starting Address

```text
00 00
```

The scanner starts at register address `0`.

### Quantity

```text
00 01
```

The scanner requests one register.

---

# Expected Response

A successful response to the request contains Function Code `0x04` and the requested register data.

A representative response could look like:

```text
00 01 00 00 00 05 01 04 02 00 00
```

Breaking it down:

```text
00 01        Transaction Identifier
00 00        Protocol Identifier
00 05        Length
01           Unit Identifier
04           Function Code
02           Byte Count
00 00        Register Value
```

The important part for detection is that the target successfully processes the Modbus request and returns a valid Modbus application-layer response.

The actual register value is device-dependent.

---

# Why Port 502 Alone Is Not Enough

Simply checking:

```text
TCP/502 = OPEN
```

does not necessarily prove that the service is Modbus.

Port numbers are conventions. A different application can listen on TCP/502, and a Modbus device may also behave differently depending on its configuration.

The scanner therefore uses:

```text
TCP connectivity
        +
Modbus protocol response
        =
Modbus detection
```

This makes application-layer detection more meaningful than a simple port scan.

---

# Fallback Detection

Some devices may not respond to the initial `0x04` request because of their register configuration or supported function codes.

The scanner therefore attempts a second request if the first one fails:

```c
modbus_read_bits(ctx, 0, 1, bits);
```

This uses Function Code:

```text
0x01 - Read Coils
```

A representative request is:

```text
00 02 00 00 00 06 01 01 00 00 00 01
```

Breakdown:

```text
00 02        Transaction Identifier
00 00        Protocol Identifier
00 06        Length
01           Unit Identifier
01           Function Code
00 00        Starting Address
00 01        Quantity
```

The scanner considers the target detected when either Modbus operation receives a successful response.

---

# Detection Flow

```text
             Target IP
                 |
                 v
          TCP connection
             port 502
                 |
          +------+------+
          |             |
        Failed       Connected
          |             |
          v             v
       Ignore      Function 0x04
                        |
                 +------+------+
                 |             |
               Valid         Failed
                 |             |
                 v             v
            MODBUS FOUND   Function 0x01
                               |
                        +------+------+
                        |             |
                      Valid         Failed
                        |             |
                        v             v
                   MODBUS FOUND    No detection
```

---

# Implementation

The scanner uses `libmodbus` to construct and parse Modbus/TCP packets rather than manually constructing protocol frames.

The primary operation is:

```c
modbus_read_input_registers(ctx, 0, 1, &reg);
```

If this fails:

```c
modbus_read_bits(ctx, 0, 1, bits);
```

The connection is then closed and the `libmodbus` context is freed.

This keeps the protocol handling inside the Modbus library while the scanner handles:

* Target enumeration
* Threading
* Connection management
* Detection
* Progress tracking
* Result logging

---

# Timeouts

The scanner uses short connection and response timeouts:

```c
#define TIMEOUT_SEC 2
```

This prevents a single unreachable or unresponsive host from blocking a worker for an excessive amount of time.

Industrial networks can contain devices with relatively slow responses, so timeout values may need to be adjusted depending on the environment.

---

# Multithreading

Targets are divided between multiple worker threads.

For example:

```text
Thread 1 → targets 1–64
Thread 2 → targets 65–128
Thread 3 → targets 129–192
Thread 4 → targets 193–254
```

Each worker independently attempts Modbus/TCP detection.

This allows multiple hosts to be tested concurrently rather than waiting for each target sequentially.

---

# Important Detection Considerations

A positive result means that the target successfully responded to a Modbus request understood by the scanner.

It does **not** necessarily identify:

* Device manufacturer
* Device model
* Firmware version
* PLC program
* Register contents
* Whether the device is vulnerable

Those are separate fingerprinting or assessment tasks.

The scanner is primarily a **Modbus/TCP service detection tool**.

---

# Limitations

The detection method is intentionally conservative.

A device may be Modbus-capable but fail detection if:

* TCP/502 is filtered
* A firewall blocks the request
* The device requires a different Unit ID
* The requested function code is unsupported
* The device does not expose the requested address
* The device is temporarily unavailable
* Network latency exceeds the configured timeout

Therefore:

```text
No response ≠ Definitively not Modbus
```

It means the scanner could not obtain a successful response using the probes it attempted.

---

# Build

Install the required dependencies and compile with:

```bash
make
```

Or directly:

```bash
gcc -Wall -Wextra -O2 -o modbus modbus.c -lmodbus -lpthread
```

Run:

```bash
./modbus -i 192.168.1.0 -s /24 -t 10 -o results.txt
```

Example:

```text
[+] Modbus detected: 192.168.1.20:502
[+] Modbus detected: 192.168.1.42:502

[+] Scanned: 254 | Found: 2 Modbus
[+] Results saved to: results.txt
```

---

# Summary

The scanner detects Modbus/TCP services by performing actual protocol interaction rather than relying exclusively on TCP port detection.

The detection process is:

```text
Connect to TCP/502
        ↓
Send Modbus Function Code 0x04
        ↓
Receive valid Modbus response?
        ↓
      YES → Modbus detected
        |
       NO
        ↓
Send Modbus Function Code 0x01
        ↓
Receive valid Modbus response?
        ↓
      YES → Modbus detected
        |
       NO
        ↓
   No detection
```

The key principle is simple:

> **Detect the protocol, not just the port.**
