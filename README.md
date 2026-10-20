# KhanDroid

Per-app, per-port Android traffic capture, with mandatory UDP export,
TCP forwarding, HTTP/HTTPS inspection (HTTP Canary style), PCapDroid-style Active Connections stream inspection, and optional
generic payload decryption — following the full guide roadmap in one
build.

## What works

- **Capture**: `VpnService` + TUN, restricted to one target app via
  `addAllowedApplication` (Compose UI app picker).
- **Filter**: `PacketFilter` gates what's exported by port; forwarding
  always happens regardless, so the app's traffic keeps working.
- **UDP forwarding**: fully implemented (NAT table + reply pump).
- **UDP export**: mandatory and always on — every matching raw packet
  streams live to `tools/khandroid_receiver.py`, which writes a `.pcap`
  file for Wireshark.
- **TCP forwarding**: TCP is terminated at the TUN boundary and relayed
  through a real, protected socket per connection (`TcpForwarder` /
  `TcpConnection`). Best-effort userspace implementation: no
  retransmission timers, no out-of-order reassembly, no TCP options,
  32-bit sequence counters with no wraparound handling. Fine for normal
  HTTP(S) request/response traffic on a typical Wi-Fi/mobile link; not a
  spec-complete TCP/IP stack.
- **HTTP inspection**: `HttpStreamParser` + `HttpTap` parse plain HTTP/1.1
  (Content-Length and chunked bodies, gzip decompression) straight out of
  the TCP relay and record request/response pairs to a Room database.
  Assumes non-pipelined HTTP/1.1 (one in-flight request per connection),
  which covers virtually all real mobile app traffic.
- **PCapDroid-Style Connections & Raw Stream Inspector**: A dedicated **Connections** tab showing active TCP ports, connection metadata (bytes sent/received, timestamps), and tapping any connection opens a raw hex/text stream inspector view.
- **HTTPS MITM (opt-in, experimental)**: `CaManager` generates an
  on-device root CA (BouncyCastle) and per-host leaf certificates;
  `TlsMitmHandler` terminates TLS with the device (`SSLEngine`, server
  mode) and opens a real `SSLSocket` to the actual server, decrypting
  both sides and feeding plaintext through the same `HttpTap`.
- **Custom payload decryption (opt-in, generic ciphers & Foxuc Gaming Protocol)**:
  `DecryptorRegistry` + `SubstitutionCipher` / `XorCipher` / `XxteaCipher` / `FoxucDecryptor`
  try to decode payloads after parsing, for apps that layer their own lightweight obfuscation on top. Configured in the
  Settings screen (presets for XXTEA, XOR, Foxuc-XXTEA).
- **Sessions & Connections screens**: lists captured HTTP exchanges and active TCP streams from Room.
- Foreground service notification with a Stop action.

## Build & Run

Open `KhanDroid/` in Android Studio (Koala+) and let Gradle sync (`assembleDebug`).
Deploy to your physical Android device, select your target app, and start capturing!

## DTC (Dragon Tiger Club) Game App Network Analysis

Under-the-hood network protocols and layers used in the DTC (Dragon Tiger Club) game app:

### 1. Transport & Network Layer Protocols
* **TCP (Transmission Control Protocol)**: Real-time gameplay actions, betting, room entry, and core communication over Port 9999 and gateway ports 6001 / 6002 via raw TCP streaming.
* **HTTPS / TLS 1.3 (Transport Layer Security)**: User login, authentication, API requests, and asset/config downloading over standard web port 443 with secure TLS encryption.
* **UDP (User Datagram Protocol)**: Packet capture and forwarding.

### 2. Application & Game-Level Protocols
* **Foxuc Gaming Protocol**: Custom binary TCP protocol with an 8-byte header structure (`wPacketSize`, `wMainCmd`, `wSubCmd`).
* **Custom Substitution Stream Cipher**: Native C++ library (`libqpry_lua.so`) containing a 256-byte substitution table (`recv_table`) that obfuscates/decrypts game packets.
* **XXTEA Encryption**: Used for decrypting game config files and sensitive payloads with the key `MBCLIENT_!2016`.

> For detailed configuration and setup steps for these decrypters in KhanDroid, see [DTC Decryption Guide](dtc_decryption_guide.md).
