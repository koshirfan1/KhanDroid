# KhanDroid

Per-app, per-port Android traffic capture, with mandatory UDP export,
TCP forwarding, HTTP/HTTPS inspection (HTTP Canary style), and optional
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
- **HTTPS MITM (opt-in, experimental)**: `CaManager` generates an
  on-device root CA (BouncyCastle) and per-host leaf certificates;
  `TlsMitmHandler` terminates TLS with the device (`SSLEngine`, server
  mode) and opens a real `SSLSocket` to the actual server, decrypting
  both sides and feeding plaintext through the same `HttpTap`. This is
  the most complex and least battle-tested part of the build:
  - Covers a normal TLS 1.2/1.3 handshake, no client-certificate auth,
    no renegotiation.
  - Apps using certificate pinning will reject the MITM cert — you'll
    see a TLS error for those, not decrypted traffic, by design (that's
    what pinning is for).
  - The device must have the KhanDroid CA installed (Settings screen
    has an export/share button) before HTTPS decryption will work at
    all — see "HTTPS decryption limits" below.
  - **Test against your own app or an app you're authorized to test
    before relying on this.**
- **Custom payload decryption (opt-in, generic ciphers only)**:
  `DecryptorRegistry` + `SubstitutionCipher` / `XorCipher` / `XxteaCipher`
  try to decode HTTP response bodies after HTTP/HTTPS parsing, for apps
  that layer their own lightweight obfuscation on top. Configured in the
  Settings screen (cipher choice + hex key / S-box table).
  **Not included, by design**: anything that reverse-engineers a named,
  specific third-party protocol (e.g. a particular game's proprietary
  wire format) without authorization — that pattern reads as cheat/hack
  tooling against someone else's service, not a generic crypto primitive,
  and isn't in this build.
- **Sessions screen**: lists captured HTTP exchanges from Room (method,
  host, path, status, timing, decryption status), tap through to full
  request/response headers and body previews. "Clear" wipes the table.
- **Settings screen**: toggle HTTP inspection, toggle HTTPS MITM, export
  the CA cert for installation, choose/configure a custom decryptor.
  **Not persisted across app restarts** — in-memory for the current run
  only (no DataStore/SharedPreferences wiring yet).
- Foreground service notification with a Stop action.

## HTTPS decryption limits (read this before relying on MITM)

- Android 7+ apps trust only system CAs by default. A user-installed CA
  (what KhanDroid generates) is trusted only by: apps that explicitly
  opt in via `network_security_config.xml` (your own debug builds), a
  shrinking set of apps that still trust user CAs, or on a rooted device
  where the CA is pushed into the system store.
- Certificate-pinning apps (banking, many social apps) will always
  reject the MITM cert, regardless of CA installation.
- The CA's private key is generated and stored only in the app's private
  storage; `exportCaCertPem()` exports the **public certificate only**,
  never the key. Still, treat the CA as sensitive — anyone who installs
  it could, in principle, be MITM'd by someone holding the matching key.

## Build

Open `KhanDroid/` in Android Studio (Koala+) and let Gradle sync — Room
(with `ksp`), BouncyCastle, and Compose are all wired into
`app/build.gradle.kts`. This environment had no Android SDK, so the
project has **not been compiled here**; review in Android Studio, which
will surface any version mismatches (Compose BOM / Kotlin / ksp plugin
versions may need a small bump depending on your installed Android
Studio / AGP version).

## Run

1. Install on a real device (VPN + raw sockets need real networking;
   some emulator images restrict this).
2. On your PC: `python3 tools/khandroid_receiver.py capture.pcap --port 5555`
3. In the app:
   - **Settings tab**: turn on HTTP inspection (default on). If you want
     HTTPS decrypted, turn on MITM and tap "Export & install KhanDroid CA
     certificate", then install it under Settings > Security > Encryption
     & credentials > Install a certificate (on the device, not the PC).
     Optionally configure a custom decryptor.
   - **Capture tab**: pick the target app, set ports, enter your PC's LAN
     IP + port 5555, **Start**, accept the VPN permission prompt.
4. Generate traffic in the target app.
5. **Sessions tab**: watch HTTP(S) exchanges appear live.
6. Open `capture.pcap` in Wireshark for the raw packet view (re-open to
   refresh, since it's being appended to live).

Make sure phone and PC are on the same network and the PC firewall
allows inbound UDP on the chosen port.

## Project layout

```
app/src/main/java/com/khandroid/app/
  KhanDroidApp.kt              Application class
  data/
    HttpExchangeEntity.kt      Room entity for one HTTP(S) exchange
    HttpExchangeDao.kt         Room DAO (insert, observeAll, clearAll)
    KhanDroidDatabase.kt       Room database
  net/
    CaptureConfig.kt           User-chosen settings (Parcelable)
    PacketFilter.kt            App/port match logic (export gate only)
    Ipv4Packet.kt              Raw IPv4 header parsing
    IpPacketBuilder.kt         Builds IPv4/UDP packets for TUN replies
    TcpPacket.kt                TCP header parsing + building (w/ checksum)
    TcpConnection.kt           Per-connection TCP state machine + HTTP/MITM hookup
    TcpForwarder.kt            TCP NAT table
    Forwarder.kt               Top-level dispatch: UDP NAT + TCP forwarding
    UdpExporter.kt             Streams matched packets to the PC receiver
    http/
      HttpStreamParser.kt      Incremental HTTP/1.1 parser (chunked, gzip)
      HttpTap.kt               Pairs request/response, records to Room
    tls/
      CaManager.kt             On-device root CA + per-host leaf certs
      TlsSni.kt                Pulls the SNI hostname out of a ClientHello
      TlsMitmHandler.kt        SSLEngine-based TLS MITM (experimental)
    crypto/
      PayloadDecryptor.kt      Plugin interface + registry
      SubstitutionCipher.kt    Custom 256-byte substitution table
      XorCipher.kt             Repeating-key XOR
      XxteaCipher.kt           XXTEA (user-supplied 128-bit key)
  service/
    KhanDroidService.kt        VpnService: capture loop, lifecycle, wiring
  ui/
    MainActivity.kt            Bottom nav: Capture / Sessions / Settings
    SessionsScreen.kt          Exchange list + detail view
    SettingsScreen.kt          MITM/decryption config, CA export
tools/
  khandroid_receiver.py        PC-side UDP -> .pcap receiver
```

## Known gaps / next steps

- Settings aren't persisted (DataStore/SharedPreferences not wired up).
- No retry/retransmission in the TCP layer — fine for normal conditions,
  not for lossy networks.
- WebSocket and HTTP/2 framing aren't parsed (HTTP/1.1 only).
- Brotli/deflate response bodies aren't decompressed (gzip is).
- No HAR/cURL export from the Sessions screen yet.
- No Room schema migrations set up (fine while `version = 1`; add a
  migration path before changing the entity shape later).

## DTC (Dragon Tiger Club) Game App Network Analysis

Under-the-hood network protocols and layers used in the DTC (Dragon Tiger Club) game app:

### 1. Transport & Network Layer Protocols
* **TCP (Transmission Control Protocol)**: Real-time gameplay actions, betting, room entry, and core communication over Port 9999 and gateway ports 6001 / 6002 via raw TCP streaming.
* **HTTPS / TLS 1.3 (Transport Layer Security)**: User login, authentication, API requests, and asset/config downloading over standard web port 443 with secure TLS encryption.
* **UDP (User Datagram Protocol)**: Packet capture and forwarding (e.g., mirroring traffic via PCAPDroid to Port 5123).

### 2. Application & Game-Level Protocols
* **Foxuc Gaming Protocol**: Custom binary TCP protocol with an 8-byte header structure (`wMainCmd` and `wSubCmd`).
* **Custom Substitution Stream Cipher**: Native C++ library (`libqpry_lua.so`) containing a 256-byte substitution table (`recv_table`) that obfuscates/decrypts game packets.
* **XXTEA Encryption**: Used for decrypting game config files and sensitive payloads with the key `MBCLIENT_!2016`.

### 3. Scripting & Serialization
* **Cocos2d-Lua (LuaJIT)**: Game UI and network packet serialization handled via Lua scripts (`.lua`).

### Network Data Encryption & Obfuscation Components / Methods
The components and methods that encrypt or obfuscate network data are:
1. **Custom 256-byte Substitution Table Stream Cipher** (implemented in `libqpry_lua.so` via `CCipher::maprecvbyte`)
2. **XXTEA Encryption Algorithm** (using key `MBCLIENT_!2016`)
3. **XOR Stream Cipher** (using key `0x70`)
4. **TLS 1.3 / HTTPS** (Transport layer encryption for API/web requests on Port 443)

> For detailed configuration and setup steps for these decrypters in KhanDroid, see [DTC Decryption Guide](dtc_decryption_guide.md).


