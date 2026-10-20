# DTC (Dragon Tiger Club) Game App - Network Encryption Analysis & Decrypter Setup

This document provides a comprehensive analysis of the network encryption and obfuscation layers used in the DTC (Dragon Tiger Club) game app and explains how to configure and use KhanDroid's payload decryptors to inspect decrypted payloads.

---

## 1. Deep-Dive Layer Analysis

### Layer 1: Transport & Network Layer (HTTPS / TLS 1.3)
- **Protocol**: TLS 1.3 over Port 443.
- **Usage**: Authentication, API logins, asset and configuration downloads.
- **Handling in KhanDroid**: Enabled via **HTTPS MITM (TlsMitmHandler + CaManager)**. Requires installing the KhanDroid CA certificate on the device.

### Layer 2: Game-Level Binary Protocol (Foxuc Gaming Protocol)
- **Structure**: Custom TCP protocol over Ports 9999, 6001, 6002.
- **Header**: 8-byte header containing `wMainCmd` (Main Command) and `wSubCmd` (Sub Command).
- **Payload Encryption**: Layers of custom obfuscation applied on top of raw packet streams.

### Layer 3: Custom 256-byte Substitution Table Stream Cipher
- **Implementation**: Native C++ shared library `libqpry_lua.so` via `CCipher::maprecvbyte`.
- **Mechanism**: Every incoming byte (0 to 255) is mapped through a fixed 256-byte substitution table (S-box).
- **KhanDroid Decrypter**: `SubstitutionCipher` (configured via 512 hex chars representing the 256 bytes).

### Layer 4: XXTEA Encryption Algorithm
- **Usage**: Used for decrypting game configuration files and sensitive data payloads.
- **Key**: `MBCLIENT_!2016` (14 bytes, padded to 16 bytes for 128-bit block requirements).
- **KhanDroid Decrypter**: `XxteaCipher` (requires 32 hex chars / 16 bytes key).

### Layer 5: XOR Stream Cipher
- **Usage**: Lightweight obfuscation on packet bodies.
- **Key**: `0x70` (ASCII `'p'`).
- **KhanDroid Decrypter**: `XorCipher` (repeating-key XOR).

---

## 2. Decrypter Setup & Configuration Guide in KhanDroid

To decrypt DTC game traffic in KhanDroid, follow these steps in the **Settings Screen**:

### Step 1: Enable HTTP Inspection & HTTPS MITM
1. Turn on **HTTP / HTTPS inspection**.
2. Turn on **Decrypt HTTPS (MITM)**.
3. Export and install the KhanDroid CA certificate on your test device (`Settings > Security > Encryption & credentials > Install a certificate`).

### Step 2: Configure the Appropriate Cipher in Settings

Depending on which layer you are inspecting:

#### Option A: XXTEA Decryption (for Configs & Encrypted Payloads)
- **Cipher Selection**: `XXTEA`
- **Key (hex)**: Convert `MBCLIENT_!2016` to hex (padded to 16 bytes / 32 hex chars):
  - ASCII: `M B C L I E N T _ ! 2 0 1 6 \0 \0`
  - Hex: `4d42434c49454e545f21323031360000`
- **Input this hex key** in the Settings screen XXTEA key field.

#### Option B: XOR Decryption
- **Cipher Selection**: `XOR`
- **Key (hex)**: `70` (or ASCII `p`)

#### Option C: Substitution Table Decryption (`libqpry_lua.so`)
- **Cipher Selection**: `Substitution-256`
- **S-box Table (hex)**: Extract the 256-byte substitution table `recv_table` from `libqpry_lua.so` (dumped via memory inspection or Ghidra/IDA Pro) and input its 512 hex characters.

---

## 3. Verification & Testing
1. Start the VPN capture in KhanDroid, selecting the DTC game app as the target.
2. Open the DTC game and perform actions (login, room entry, betting).
3. Check the **Sessions screen** in KhanDroid to view parsed HTTP/WebSocket/TCP exchanges alongside decrypted payload previews.
