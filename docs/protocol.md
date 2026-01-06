# Bridgefall Paniq Protocol (Rust / KCP Implementation)

This document defines the UDP envelope used between the Paniq Rust client (`socks5d`) and proxy server (`proxy-server`), including packet types, fields, and transport integration. It is adapted from the reference Go implementation but specifically tuned for the Rust/KCP stack.

## 1. Overview

All client↔server traffic uses UDP datagrams. The envelope has two phases:

1. **Preamble**: A sequence of unframed junk and signature packets followed by a framed initiation packet.
2. **Transport**: Framed datagrams carrying the inner **KCP** segments.

Key configuration parameters (loaded from JSON profiles) influence the wire format:

- **Jc/Jmin/Jmax**: Junk datagram count and size range.
- **S1/S2/S3/S4**: Padding lengths for framed packets (`Initiation`, `Response`, `CookieReply`, `Transport`).
- **H1/H2/H3/H4**: Header ranges for framed packet types.
- **I1..I5**: Signature chain specifications.
- **encrypted_timestamp** / **require_encrypted_timestamp**: Handshake security.
- **transport_replay** / **transport_replay_limit**: Per-packet transport counter for replay detection.

## 2. Common Framed Datagram Format

Used by `MessageInitiation`, `MessageResponse`, `MessageCookieReply`, and `MessageTransport`.

```
| padding (S*) | header (4 bytes, LE) | payload (variable) |
```

**Fields**

| Field   | Size | Encoding | Description |
|---------|------|----------|-------------|
| padding | S*   | raw      | Cryptographically random bytes. Length depends on message type. |
| header  | 4    | uint32 LE | Random value within the configured header range for that message type. |
| payload | var  | bytes    | Message-specific fields (see below). |

At decode time, the receiver tries each message type by checking if the header value falls within the configured range. If zero or multiple types match, the datagram is rejected.

## 3. Preamble Phase (Unframed)

Preamble packets are **not framed**. The server expects them in strict order: junk → signatures → initiation.

### 3.1 Junk (Preamble-only)
Exactly `Jc` packets of cryptographically random bytes with length in `[Jmin, Jmax]`. These are not parsed or validated.

### 3.2 Signature (Preamble-only)
Up to 5 signature datagrams defined by `I1..I5`. These are used to mimic standard protocol handshakes. The server deobfuscates and validates these against the expected chain if `signature_validate` is enabled.

**Signature chain tags**

| Tag | Size (obfuscated) | Validation | Description |
|-----|------------------|------------|-------------|
| `<b HEX>` | len(HEX)/2 | exact match | Fixed bytes (hex string). |
| `<t>` | 4 | none (parses) | Unix time in seconds, big-endian uint32. |
| `<r N>` | N | none | Random bytes. |
| `<rc N>` | N | alpha only | Random A–Z/a–z bytes. |
| `<rd N>` | N | digits only | Random 0–9 bytes. |
| `<d>` | variable | copy | Raw data bytes (payload). |
| `<ds>` | variable | base64 | Raw payload bytes encoded in base64 (no padding). |
| `<dz N>` | N | none | Data length encoded in N bytes (big-endian). |

## 4. Framed Packet Types

### 4.1 MessageInitiation (H1/S1)
**Purpose**: Client initiates the encrypted handshake.

**Payload Layout**
```
| encrypted_timestamp (optional) | MAC1 (optional, 16 bytes) |
```
*   **Encrypted Timestamp**: Version 1, Client Ephemeral Public Key (32), Nonce (24), AEAD-encrypted TAI64N timestamp (12 bytes + 16-byte tag).
*   **MAC1**: Authenticates the entire framed datagram to reject unauthorized probes.

### 4.2 MessageResponse (H2/S2)
**Purpose**: Server acknowledgment and session assignment.

**Payload Layout**
```
| conv_id (4 bytes, BE) |
```
*   **conv_id**: A random 32-bit conversation ID assigned by the server for the KCP session.

### 4.3 MessageTransport (H4/S4)
**Purpose**: Carries the inner transport segment (KCP).

**Payload Layout**
```
| counter (8 bytes, optional) | inner_len (2 bytes, BE) | inner_payload (var) | padding (var) |
```

**Fields**
*   **counter**: Monotonic 64-bit counter for replay protection (required if `transport_replay=true`).
*   **inner_len**: The exact length of the KCP segment.
*   **inner_payload**: The raw KCP packet.
*   **padding**: Random bytes added to satisfy the `S4` padding policy and vary packet sizes.

## 5. Inner Transport Layers

### 5.1 KCP (Reliable UDP)
Paniq-rs uses **KCP** to provide reliability and stream-like behavior over the obfuscated UDP envelope. KCP handles:
*   Retransmissions and ACK/NACK logic.
*   Congestion control and flow control (Window sizing).
*   Segmenting and reassembling streams.

### 5.2 async-smux (Multiplexing)
Since KCP provides a single reliable stream, **smux** is used on top of it to multiplex multiple application connections (e.g., several SOCKS5 streams) over a single Paniq tunnel.

`Application TCP -> SOCKS5 -> smux Stream -> KCP -> Paniq Envelope -> UDP`

## 6. Size Constraints

For framed transport packets:
```
max_transport_payload = MaxPacketSize - (S4 + 4)
len(counter + inner_len + inner_payload + padding) <= max_transport_payload
```
The `MaxPacketSize` is defined in the profile (default 1350). The resulting `KCP MTU` is automatically derived based on the selected overhead (counter, padding, and envelope).

## 7. Migration Notes (from Go/QUIC)
*   **conv_id in Response**: Unlike Go/QUIC, the Rust/KCP implementation uses the `MessageResponse` payload to transmit the KCP `conv_id`.
*   **No External TLS**: Transport security is handled entirely by the obfuscation layer (Encrypted Timestamp) and smux/KCP isolation.
*   **Mandatory Initiation Response**: The client MUST wait for the `MessageResponse` to receive its `conv_id` before sending any `MessageTransport` packets.
