# Protocol and wire format

rustnies uses a custom protocol over UDP. Every datagram on the wire is the
output of the `Transport` layer's `wrap` applied to a *plaintext frame*. In
phase 1 the default `Transport` is the identity `PlainTransport`, so the wire
bytes equal the plaintext frame. See [transport.md](transport.md) for how the
wrap/unwrap step is factored out.

## Plaintext frame

```
[ cleartext header (24 bytes) ][ encrypted payload (ciphertext + 16-byte tag) ]
```

The header is **authenticated** (passed as AEAD associated data) but **not
encrypted**. This lets a receiver route, replay-filter, and sequence packets
before decrypting, without leaking anything sensitive: the header carries only
bookkeeping (session id, sequence, acks, FEC indices), never content. Any
tampering with a header bit breaks the Poly1305 tag, so integrity is
end-to-end.

Encryption is ChaCha20-Poly1305; see [crypto.md](crypto.md).

## Packet header (24 bytes)

All multi-byte fields are little-endian, packed. Serialisation is hand-rolled
(`PacketHeader::write_to` / `read_from`) so the wire format is byte-stable and
has no serde on the hot path.

| Offset | Size | Field        | Meaning                                                       |
|--------|------|--------------|---------------------------------------------------------------|
| 0      | 1    | `version`    | Protocol version. Currently `0x01`.                           |
| 1      | 1    | `packet_type`| Packet type discriminator (see below).                       |
| 2      | 4    | `session_id` | 32-bit opaque session id (derived from the handshake hash).  |
| 6      | 4    | `seq`        | Monotonic sequence number for this direction. `0` is reserved.|
| 10     | 4    | `ack_seq`    | Ack anchor: highest received seq from the peer (acked itself). |
| 14     | 4    | `ack_bitmap` | Bitmap of the 32 seqs below `ack_seq` (bit i = `ack_seq-1-i`).|
| 18     | 2    | `fec_group`  | FEC group id this packet belongs to.                          |
| 20     | 1    | `fec_index`  | Index within the group (`0..k+m`).                            |
| 21     | 1    | `fec_k`      | Number of source symbols in the group.                        |
| 22     | 1    | `fec_m`      | Number of parity symbols in the group.                        |
| 23     | 1    | `flags`      | Reserved flag bits (see `HeaderFlags`).                       |

Constants live in `src/protocol/header.rs`:

- `PROTOCOL_VERSION = 0x01`
- `HEADER_LEN = 24`
- `AEAD_TAG_LEN = 16` (ChaCha20-Poly1305 tag per datagram)
- `OUTER_OVERHEAD = 28` (UDP 8 + IPv4 20 on the wire; IPv6 outers cost 48)
- `PATH_MTU = 1500` (assumed path MTU for the outer UDP datagrams)
- `MAX_PAYLOAD = 1400 - HEADER_LEN - AEAD_TAG_LEN` (1360: largest TUN payload
  per Data datagram)

Wire budget for a full-size payload with the default 1400-byte TUN MTU:

```text
1360 (payload) + 24 (header) + 16 (AEAD tag) + 8 (UDP) + 20 (IPv4) = 1428
```

That stays under the 1500-byte path MTU with ~70 bytes of margin for PPPoE,
carrier encapsulation, an IPv6 outer (+20), or a small transport tag. The
daemon additionally clamps the TUN device MTU to `MAX_PAYLOAD` so the kernel
hands us only wire-safe inner packets, and the tunnel drops anything larger
(counted in `tx_dropped_mtu`) as a safety net for FD-backed devices. The
padding obfuscation layer's default top bucket is 1400 for the same reason:
a 1500-byte bucket would force a 1528-byte outer datagram on every
full-size frame.

### Header flags

`HeaderFlags` is a `bitflags` type over a single byte:

| Bit | Flag         | Meaning                                                  |
|-----|--------------|----------------------------------------------------------|
| 0   | `RETRANSMIT` | Set on retransmitted reliable control packets (dedupe). |
| 1-7 | reserved     | Unused.                                                  |

## Packet types

`PacketType` is a `#[repr(u8)]` enum. Unknown byte values cause a header parse
error and the packet is dropped.

| Value | Type         | Direction        | Reliable? | Carries payload?        |
|-------|--------------|------------------|-----------|-------------------------|
| 1     | `Handshake1` | client -> server | yes       | no (handshake bytes)    |
| 2     | `Handshake2` | server -> client | yes       | key confirmation blob   |
| 3     | `Data`       | both             | no        | one TUN packet          |
| 4     | `Ack`        | both             | no        | no                      |
| 5     | `Fec`        | both             | no        | one parity symbol       |
| 6     | `Ping`       | both             | no        | 12-byte RTT probe       |
| 7     | `Pong`       | both             | no        | 12-byte echoed probe    |
| 8     | `Close`      | both             | yes       | no                      |
| 9     | `Keepalive`  | both             | no        | 8-byte timestamp        |

`Keepalive` is sent during idle periods (every ~20s) to keep NAT mappings alive
and prove the peer is responsive. If no traffic is seen from a peer within ~75s,
the session is torn down and its state freed. This also resolves stale-session
issues after ungraceful disconnects: the old session times out and the server
reaps it.

## Session identity and server dispatch

The 32-bit `session_id` is derived from the Noise handshake hash
(`session_id_from_hash`), which includes a fresh ephemeral per handshake, so
every session — including two concurrent sessions from the same device — gets
a distinct id. It is carried **in cleartext** (and AEAD-authenticated as AAD)
in every steady-state header precisely so the multi-client server can route by
it: the dispatcher's session table is keyed by `SessionId`, and the client's
`SocketAddr` is only "where to send the next datagram", updatable when the
client roams. A fresh handshake message 1 therefore always creates a new,
independent session; it never implicitly replaces a live session at the same
address or with the same static key. Stale sessions are reclaimed by the 75s idle
`SESSION_TIMEOUT` and the channel-closed sweep.

To bound resource use against a misbehaving or malicious client, the server
enforces an optional per-static-key session cap (`max_sessions_per_peer`,
default 0 = unlimited). When a new handshake would exceed the cap for a peer key,
the **oldest-idle** session for that key is evicted (logged) — the new handshake
is not refused, so a legit reconnect to a fresh NAT port still succeeds. The
oldest-idle policy favours keeping recently-active sessions and is the least
disruptive when the cap bites.

The handshake-probe path (the only per-datagram asymmetric-crypto step) is
rate-limited: a per-source token bucket (burst 4, refill 1 per 200 ms) plus a
global cap of 64 tracked sources bounds the DoS surface from an attacker
flooding garbage UDP. Idle sources drop out of the tracker after 5 s.

`PacketType::is_reliable` returns `true` for `Handshake1`, `Handshake2`, and
`Close`. These are the only packet types that go through the reliable-delivery
channel (sequenced, replay-filtered, retransmitted until acked). All data
traffic is best-effort and recovered, if at all, by FEC.

## Sequencing

Each direction maintains its own monotonic `seq` counter starting at 1 (`0` is
reserved and never accepted). The sender allocates a new `seq` per outgoing
packet via `Session::alloc_seq`. The nonce for AEAD is derived from
`session_id`, `seq`, and the direction, so each (key, nonce) pair is unique per
direction without maintaining send-side cipher state. See [crypto.md](crypto.md).

## Acknowledgements

Acks are **piggybacked** onto every outgoing packet via the `ack_seq` /
`ack_bitmap` fields, so there is normally no standalone `Ack` traffic. The
`Ack` packet type exists for explicit acks when there is nothing else to send.

`AckTracker` (in `src/protocol/session.rs`) maintains a *sliding* window, not
a cumulative-ack watermark:

- `anchor`: the highest received seq (0 = nothing received yet).
- `bitmap`: bit `i` is set iff seq `anchor - 1 - i` has been received.

Every authenticated packet (data, parity and control) is recorded, because the
advertisement paces the *whole* flow: the congestion controller releases
in-flight slots for newly acked seqs. A sliding window is required rather than
a contiguous watermark because data is best-effort and holes are permanent, so
a watermark would stall forever at the first lost data packet. `record(seq)`
slides the window forward (tolerating u32 wrap) or sets a bit below the
anchor. `snapshot()` produces the `(ack_seq, ack_bitmap)` pair to advertise:
`ack_seq` is the anchor (acked by definition), and bit `i` of `ack_bitmap`
covers `ack_seq - 1 - i` (the 32 seqs immediately below the anchor).

The sender tracks outstanding reliable packets and, on observing the peer's
`ack_seq`/`ack_bitmap`, discards any whose seq the peer has now acknowledged
(`Session::peer_acked`). Unacked packets past the retransmission timeout are
retransmitted.

## Replay protection

`ReplayWindow` is a sliding-window filter (IPsec-AH style): a `highest` seen
seq watermark plus a 64-bit bitmap of the `WINDOW = 64` most recent seqs below
`highest`.

- `seq > highest`: shift the bitmap by `seq - highest`, set bit 0, update
  `highest`. Accept.
- `seq <= highest`, within the window: check bit `highest - seq`. If set, the
  packet is a replay/duplicate -> reject. Otherwise set the bit and accept.
- `seq` below the window: reject.
- `seq == 0`: always reject (reserved).

Reliable packets (`Handshake*`, `Close`) always pass through the replay window
via `Session::receive_reliable`, which both checks/records and feeds the ack
tracker. Best-effort data packets do **not** go through the replay window
(their seq may legitimately be reused after a session restart, and FEC/dedup
is handled by the FEC group logic and the AEAD tag).

## Codec

`src/protocol/codec.rs` provides the structural split between header and body:

- `encode_raw(header, ciphertext)` -> `BytesMut` containing `header || body`.
- `decode(buf)` -> `Packet { header, body }` where `body` is the still-encrypted
  ciphertext. Decryption is intentionally left to `crypto::aead`; the codec is
  purely structural and cipher-independent.
- `split(buf)` -> `(PacketHeader, Bytes)` for hot-path decoders that want a
  header borrow and an owned body without copying the header.

A `Packet` value bundles a `PacketHeader` and a `bytes::Bytes` ciphertext body.
`Packet::empty` builds a header-only control frame.

## Session

`Session` (in `src/protocol/session.rs`) holds per-connection state that is
independent of the cipher:

- `id: SessionId`
- `role: SessionRole` (`Initiator` or `Responder`)
- `next_seq: u32` (outgoing sequence counter)
- `replay: ReplayWindow`
- `ack: AckTracker`
- `peer_ack` / `peer_bitmap` (the peer's most recent ack advertisement)

Key methods:

- `alloc_seq()` -> next outgoing seq.
- `observe_acks(ack_seq, ack_bitmap)` -> record the peer's advertisement.
- `peer_acked(seq)` -> has the peer acknowledged our outgoing `seq`?
- `receive_reliable(seq)` -> replay-check + record; returns `true` if fresh.
- `ack_snapshot()` -> `(ack_seq, ack_bitmap)` to put in an outgoing header.

The cipher state (the two application keys) is held by the `Tunnel`, not by the
`Session`, so session bookkeeping is pure and unit-testable without crypto.
