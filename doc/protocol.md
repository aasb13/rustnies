# Protocol and wire format

rustnies uses a custom protocol. Every message on the wire is the output of the
`Transport` layer's `wrap` applied to a *plaintext frame*. The default
`Transport` is the identity `PlainTransport`, so the wire bytes equal the
plaintext frame. See [transport.md](transport.md) for how the wrap/unwrap step
is factored out, and [carrier.md](carrier.md) for what the bytes travel over
(UDP or TCP).

## Plaintext frame

```
[ cleartext header (24 bytes) ][ encrypted payload (ciphertext + 16-byte tag) ]
```

The header length above is the default (`v1-fixed`). The *encoding* is
swappable — see "Header codecs" below — but the frame shape is always
`header || sealed payload`.

The header is **authenticated** (passed as AEAD associated data) but **not
encrypted**. This lets a receiver route, replay-filter, and sequence packets
before decrypting, without leaking anything sensitive: the header carries only
bookkeeping (session id, sequence, acks, FEC indices), never content. Any
tampering with a header bit breaks the Poly1305 tag, so integrity is
end-to-end.

Encryption is ChaCha20-Poly1305; see [crypto.md](crypto.md).

## Header codecs

The header's **encoding** is a negotiated part (`[frame] codec`). What is *not*
swappable is the packet taxonomy: `PacketType` stays a closed `#[repr(u8)]`
enum, and the receive path's `match` on it stays exhaustive, so adding a packet
type is a compile error until every site handles it.

| Name | Layout |
|---|---|
| `v1-fixed` | The packed 24-byte header below. The default, and byte-identical to a pre-seam build. |
| `v2-tlv` | A self-describing tag-length-value header. Omit zero-valued fields, skip unknown tags. |

`protocol::frame::FrameCodec` owns the encoding: `write_header` / `read_header`
for serialisation, `encode_header` for the AEAD associated data, `body_offset`
to find where the body starts, and `peek_session_id` for server routing.

Two invariants a codec must uphold, both pinned by tests:

- **Round-trip stability.** The receive path re-encodes the *decoded* header to
  rebuild the AEAD associated data, so `encode(read(x))` must equal `x` exactly.
  A codec that is not canonical would authenticate a different byte string than
  the sender sealed, and every packet would fail.
- **A distinct wire discriminator.** A datagram server must route a frame
  before it knows its session, and therefore before it knows its codec, so the
  routing peek (`peek_any_session_id`) tries each codec in turn. That is only
  unambiguous if no two codecs accept the same buffer.

### v2-tlv, in brief

```text
[0]      magic (0x52)
[1..3]   total header length, u16 big-endian (excluding this preamble)
then, repeated: [tag u8][len u8][value, len bytes]
```

Tags are written in ascending order, which is what makes the encoding canonical.
A field left at its zero default is omitted and decodes back to zero, so a sparse
frame is smaller than v1's fixed 24 bytes (a `Ping` is 21). The cost is two
bytes per field, so a *fully populated* header is larger (46 vs 24). The win is
extensibility — a new optional field costs a tag, not a re-layout — not size.

## Packet header: `v1-fixed` (24 bytes)

All multi-byte fields are little-endian, packed. Serialisation is hand-rolled
(`PacketHeader::write_to` / `read_from`, reached through
`V1FixedCodec`) so the wire format is byte-stable and has no serde on the hot
path.

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
  per Data message, using the `v1-fixed` header length)

Note that `MAX_PAYLOAD` is expressed against the compiled-in `v1-fixed` header
length. A codec with a larger header shrinks the usable payload, which is why
`FrameCodec::max_header_len` exists and why the routing-whitening keystream is
sized from the *negotiated* codec rather than from `HEADER_LEN`.

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

The ACK fields are applied only after the packet's AEAD tag verifies. The
sender retains exact-byte records for transmitted data/parity packets, retires
acknowledged records, and finalizes a missing record as wire loss after it falls
more than 32 sequence numbers below the forward-moving anchor or after
`max(RTO, 500 ms)` if no ACK resolves it. A missing `Data` record contributes to source-loss and congestion
windows; a missing `Fec` record releases its bytes but does not inflate source
loss. Unacked reliable-control packets past the retransmission timeout are
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
`Packet::empty` and `split` are part of the codec's public surface but the
production send/receive path uses `encode_raw` + `decode` (see
`Tunnel::send_packet` / `handle_udp_datagram`); they exist for hot-path decoders
that want a zero-copy body.

Note the decoder deliberately does **not** validate the body against
`header.packet_type` (no per-type length or content check). The size gates live
one layer up, in the tunnel: `MAX_PAYLOAD` on the TUN read path and
`PATH_MTU - OUTER_OVERHEAD` on the send path.

## Modularity

The packet *taxonomy* above is fixed: `PacketType` is a closed enum and the
receive path's `match` on it is exhaustive. Everything else is a swappable part
selected per session from config, and most of them are negotiated in the Noise
handshake:

| Swappable | Trait | Not swappable | Trait |
|---|---|---|---|
| Byte carrier (UDP/TCP) | `carrier::Carrier` | Packet taxonomy | `PacketType` |
| Key exchange | `protocol::handshake::Handshake` | | |
| Header encoding | `protocol::frame::FrameCodec` | | |
| AEAD cipher | `crypto::suite::AeadCipher` | | |
| Message envelope | `transport::Transport` | | |
| FEC erasure code | `fec::FecScheme` | | |
| Congestion control | `congestion::CongestionControl` | | |

The line is drawn around the *encoding*, not the *semantics*: two codecs can put
the same fields on the wire in completely different ways, but there is still one
fixed set of things a VPN does. That is a deliberate trade — see
[`profiles.md`](profiles.md) for the reasoning, and
[`carrier.md`](carrier.md) for the byte-carrier seam specifically.

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
