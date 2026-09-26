# Architecture

This document describes the end-to-end architecture of rustnies phase 1: how
the modules fit together, the steady-state data flow, and the key design
decisions and the reasoning behind them.

## Module map

```
src/
  lib.rs              Crate root; re-exports the public API.
  main.rs             Binary entrypoint; delegates to cli::run().
  cli.rs              clap CLI: server / client / status / stop / ping / keygen /
                      pubkey / revoke / list-sessions / disconnect / dns-check.
  config.rs           ServerConfig / ClientConfig (serde) + file-config merge + schema validation.
  stats.rs            Counters (owned by the tunnel) + Stats snapshot (over IPC), incl. lifecycle
                      counters (handshakes_accepted, sessions_timed_out, etc.).
  daemon/mod.rs       Persistent daemon: owns the tunnel task(s), IPC server, control channel
                      (ServerHandle + ControlCommand), SIGHUP peer reload, and route/firewall
                      setup (route-all, kill switch, DNS leak prevention, client-side NAT).
  ipc/
    mod.rs            Unix-socket IPC server + client; newline-delimited JSON; dispatches
                      operator control commands (Revoke, ListSessions, Disconnect) to the
                      server dispatcher via ServerHandle.
    messages.rs       Request / Response enums (Status, Stop, Ping, Revoke, ListSessions, Disconnect).
  carrier/
    mod.rs            Byte-carrier seam: Carrier / CarrierListener traits, UdpCarrier,
                      TcpCarrier (2-byte length-delimited), Inbound. See doc/carrier.md.
  tunnel/
    mod.rs            Steady-state tunnel: TUN<->carrier pump, FEC, congestion, RTT, keepalives,
                      TunnelExit enum, eviction-signal receiver.
    handshake.rs      Noise IK handshake driver over a Carrier (retried, loss-tolerant).
    peers.rs          Server-side peer authorization list (`PeerAuth`) + runtime denylist.
    server.rs         Multi-client server dispatcher (SessionId-routed, roaming, cap eviction,
                      ControlCommand enum, ServerHandle, eviction-signal channel).
  protocol/
    mod.rs            Re-exports.
    header.rs         PacketHeader (the semantic value), PacketType, HeaderFlags.
    codec.rs          Packet (header || ciphertext) helpers; the frame *encoding*
                      itself is swappable via frame.rs.
    frame.rs          FrameCodec seam: header serialisation, body_offset, and the
                      codec-agnostic server routing peek. V1FixedCodec (24-byte
                      packed, the default) and V2TlvCodec (self-describing).
    session.rs        Session: sequencing, ReplayWindow, AckTracker,
                      session_id_from_hash.
    handshake.rs      Handshake trait (KEX seam), HandshakeError, build_handshake,
                      SessionEstablished, InitiatorHello.
    profile.rs        Protocol profiles: ClientOffer / Selection wire formats,
                      the server-authoritative selection rule, LocalProfile
                      (pre-handshake config) and ResolvedProfile (a session's
                      runnable parts). See doc/profiles.md.
  crypto/
    mod.rs            Re-exports.
    keys.rs           Static X25519 KeyPair (generate / load_or_create at 0600).
    noise.rs          Noise IK handshake state machine (Split -> app keys,
                      keyed by the negotiated cipher suite).
    aead.rs           ChaCha20-Poly1305 with deterministic per-packet nonces.
    suite.rs          AeadCipher trait + registry (the swappable cipher seam).
  transport/
    mod.rs            Swappable Transport trait + PlainTransport / TaggedTransport
                      + name/id registry.
  obfuscation/
    mod.rs            ObfuscationLayer trait + ObfuscationStack (ordered, composable).
    padding.rs        SizePadding layer (bucket-based size hiding).
    timing.rs         TimingJitter layer (send jitter + idle decoy packets).
    header_xor.rs     HeaderXor layer (per-session header whitening).
  fec/
    mod.rs            Re-exports.
    gf256.rs          GF(256) arithmetic (tables, solve_system).
    reed_solomon.rs   Systematic Reed-Solomon (k, m) erasure code.
    adaptive.rs       AdaptiveFec controller (loss-driven, hysteresised).
  congestion/
    mod.rs            CongestionController (SRTT/RTTVAR, slow start, MD on loss).
  tun/
    mod.rs            Platform-independent Tun + TunFactory traits (incl. from_fd).
  platform/
    mod.rs            Platform selector + platform-agnostic ops (dns_check).
    linux.rs          LinuxTunFactory (tun_rs, dual-stack) + NatRules (server + client-side
                      iptables/ip6tables masquerade), RouteGuard (route-all v4+v6),
                      KillSwitch + DnsLeakGuard + ResolvConfGuard (dual-stack), route-file.
tests/
  end_to_end.rs       Loopback handshake + key-matching integration tests.
```

## Layering

The crate is layered so that each tier only depends on the tier below it, and
the platform-specific code is isolated at the edges:

```
            +-----------------------------+
            |  cli.rs / daemon/mod.rs     |  process + IPC orchestration
            +-----------------------------+
                          |
            +-----------------------------+
            |  tunnel/ (steady-state)     |  ties everything together
            +-----------------------------+
              |        |        |        |
        +-----+---+ +--+--+ +---+---+ +--+------+ +-----------+
        |protocol/| |crypto/| |  fec/ | |transport/| |obfuscation/|  core, platform-free
        +---------+ +-------+ +-------+ +----------+ +-----------+
                          |
            +-----------------------------+
            |  carrier/ (UDP | TCP)       |  byte pipe, below the protocol
            +-----------------------------+
                          |
            +-----------------------------+
            |  tun/ (trait)               |  platform abstraction
            +-----------------------------+
                          |
            +-----------------------------+
            |  platform/linux.rs          |  OS-specific TUN + NAT
            +-----------------------------+
```

The core modules (`protocol`, `crypto`, `fec`, `transport`, `obfuscation`,
`tun`, `tunnel`) contain **no** platform-specific code and **no** desktop-only
assumptions. They compile and are unit-tested independently of Linux.
`platform/` is the only place that touches `tun_rs`, `iptables`, or file
descriptors for TUN.

## Steady-state data flow

After the Noise IK handshake establishes two application keys and a session id,
both client and server run the same `Tunnel::run` loop. Client and server are
symmetric in steady state; the only differences are which side initiated the
handshake and whether the server installs NAT rules.

### Client -> Server (tunneled outbound traffic)

1. A packet is read from the local TUN interface.
2. The tunnel allocates a sequence number and builds a `Data` header carrying
   the current sliding-window ack anchor + bitmap (piggybacked
   reverse-direction acks).
3. The packet is AEAD-encrypted with the session's initiator->responder key,
   using the encoded header as authenticated associated data (AAD). The nonce
   is `session_id || seq || direction || zero`.
4. The plaintext frame `header || ciphertext` is passed through the
   `ObfuscationStack` (if configured; identity by default) and then the
   `Transport` layer's `wrap` (identity envelope in phase 1). Obfuscation
   transforms plug in via the `ObfuscationStack`, not `Transport::wrap`; see
   `doc/obfuscation.md` for the stackable layer system.
5. The wrapped bytes are sent as one protocol *message* to the peer. On the
   default `udp` carrier that is one datagram; on `tcp` the carrier adds a
   2-byte length prefix and the bytes may span several reads. The tunnel does
   not know which — see `doc/carrier.md`.
6. The plaintext packet is also accumulated into the current FEC group. When
   the group reaches `k` source symbols, `m` parity symbols are encoded and
   transmitted as `Fec` packets (same header + AEAD + transport pipeline).

### Server -> Client (tunneled inbound traffic + NAT)

On the server, packets read from the TUN interface are tunneled back exactly as
above (responder->initiator key/direction). Outbound traffic from a client
arrives at the server's TUN as a normal IP packet; the server's NAT rules
(`NatRules` in `platform/linux.rs`) masquerade it onto the default egress
interface so it reaches the internet. Replies come back, get reverse-NATed to
the tunnel address, and are read from the TUN and tunneled to the client.

### Server dispatch: sessions are identified by SessionId, not address

The server (`src/tunnel/server.rs`) is a single dispatcher task owning one
bound UDP socket and one shared TUN device, with one independent `Tunnel`
task per client. Session identity is the 32-bit `SessionId` carried in every
steady-state header — **not** the client's `SocketAddr`. The dispatcher keeps
two structures (single-task owned, no locking):

- `sessions: HashMap<SessionId, ClientHandle>` — the source of truth.
- `addr_index: HashMap<SocketAddr, SessionId>` — a stale-tolerant routing
  cache, used only when the header cannot be peeked.

Per inbound datagram: (1) peek the `SessionId` (after stripping the stateless
transport envelope); a live match is forwarded to that session. (2) Otherwise
probe `handshake::respond_message_1` — cryptographically unambiguous, so a
fresh handshake from a known address is recognised as a **new** session rather
than swallowed by the old tunnel. (3) Otherwise fall back to `addr_index`
(covers packets whose header the dispatcher cannot peek, e.g. a whitened frame
whose per-session keystream the dispatcher does not yet know). (4) Otherwise
drop as scan noise.

The handshake probe (step 2) is the only path that pays the asymmetric-crypto
cost of `respond_message_1`, so it is **rate-limited**: a per-source token
bucket (`HANDSHAKE_PROBE_BURST` = 4, refilled one per 200 ms) plus a global cap
(`HANDSHAKE_PROBE_GLOBAL_CAP` = 64 tracked sources) bound the per-datagram crypto
work. An attacker flooding garbage UDP is throttled at the bucket before any
Noise responder work runs. Idle sources are evicted from the tracker after
`HANDSHAKE_TOKEN_TTL_MS` (5 s) of silence.

Consequences: multiple concurrent sessions may share one client address (a
fresh handshake never replaces an existing session, by address or by static
key); **but** a per-static-key session cap (`max_sessions_per_peer`, default 0 =
unlimited) bounds how many sessions a single peer key may hold
simultaneously — when a new handshake would exceed the cap, the oldest-idle
session for that key is evicted (logged), so a legit reconnect to a fresh NAT
port still succeeds while a misbehaving client cannot exhaust server memory/fds;
and a session survives its client's address changing mid-session (roaming).

**Whitened (`header_xor`) roaming is supported.** Each session stores its
`header_xor` keystream as *public routing metadata* in `ClientHandle`
(`pub_route_keystream`), derived from the handshake hash (not secret — the AEAD
AAD still authenticates the header). The peek path tries de-whitening the frame
with each live session's stored keystream and re-peeks the `SessionId`; a wrong
keystream fails the version/type check with probability ~1/255, so this never
misroutes. This lets a whitened session remain peek-routable after roaming to a
new address (where the `addr_index` cache is stale), so no re-handshake is
needed.

A session survives its client's address changing mid-session (roaming) — the
tunnel task updates its peer only after a packet **AEAD-decrypts** from the new
address (the tag is the authentication gate) and signals the dispatcher to
refresh the address index. The address-update trust model: the dispatcher never
changes a session's routing address based on a peeked/pre-decrypt header — it
only trusts the confirmed address-change signal sent after a successful AEAD
decrypt. Address-move frequency: "always take the latest authenticated source"
(WireGuard-style) — there is deliberately no minimum dwell time; each move must
re-authenticate via AEAD.

### Server identity model: operations impact

Sessions are now 1:1 with a Noise handshake's derived `SessionId`, **not** with
a client IP:port. Operationally this changes what server-side tooling can assume:

- **Connection logging**: a client that roams or reconnects appears as the *same*
  connection (same `session_id`, same static key) even though its source UDP
  address changes. Log correlation should key on `session_id` / static pubkey,
  not on `SocketAddr`. The server logs `session_id` on spawn and on roaming.
- **Per-IP rate limiting / abuse mitigation**: a single UDP source may carry
  multiple sessions (intentional multi-tunnel or re-NAT collision), and one
  session may roam across many source addresses. Abuse controls keyed on source
  IP alone are unreliable. The handshake-probe rate limiter is keyed on source
  address for *probe denial-of-service* protection, but steady-state session
  accounting is by `session_id`.
- **Monitoring dashboards**: `clients` (in `rustnies status`) now counts live
  sessions, not source addresses. A roaming client is always one session, so the
  count is stable across moves; a multi-tunnel client is multiple sessions.
- **Address bookkeeping**: the server no longer keeps a `peer -> session` map by
  address; return traffic is routed by `session_id` (learned from the TUN
  post-and-ack) and the `addr_index` cache (last known address per session,
  refreshed on roam). Client tunnel IPs learned from observed inner source
  addresses are accepted only inside the configured TUN subnet
  (`should_learn_tun_ip`); implausible sources (LAN neighbors, the client's
  public underlay IP) are rejected with a warning and never registered, so
  return traffic cannot be misrouted into the tunnel.

### Receive path (both sides)

1. One whole protocol message is received from the `Carrier` (which has already
   done any stream reassembly).
2. `Transport::unwrap` reverses the wrap step, yielding the plaintext frame.
3. The negotiated `FrameCodec` splits the frame into `PacketHeader` +
   ciphertext. The receive path then *re-encodes* the decoded header to rebuild
   the AAD, so a codec's encoding must be exactly canonical.
4. The ciphertext is AEAD-decrypted with the header as AAD. A failed tag
   drops the packet silently without applying its ACK fields.
5. The authenticated peer's advertised `ack_seq`/`ack_bitmap` are observed
   and reconciled against exact-byte records for transmitted data/parity.
6. Every authenticated packet is recorded in the ack tracker (its seq
   advances the ack anchor we advertise back). Reliable packet types
   (`Handshake1`, `Handshake2`, `Close`) additionally pass through the replay
   window; duplicates are dropped.
7. Dispatch by `PacketType`:
   - `Data` -> written to the TUN, and recorded into the RX FEC group.
   - `Fec` -> recorded into the RX FEC group as a parity symbol.
   - `Ping` -> echoed back as `Pong` with the same 12-byte timestamp body.
   - `Pong` -> RTT sample fed to the congestion controller.
   - `Ack` -> no additional action; its ACK fields were reconciled after
     authentication.
   - `Close` -> tears down the tunnel.
8. When an RX FEC group has at least `k` surviving symbols, Reed-Solomon
   decodes the missing sources. Newly recovered sources are written to the TUN
   and counted. The original sender derives loss feedback from the missing
   source sequence in the peer's ACK window; receiver-side recovery never
   changes the reverse direction's controllers.

### Background ticks

`Tunnel::run` also drives three intervals:

- **Ping** (500 ms): sends a `Ping` carrying a monotonic id and a microsecond
  timestamp; the peer echoes it as `Pong`. The round-trip time feeds
  `CongestionController::on_rtt_sample`.
- **FEC tick** (100 ms): flushes any partial TX FEC group so receiver group
  assembly does not stall, evicts expired RX groups, and publishes live stats
  to the shared counters.
- **RTO tick** (50 ms): retransmits unacked reliable control packets whose
  retransmission timeout has elapsed.

## Key design decisions

### Why UDP by default, with a custom protocol

The target network environment blocks QUIC, and TCP's head-of-line blocking and
in-order delivery are wrong for a latency-sensitive tunnel that wants to apply
FEC and best-effort delivery to data while keeping only control messages
reliable. A custom protocol over UDP gives full control over the wire format,
sequencing, ack strategy, and FEC grouping.

UDP is the **default, not the only option**. `[carrier] name = "tcp"` swaps in
a length-delimited stream, which is useful where UDP is filtered but TCP is not.
The trade is real: no roaming, one connection per session (so no shared-socket
 multiplexing), and head-of-line blocking. It is a config change rather than a
rewrite because the carrier is a seam — see `doc/carrier.md`.

### Why the header *encoding* is swappable but the taxonomy is not

`PacketType` stays a closed `#[repr(u8)]` enum and the receive path's `match` on
it stays exhaustive, so a new packet type is a compile error until every site
handles it. What the `[frame] codec` seam replaces is the byte *layout*:
`v1-fixed` and `v2-tlv` put the same fields on the wire in entirely different
ways. Making the taxonomy runtime-configurable would buy nothing — the set of
things a VPN does is not a deployment choice — and would cost that
compile-time check.

### Why Noise IK for the handshake

Noise is a standard, well-studied handshake framework. The **IK** pattern gives
mutual authentication with the initiator knowing the responder's static public
key out of band, in two messages. We implement the pattern faithfully against
the Noise spec (`Noise_IK_25519_ChaChaPoly_SHA256`) rather than inventing a new
protocol. See [crypto.md](crypto.md) for the precise message flow.

### Why explicit per-packet nonces instead of Noise's transport cipher

Noise's transport cipher is stateful (a monotonic nonce counter per direction).
UDP packets can be lost or reordered, so a stateful counter would either reject
legitimate reordered packets or require complex state. Instead, after
`Split()` we derive two application keys via HKDF and use ChaCha20-Poly1305 with
deterministic 96-bit nonces composed of `session_id || seq || direction`. Each
(key, nonce) pair is used exactly once because `seq` is monotonic per direction
and `direction` disambiguates the two directions. This is the same security
property Noise's transport cipher gives, expressed in a way that tolerates
reordering and loss.

### Why the header is authenticated but not encrypted

The 24-byte header is passed as AEAD associated data. This lets a receiver
route by session id, filter replays, and read sequence/ack/FEC metadata before
decrypting, without leaking anything sensitive (the header carries no content,
only bookkeeping). Tampering with any header bit breaks the Poly1305 tag, so
integrity is still end-to-end.

### Why FEC is adaptive and grouped

Fixed redundancy wastes bandwidth on good links and is insufficient on bad
ones. `AdaptiveFec` watches smoothed packet loss and picks a `k`/`m` pair per
group: as loss rises, `m` increases; as it falls, `m` decreases. Hysteresis
bands (the `down` threshold is 60% of the `up` threshold) prevent the ratio
from flapping near a threshold. `k` is held constant by default so group
formation delay stays predictable; only the parity count adapts. See
[fec.md](fec.md).

### Why the Transport layer is a trait

Phase 1 ships an identity `PlainTransport`. The point of separating it is that
the on-the-wire envelope shape can change without touching the protocol,
crypto, FEC, congestion, or TUN layers. Stackable obfuscation transforms
(padding, timing, header whitening) are NOT implemented as transports — they
sit *on top* of `Transport` via the `ObfuscationLayer` stack and are opt-in via
`[obfuscation]` (off by default); see [obfuscation.md](obfuscation.md). The
`Transport` seam itself remains reserved for envelope-level / full-protocol
mimicry (e.g. TLS/JA3 fronting), still future work. The trait is a stateless
per-datagram transform by design; any stateful shaping belongs in a higher
layer. See [transport.md](transport.md).

### Why TUN is behind a trait with `from_fd`

The core must be reusable from mobile hosts. On Android (VpnService) and iOS
(NEPacketTunnelProvider) the OS grants an already-open TUN file descriptor;
the app does not create a named device. The `Tun` / `TunFactory` traits let the
core accept either a name (desktop) or an open FD (mobile), and the Linux
implementation lives in `platform/linux.rs` where it cannot leak into the core.
See [platform.md](platform.md).

### Why a daemon + CLI over IPC

Running the VPN as a persistent background process means the tunnel state
(session, FEC groups, congestion window, stats) lives as long as the
connection. A lightweight CLI talks to the running daemon over a Unix socket to
query live stats or issue `stop`, without relaunching the VPN or disrupting the
session. See [daemon.md](daemon.md).

## Threat model and scope (phase 1)

Phase 1 provides:

- Confidentiality and integrity of tunneled traffic via ChaCha20-Poly1305.
- Mutual authentication of both peers via Noise IK and long-term static
  X25519 keys (the server's public key must be distributed to the client out
  of band).
- Replay protection via a sliding-window sequence filter.
- Forward secrecy within a session: ephemeral X25519 keys are generated per
  handshake and zeroised on drop.
- Route-all (client routes all traffic through the tunnel), automatic
  reconnection, and two client-side reliability guarantees: **DNS leak
  prevention** (DNS is forced through the tunnel when route-all is on) and an
  opt-in **kill switch** (blocks all non-tunnel traffic and fails closed if the
  tunnel drops). See `doc/platform.md`.
- **IPv6 dual-stack** support: the TUN device, route-all, kill switch, DNS leak
  prevention, and NAT all operate on both IPv4 and IPv6 when a dual-stack TUN is
  configured (`tun_addr6` / `--tun-addr6`). See `doc/ipv6.md`.

Phase 1 does **not** provide:

- Full protocol mimicry (e.g. TLS/JA3 impersonation). Basic obfuscation
  transforms — padding, timing, header whitening — ARE implemented in
  `src/obfuscation/` and opt-in via `[obfuscation]` (off by default).
- Post-compromise security across sessions beyond per-session ephemeral keys.
- Defenses against an active adversary who can drop, reorder, or inject UDP
  datagrams (these are dropped by AEAD/replay, but there is no active probing
  resistance yet).
- Key rotation mid-session.
- Multi-client fan-out on the server is implemented (one server process serves
  many concurrent clients via the dispatcher in `src/tunnel/server.rs`).
