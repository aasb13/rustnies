# Session & Peer Lifecycle Specification

This document is the authoritative state machine for a rustnies session — the
lived relationship between a client and the server, keyed by `SessionId`. It is
derived from reading the current implementation in `src/tunnel/server.rs`,
`src/tunnel/mod.rs`, `src/tunnel/handshake.rs`, `src/tunnel/peers.rs`, and
`src/protocol/session.rs`.

The goal is to make explicit what is currently only implicit across several
files, and to drive the operator-facing CLI (steps 3–5 of the roadmap) from a
single design rather than ad-hoc assumptions.

## Definitions

- **Peer (static key).** A long-term X25519 identity. On the server it is an
  entry in the `PeerAuth` authorized set (the `[[peers]]` array, reloaded by
  SIGHUP). On the client it is the server's known static public key. A peer key
  persists across sessions; it is the stable identity for logging, auditing, and
  revocation.
- **Session.** An ephemeral, per-handshake encrypted channel. A new Noise IK
  handshake always produces a new `SessionId` (derived from the handshake hash,
  which includes a fresh ephemeral), so two concurrent connections from the same
  peer key are two independent sessions. A session has directional app keys
  (`key_i2r`, `key_r2i`) and lives for the duration of one tunnel task.
- **Tunnel task.** The per-session `tokio::spawn`ed future running
  `Tunnel::run`. It owns the session's cipher state, FEC groups, congestion
  controller, and receive loop. On the server it reads UDP and TUN over
  channels from the dispatcher; on the client it reads from a dedicated
  socket-reader task.

## Implementation status

G1, G2, G4, G5, and G6 have been implemented (see the gap sections below for
details and code references). G3 (roaming tracking) is also implemented. Only
the future-work items (rehandshake key-rotation seam, structured event stream
vs. counters) are deferred to later phases.

## State machine

```
                        ┌──────────────┐
                        │  idle        │   (no session exists yet;
                        │              │    peer key known or unknown)
                        └──────┬───────┘
                               │
            handshake msg1     │  (server) / connect (client)
              received         │
            or connect called  │
            ┌──────────────────┘
            ▼
    ┌─────────────────┐
    │  handshaking    │   (Noise IK in flight)
    └──────┬──────────┘
           │
     handshake
     completed           ┌──────────────────────┐
            ┌────────────┤  live                │
            ▼            └──────────┬───────────┘
    ┌─────────────────┐             │
    │  error          │             │ periodic tick
    │  (handshake     │             │ (no authenticated
    │   rejected/     │             │  traffic for
    │   failed)       │             │  SESSION_TIMEOUT)
    └─────────────────┘             ▼
                          ┌──────────────────────┐
                          │  idle_timeout        │
                          └──────────┬───────────┘
                                     │ sweep / stop
                                     ▼
                        ┌──────────────┐
                        │  closed      │   (terminal)
                        └──────────────┘
```

For the multi-client **server**, the dispatcher also maintains bookkeeping-only
transitions that do not map onto a single tunnel task: **roaming**, **cap
eviction**, and **reaping of a crashed/exited tunnel**. These are described
below under "Server-side transitions" because they are owned by the dispatcher
task, not by the per-session tunnel.

### States

| State | Description |
|-------|-------------|
| **idle** | No session exists (or the session's tunnel task has already exited and the dispatcher has not yet swept the entry). The peer key may or may not be authorized. |
| **handshaking** | A Noise IK handshake is in flight (message 1 sent or received, message 2 not yet confirmed). No steady-state data flows. The handshake is retried loss-tolerant by the initiator. |
| **live** | The Noise handshake completed and `Tunnel::run` is pumping data. The 75 s activity timer is armed; periodic pings, keepalives, FEC flushes, and retransmits are active. |
| **idle_timeout** | A sub-state reached inside `Tunnel::run` when no authenticated packet (data, control, keepalive, ping/pong) has been received from the peer within `SESSION_TIMEOUT` (75 s). The tunnel is tearing itself down. This is a transient terminal state on the tunnel-task side; the dispatcher reaches `closed` after its sweep. |
| **error** | A handshake failed (rejected key, corrupt message, I/O error) or `Tunnel::run` exited with a non-close error (`UdpClosed`, `TunError`). On the client this triggers the reconnection backoff. |
| **closed** | Terminal. The tunnel task has exited, the dispatcher has swept the entry (server) or the daemon has stopped (`Stopped`). No further data flows for this `SessionId`. |

### Transitions

| # | Event | From | To | Owner | Mechanism |
|---|-------|------|----|-------|-----------|
| T1 | Handshake accepted (Noise `Split` succeeds; peer authorized) | `idle` → `handshaking` → `live` | Dispatcher (server) / daemon (client) | `handle_handshake` → `spawn_client` (server); `handshake::client` → `Tunnel::from_handshake` (client) |
| T2 | Handshake rejected (unauthorized static key) | `handshaking` → `error` | Handshake responder | `respond_message_1` returns `None` after `authorizer` returns `false`; no session is created. Logged at `info`. |
| T3 | Handshake rejected (corrupt / wrong server key) | `handshaking` → `error` | Handshake responder | `respond_message_1` returns `None` on `read_message_1` error. Logged at `info` with the Noise reason. |
| T4 | Stop signal (Ctrl+C / IPC `Stop`) | `live` | `closed` | Shared `watch<bool>` (server) / `Tunnel::run` selects on `stop.changed()` (client) | `TunnelExit::Stopped`; tunnel sends `PacketType::Close` to peer before exiting. |
| T5 | Peer sent `Close` | `live` / `idle_timeout` → `closed` | Tunnel task (both sides) | `handle_udp_datagram` sees `PacketType::Close`, sets `self.closing = true`; `Tunnel::run` breaks with `TunnelExit::PeerClosed`. |
| T6 | No peer traffic for `SESSION_TIMEOUT` (75 s) | `live` → `idle_timeout` → `closed` | Tunnel task (both sides) | The `timeout_check` 1 s tick compares `last_peer_activity.elapsed()` to `SESSION_TIMEOUT`; on breach sends a `Close` and returns `TunnelExit::SessionTimeout`. |
| T7 | UDP source closed | `live` → `error` → (client) reconnect | Tunnel task | `udp_rx.recv()` returns `None`; `Tunnel::run` breaks with `TunnelExit::UdpClosed`. |
| T8 | TUN read error | `live` → `error` | Tunnel task | `tun.recv` returns `Err`; `Tunnel::run` breaks with `TunnelExit::TunError`. |
| T9 | Roam confirmed (AEAD decrypt from a new `SocketAddr`) | `live` | `live` (same session) | Tunnel task | `handle_udp_datagram`: on a successful AEAD decrypt from a source address different from `self.peer`, updates `self.peer` and signals the dispatcher over the address-change channel. The AEAD tag is the authentication gate. |
| T10 | Per-peer session cap exceeded | `live` → `closed` (victim) | Dispatcher | `evict_oldest_peer_session` | On a new handshake that would exceed `max_sessions_per_peer` for a static key, the oldest-idle session for that key is removed from the `sessions` map. Removing the handle drops the `udp_tx` sender, which makes the victim's `Tunnel::run` exit promptly (T7, `UdpClosed`) on its next select iteration. Unlike T4/T6, the victim does **not** send a `Close` to its peer before exiting — the peer only discovers the eviction indirectly (silently dropped data, then its own T6 timeout). |
| T11 | Dispatcher sweep | `idle_timeout` / `error` → `closed` | Dispatcher | 1 s `sweep` tick | `sessions.retain(|_, h| !h.tun_tx.is_closed())` — entries whose tunnel task exited (via T5/T6/T7/T8) have a closed TUN channel. `addr_index` entries pointing at swept sessions are reaped. (Cap-evicted entries are already removed by T10; the sweep does not double-handle them.) |

### Transition event taxonomy

- **Authenticated events** — proven by a valid AEAD tag or a Noise
  cryptographic proof. These are trustworthy regardless of source address:
   - T2/T3 authorization (Noise message-1 proves possession of the initiator's
     static key; the `authorizer` closure then checks it against the `PeerAuth`
     allowlist).
  - T5 `Close` (authenticated by AEAD).
  - T6 inactivity timeout (locally observed: no authenticated packet seen).
  - T9 roaming (a successful AEAD decrypt from a new address is identity
    proof; the dispatcher never trusts a pre-decrypt header for address changes).
- **Local events** — produced by the tunnel task itself or the daemon:
  - T4 stop signal.
  - T6 timeout.
  - T7/T8 transport-level exit conditions.
- **Dispatcher-internal events** — bookkeeping decisions by the server
  dispatcher that do not involve the per-session tunnel task directly:
  - T1 spawn (after a successful handshake).
  - T9 roaming signal (the tunnel task proves it; the dispatcher updates its
    `addr_index` cache and `ClientHandle.current_addr`).
  - T10 cap eviction.
  - T11 sweep.

## Server-side transitions (multi-client dispatcher)

`run_server` in `src/tunnel/server.rs` is the single owner of the `sessions`
table (`HashMap<SessionId, ClientHandle>`) and the `addr_index` cache
(`HashMap<SocketAddr, SessionId>`). All transitions T1, T9, T10, T11 above are
applied by the dispatcher task on this table. Per-session cryptographic state
and steady-state logic live in the spawned `Tunnel` task; the dispatcher only
owns routing tables and lifecycle hooks.

### T1 — Handshake accepted → session spawned

Triggered by: an inbound UDP datagram that is not peek-routable to a live
session, passes the per-source handshake-probe token bucket, and is recognized by
`handshake::respond_message_1` as a valid Noise message 1 from an authorized
peer.

Owned by: `handle_handshake` / `spawn_client` (dispatcher task).

The dispatcher:
1. Locks `PeerAuth`, builds an `Authorizer` closure (`check(key) -> (bool,
   Option<name>)`), passes it to `respond_message_1`.
2. `respond_message_1` decrypts the initiator's static key, runs the Noise
   responder (ee, es, se DHs), **authorizes** the key, builds message 2, and
   derives the `SessionId` from the handshake hash.
3. If authorization fails (T2), returns `None` — no session, no message 2
   sent (no resource created).
4. If it succeeds, `handle_handshake` calls `evict_oldest_peer_session` (T10
   check), seeds the per-client obfuscation stack from the handshake hash,
   extracts the `header_xor` public routing keystream if applicable, and
   `spawn_client` inserts a new `ClientHandle` keyed by `SessionId`.

**Important:** a fresh handshake **never** replaces an existing session — not by
address, not by static key. Two concurrent sessions from the same peer coexist.
Stale sessions are reclaimed by T6 (timeout) and T11 (sweep). This is a
deliberate design choice (see `doc/architecture.md` §"Server dispatch").

### T9 — Roaming (address change)

Triggered by: a steady-state datagram from a source address different from the
session's current `peer`, which AEAD-decrypts successfully.

Owned by: the per-session `Tunnel` task (detects), the dispatcher (applies).

The `Tunnel::run` loop does **not** pre-filter by source address.
`handle_udp_datadgram` decrypts unconditionally; if the AEAD tag verifies, the
source is authenticated and the tunnel updates `self.peer = from`, then sends
`(SessionId, new_addr)` over the bounded address-change channel. The dispatcher
updates `ClientHandle.current_addr` and refreshes `addr_index`, removing the
old mapping only if it still points at this session.

The `addr_index` is a **stale-tolerant cache**: a wrong entry never misroutes
because the tunnel's AEAD decrypt rejects foreign bytes (the comment at
`server.rs:521` makes this explicit). Under `header_xor` obfuscation, the
dispatcher also stores a per-session de-whitening keystream derived from the
handshake hash, so a roaming whitened session remains peek-routable without a
re-handshake.

### T10 — Per-peer session cap eviction

Triggered by: a new handshake that would make the count of live sessions for one
static key exceed `max_sessions_per_peer` (default 0 = unlimited).

Owned by: `evict_oldest_peer_session` (dispatcher task, at spawn time).

When the cap would be exceeded, the **oldest-idle** session for that key (by
`last_forwarded`) is removed from the `sessions` map. The new handshake is
**not** refused (so a legit reconnect to a fresh NAT port succeeds). The
evicted session's tunnel task exits promptly (T7/`UdpClosed`) because removing
the `ClientHandle` drops the dispatcher's `udp_tx` sender — the tunnel's
`udp_rx.recv()` returns `None` on its next select poll. The victim does not
receive a direct signal (no `Close` is sent to it) — see **Gap G4** below.

### T11 — Sweep

Triggered by: the 1 s `sweep.tick()` in the dispatcher select loop.

Owned by: `run_server` (dispatcher task).

Removes entries whose `tun_tx` channel is closed (the tunnel task dropped its
end, meaning the task exited). This covers T6 (timeout), T7 (UDP closed), T8
(TUN error), T5 (peer close), and T10 (cap eviction) — all cause the tunnel
task to exit, which closes the channel the dispatcher observes. The sweep also
reaps stale `addr_index` entries pointing at swept sessions. When all sessions
are gone, `counters.connected` is set to `false`.

## Client-side transitions (reconnection loop)

`run_client` in `src/daemon/mod.rs` runs the client daemon. The lifecycle is:

```
        ┌──────────────┐
        │  idle        │
        └──────┬───────┘
               │ bind socket + handshake (retried, 10 attempts)
               ▼
        ┌──────────────┐
        │  handshaking │
        └──────┬───────┘
      success  │  (reset backoff)
               ▼
        ┌──────────────┐
        │  live        │
        └──────┬───────┘
               │ Tunnel::run exits (T5/T6/T7/T8/T4)
          ┌────┴────┐
          │         │
     reconnect     stop
     enabled       requested
        ▼           ▼
   ┌──────────┐  ┌────────┐
   │reconnect │  │closed  │
   │backoff   │  └────────┘
   └────┬─────┘
        │ sleep (exponential, 1s→30s, abortable by stop signal)
        ▼
   ┌──────────────┐
   │  handshaking │  (loop)
   └──────────────┘
```

The TUN device and all firewall guards (kill switch, DNS leak, route-all,
route-file, NAT) are brought up **once** before the loop and kept for the
daemon lifetime — only the UDP socket and cipher state are rebuilt per session.
`Tunnel::run` returns a `TunnelExit` that maps to the `last_error` field in
`Counters`/`Stats` (e.g. "session timeout", "peer closed", "udp source
closed"). The reconnection backoff is reset after a successful session.

On the client side there is no `PeerAuth` denylist check beyond the initial
static-key verification (`--server-key` / `server_key` must match); the client
always authenticates the server's key out of band and does not consult a
peer list for incoming connections (it is the initiator).

## Audit: gaps between spec and implementation

These are transitions or states that are **named in the state machine above but
are not fully handled today**, plus lifecycle needs that the current code does
not address at all. Each is a concrete gap, not a hypothetical.

### Gap G1 — No runtime revocation / denylist

**Status: implemented.** `PeerAuth` (`src/tunnel/peers.rs`) now includes a
`denylist: HashSet<[u8; 32]>` consulted in `authorized()` and `check()` before
the allowlist/open-mode check. The denylist is populated at runtime via the
IPC `Revoke` request (`src/ipc/mod.rs:handle_revoke`) which calls
`peer_auth.revoke(key)`. Live sessions for a revoked key are evicted by the
dispatcher via `evict_sessions_for_key`. **SIGHUP reloads do not clear the
denylist** — a key removed from `[[peers]]` plus SIGHUP rejects future
handshakes, but a runtime `revoke` persists across SIGHUP (reset only on
daemon restart). Operators remove the key from config + SIGHUP for
permanent exclusion. See `doc/obfuscation.md` for the 75 s worst-case window.

### Gap G2 — No operator-facing disconnect / revoke IPC command

**Status: implemented.** New IPC `Request` variants added to
`src/ipc/messages.rs`:

| Request | Purpose | Response |
|---------|---------|----------|
| `Revoke { public_key }` | Add key to runtime denylist + evict live sessions | `Ack(n_evicted)` |
| `ListSessions` | Enumerate live sessions | `Sessions(Vec<SessionInfo>)` |
| `Disconnect { session_id, peer_key }` | Gracefully tear down matching sessions | `Ack(n_disconnected)` |

`Request` variants and matching `Response` variants are serde-serialised over
the Unix-socket IPC channel (`src/ipc/mod.rs`). The CLI subcommands
(`rustnies revoke`, `rustnies list-sessions`, `rustnies disconnect`) are in
`src/cli.rs` and issue `Request` messages, checking for `Response::Error` and
reporting "only available on the server daemon" for client-side IPC.

### Gap G3 — Roaming is not observable / not tracked historically

**Status: implemented.** `ClientHandle` (`src/tunnel/server.rs`) now tracks
`roam_count: u32`, `last_roam: Option<Instant>`, `spawned_at: Instant`, and
`peer_label: Option<String>`. The dispatcher's roaming handler
(`src/tunnel/server.rs:711`) increments `roam_count`, sets `last_roam`, and
bumps `stats::Counters::sessions_roamed`. `build_session_list` reports these
as `SessionInfo` fields (`roam_count`, `last_roam` as seconds-since, `age_secs`).

### Gap G4 — Cap-evicted sessions are not cleanly signaled

**Status: implemented.** Cap-eviction, revocation-driven eviction, and operator
disconnect now all route through a single `evict_tx: mpsc::UnboundedSender<()>`
channel on `ClientHandle` (`src/tunnel/server.rs`). When the dispatcher evicts a
session (cap, revoke, or disconnect), it sends a unit signal on `evict_tx`,
which is stored as `evict_rx: Option<mpsc::UnboundedReceiver<()>>` on the
`Tunnel`. The `Tunnel::run` select loop (`src/tunnel/mod.rs:478`) polls
`evict_recv(&mut evict_rx)`; on signal it calls
`send_control(PacketType::Close)` and exits with `TunnelExit::PeerClosed`.

This replaces the old behavior where eviction dropped the dispatcher's `udp_tx`
sender, causing a `UdpClosed` exit with no `Close` packet sent. All three
teardown paths now exit cleanly as `PeerClosed`.

### Gap G5 — No structured connect/disconnect lifecycle events

**Status: implemented (counters).** `src/stats.rs` `Counters` now includes:

| Counter | Incremented at |
|---------|---------------|
| `handshakes_accepted` | `server::handle_handshake`, handshake success (T1) |
| `handshakes_rejected` | `server::handle_handshake`, handshake refusal/non-handshake (T2) |
| `sessions_timed_out` | `Tunnel::run`, exit on `TunnelExit::SessionTimeout` (T6) |
| `sessions_peer_closed` | `Tunnel::run`, exit on `TunnelExit::PeerClosed` (T5, T10, revoke, disconnect) |
| `sessions_evicted` | `Tunnel::run`, exit on `TunnelExit::UdpClosed` (fallback) |
| `sessions_roamed` | `server::run_server` roaming handler (T9) |

These appear in the `Stats` snapshot served via IPC `Status` and are formatted
into the CLI `status` output. **Future work:** a structured event stream
(protobuf/JSON events at each transition) is deferred to a later phase; the
counters provide the observability floor now.

### Gap G6 — `Handshake1`/`Handshake2` on the steady-state wire

The header's `PacketType` enum includes `Handshake1` (wire byte `1`) and
`Handshake2` (wire byte `2`), but steady-state frames are never constructed with
these types. The actual Noise IK handshake messages are opaque blobs sent *before*
a session exists and are not wrapped in the 24-byte protocol header at all. The
`is_reliable` method lists them as reliable types, and the replay path
(`receive_reliable`) handles them — but in practice they only matter for a future
in-session rehandshake / key-rotation path, which does not exist today (phase 1 has
no mid-session rehandshake; a new connection is always a brand-new `SessionId`).

**Decision:** Retained. `Handshake1`/`Handshake2` are **reserved wire-protocol
values** (`0x01`/`0x02` in the `packet_type` byte). Removing them from the `PacketType`
enum would be a wire-format breaking change that could corrupt the encoding of
subsequent variants or leave permanently-unreachable gaps. They are harmless dead
code that documents forward intent for the rehandshake seam. The `is_reliable`
listing is intentional: if/when rehandshakes are designed, these types will use the
existing reliable-control delivery path. **Action:** nothing to implement; these
variants must not be constructed on the wire until rehandshakes are designed.

## Mapping to the operator surface (steps 3–5)

This state machine directly defines the CLI/IPC surface that step 3 should
expose:

| State machine element | IPC request | Server-side owner |
|----|----|----|
| List sessions (live + idling, with peer key, addr, age, roam count) | `list_sessions` | dispatcher (`sessions` table + `ClientHandle`) |
| List peers (authorized keys + labels, open/restrict mode) | `list_peers` | `PeerAuth` (read-only snapshot) |
| Disconnect a session or all sessions for a peer | `disconnect {session_id \| peer_key}` | dispatcher (insert T5-equivalent teardown) |
| Revoke a static key (denylist + evict live sessions) | `revoke {public_key}` | `PeerAuth` (denylist) + dispatcher (evict) |
| Onboarding: generate a peer's keypair + config | `keygen --peer` / `peer add` | daemon (no persistent state; writes a client config) |

The disconnect and revoke operations need **new** IPC request/response variants
beyond `Status`/`Stop`/`Ping`. The disconnect of a specific session is a
server-side-only operation (the client has one session); revoke is
server-side-only. The connect/disconnect/roam/timeout events (Gap G5) should be
emitted as structured `tracing` events (and optionally a metrics counter) at
each transition — the state machine table above is the list of emission points.

## Constants reference

| Constant | Value | Where | Purpose |
|----------|-------|-------|---------|
| `SESSION_TIMEOUT` | 75 s | `src/tunnel/mod.rs:51` | Inactivity teardown (T6) |
| `KEEPALIVE_INTERVAL` | 20 s | `src/tunnel/mod.rs:48` | Authenticated idle keepalive |
| `HANDSHAKE_RTO` | 500 ms | `src/tunnel/handshake.rs:22` | Client handshake retransmit |
| `HANDSHAKE_MAX_ATTEMPTS` | 10 | `src/tunnel/handshake.rs:23` | Client handshake retry budget |
| `HANDSHAKE_PROBE_BURST` | 4 | `src/tunnel/server.rs:128` | Server probe token bucket capacity |
| `HANDSHAKE_PROBE_INTERVAL_MS` | 200 | `src/tunnel/server.rs:129` | Probe token refill interval |
| `HANDSHAKE_PROBE_GLOBAL_CAP` | 64 | `src/tunnel/server.rs:133` | Max tracked probe sources |
| `HANDSHAKE_TOKEN_TTL_MS` | 5000 | `src/tunnel/server.rs:135` | Probe-tracker idle eviction |
| `PING_INTERVAL` | 500 ms | `src/tunnel/mod.rs:40` | RTT probe interval |
| `FEC_TICK` | 100 ms | `src/tunnel/mod.rs:42` | TX group flush + stats publish |
| `RTO_TICK` | 50 ms | `src/tunnel/mod.rs:44` | Reliable-control retransmit |
| sweep interval | 1 s | `src/tunnel/server.rs:356` | Dispatcher session reaping (T11) |
| `SESSION_TIMEOUT` configurable | yes (tests) | `Tunnel::set_keepalive_params` | Tunable for tests |

## Security properties of the lifecycle

- **Identity is the static key, not the address.** Session identity is
  `SessionId` (cleartext, AEAD-authenticated as AAD), anchored to the static
  key learned in the Noise handshake. A roaming client's changing `SocketAddr`
  never changes its session identity (`doc/architecture.md` §"Server dispatch").
- **Authorization is handshake-time, not steady-state.** `PeerAuth::check` is
  called inside `respond_message_1` (before message 2 is built and before any
  session state is created). An unauthorized peer gets no message 2 and no
  session. This is the only authorization gate today; there is no re-check on
  steady-state packets because the AEAD keys themselves are the steady-state
  proof of identity.
- **Address updates require AEAD authentication.** The dispatcher never updates
   a session's routing address from a peeked/pre-decrypt header. Only a
   successful AEAD decrypt of a datagram from a new address triggers roaming
   (Transition T9). This prevents address-hijack spoofing.
- **Freshness on reconnect.** A new handshake uses a fresh ephemeral, so its
  `SessionId` differs from the previous one — a reconnect is a new session
  (T1) coexisting with any still-alive old session, not an implicit replacement.
  This is intentional: it makes NAT rebinding transparent but means stale
  sessions are only reclaimed by timeout or cap-eviction (Gap G4 window).
