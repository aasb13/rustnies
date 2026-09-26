# The carrier seam

What the protocol's bytes travel over. The seam is `crate::carrier`, and it is
the layer that makes "use TCP instead of UDP" a config change rather than a
rewrite.

## Why this seam exists

Phase 1 hard-coded `tokio::net::UdpSocket` in six places: the daemon bound one,
the tunnel held an `Arc<UdpSocket>` and called `send_to`, the server demuxed
sessions off one shared socket with `recv_from`, and the handshake driver read
from it directly. Every one of those sites assumed **datagram semantics**:

- one `send` is one delivery;
- a frame is self-delimiting, with its length implied by the datagram;
- the receiver learns the sender's *current* address on every message, which is
  what makes NAT roaming work.

None of those hold for a stream. So the seam is defined in terms of
**messages**, not bytes: a `Carrier` always hands its caller exactly one whole
protocol message, and owns whatever framing is needed to achieve that.

## The trait

```rust
pub trait Carrier: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn preserves_boundaries(&self) -> bool;
    fn supports_roaming(&self) -> bool { self.preserves_boundaries() }
    fn send(&self, data: &[u8], peer: SocketAddr) -> BoxFuture<'_, io::Result<()>>;
    fn recv(&self) -> BoxFuture<'_, io::Result<(Bytes, SocketAddr)>>;
    fn box_clone(&self) -> Box<dyn Carrier>;
}
```

Sends take `&self` so one carrier can be shared: the server's socket is used by
every session concurrently, which is why the tunnel holds an
`Arc<dyn Carrier>` rather than an owned handle. `recv` also takes `&self` for
the same reason; the UDP implementation is lock-free and the TCP one puts its
read half behind a `Mutex`, uncontended in practice because a session has one
receive task.

Methods return `Pin<Box<dyn Future>>` rather than being `async fn`, which keeps
the trait object-safe without pulling in `async-trait`.

## Datagram vs stream

`preserves_boundaries` is the method the rest of the design hangs off.

| | `udp` | `tcp` |
|---|---|---|
| boundaries | the datagram | a 2-byte big-endian length prefix (`STREAM_LEN_PREFIX`) |
| roaming | yes | no — the connection is pinned |
| many sessions per socket | yes | no — one connection *is* one session |
| header bytes on the wire | none | 2 per message |
| head-of-line blocking | none | yes, per connection |

The protocol never learns which it got. That is deliberate: it is what stops
`FrameCodec` from having to invent a length field of its own, and it is why
`v1-fixed` — whose header carries no length — works unchanged over a stream.

### Roaming is a behavioural difference, not an optimisation

Only a datagram carrier can move mid-session. `supports_roaming` says so, and
the tunnel consults it before accepting a source-address change: over a stream a
frame whose source address differs from the pinned peer did not arrive on this
session's carrier at all, so repointing the session at that address would leave
it sending into a black hole. That path now logs and leaves the address alone.

## The listener side

A server needs an *accept* side, and the two shapes differ in a way that
matters:

- a **datagram** listener yields more datagrams from one socket, forever;
- a **stream** listener yields a **new connection** per client.

`CarrierListener` unifies both into one `Inbound` stream, so the server's
`select!` has a single arm:

```rust
pub enum Inbound {
    Datagram  { data: Bytes, from: SocketAddr },
    Connection { carrier: Arc<dyn Carrier>, from: SocketAddr },
}
```

`CarrierListener::sender()` returns the shared socket for a datagram server
(`None` for a stream server, where a session answers on its own connection).
The server dispatches on the two variants:

- `dispatch_datagram` — the full four-step routing: peek by `SessionId`, then a
  rate-limited handshake probe, then the `addr_index` fallback, else drop as
  scan noise.
- `dispatch_connection` — no peek and no fallback are possible, because the
  connection *is* the session. It reads one message and requires it to be a
  valid message 1.

## Configuration

```toml
[carrier]
name = "udp"   # or "tcp"
```

**This is config-pinned, not negotiated, and it cannot be.** The negotiation
travels over the carrier, so there is no channel left to agree on it. Both peers
must name the same carrier.

An unknown name is a hard error. The alternative — a server listening on UDP
while its clients dial TCP — is a deployment where nothing ever connects and
nothing says why.

### Diagnosing a mismatch

A mismatch surfaces as a failed handshake, which is not a great diagnostic. The
client advertises its carrier name in the message-1 offer (behind
`[handshake] propose`, the same opt-in as every other capability), and the
server compares it, so a fleet with `propose = true` gets an explicit
"carrier mismatch" naming both sides instead of a silent timeout. Without
`propose` there is nothing to compare against, so it can only time out.

## Adding a carrier

Implement `Carrier` and `CarrierListener`, then register the name in
`KNOWN_CARRIERS` and the two `match`es in `bind_carrier_listener` /
`connect_carrier`. If the new carrier cannot carry arbitrary peers over one
socket, it returns `preserves_boundaries() == false` and the server's
`dispatch_connection` path handles it — no change to the tunnel.

Two things a new implementation must get right:

- **`send` must not silently truncate.** The TCP carrier returns
  `InvalidInput` for a message over `STREAM_MAX_MESSAGE` rather than casting
  the length to `u16`, which would desynchronise the stream permanently.
- **`recv` must not yield a partial message.** A stream carrier is responsible
  for reassembly; `read_message` loops until `take_message` yields a whole
  frame.
