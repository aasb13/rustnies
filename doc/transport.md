# Transport abstraction

The raw packet (header + AEAD ciphertext) is never sent directly on the wire.
It passes through a `Transport` layer that `wrap`s it into the bytes that
actually go on UDP and `unwrap`s incoming bytes back into the plaintext frame.
This is the swappable seam for the on-the-wire envelope shape. Stackable,
composable obfuscation transforms (padding, timing, header whitening) plug in
*on top of* the transport via the `ObfuscationLayer` stack — see
[obfuscation.md](obfuscation.md); the `Transport` seam itself is reserved for
envelope-level / full-protocol mimicry (e.g. TLS/JA3 fronting), still future
work.

All transport code is in `src/transport/mod.rs`.

## The trait

```rust
pub trait Transport: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn wrap(&self, frame: &[u8]) -> Vec<u8>;
    fn unwrap(&self, datagram: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn boxed_clone(&self) -> Box<dyn Transport>;
}
```

- `wrap` takes the *plaintext frame* produced by `protocol::codec` (the bytes
  `header || ciphertext`) and returns the bytes to transmit on the UDP socket.
- `unwrap` is the inverse: it takes the raw bytes received from the socket and
  returns the plaintext frame for `protocol::codec::decode`.
- `boxed_clone` lets a transport be held behind a trait object and duplicated
  across tasks (the handshake and tunnel each need their own copy).

### Design constraints

Transports are **stateless per-datagram transforms** by design:

- They are cheap and allocation-light.
- They may **not** touch the socket, TUN, or session state.
- They do not reorder or coalesce across datagrams. Any stateful shaping
  (reordering, coalescing, pacing to a mimicry profile) belongs in a higher
  layer that wraps the `Transport` or sits above it.

Keeping the trait this narrow makes implementations trivial to reason about and
audit, and makes the abstraction real rather than a leaky placeholder.

## Error model

`TransportError` has two variants:

- `UnwrapFailed` -> the incoming bytes do not match the expected shape (e.g. an
  obfuscation transform rejecting foreign traffic that does not carry its tag).
- `TooLarge(n)` -> the transport output exceeded a size bound.

`wrap` is expected to be infallible for well-formed inputs. On the receive
path, a `TransportError` causes the tunnel to drop the datagram silently (it is
either foreign traffic or a corrupted frame).

## Provided implementations

### `PlainTransport`

Identity transform: `wrap` returns the frame verbatim, `unwrap` returns the
datagram verbatim. This is the **phase 1 default** and the reference for any
future transport.

```rust
pub fn default_transport() -> Box<dyn Transport> {
    Box::new(PlainTransport)
}
```

### `TaggedTransport`

Prepends a fixed 2-byte tag before every wrapped datagram and requires it on
unwrap. It exists primarily to prove the abstraction is real and as a skeleton
for obfuscation work:

```rust
pub struct TaggedTransport {
    pub tag: [u8; 2],
}
```

A real obfuscation strategy would replace the tag with whatever
detection-evasion transform is desired, without touching the rest of the
pipeline.

## How obfuscation plugs in

Stackable transforms (size padding, timing jitter, header whitening) plug in
*above* the transport as `ObfuscationLayer`s composed in an `ObfuscationStack`,
selected from the `[obfuscation]` TOML section. See
[obfuscation.md](obfuscation.md).

For an envelope-level / full-protocol mimicry transform that changes the raw
datagram shape (e.g. TLS/JA3 fronting) — still future work — the `Transport`
trait is the seam. Because it is the only boundary between the protocol/crypto
pipeline and the raw UDP bytes, adding such a transport looks like:

1. Implement `Transport` for a new type (e.g. `TlsFrontTransport`,
   `MimicryTransport`).
2. Construct it wherever `default_transport()` is called today (the daemon's
   client/server paths and the handshake driver).
3. Nothing else changes: the protocol header, AEAD, FEC, congestion, and TUN
   layers are oblivious to the on-the-wire shape.

The `Transport` can also be selected at runtime (e.g. from config) since it is
a `Box<dyn Transport>`; the daemon just needs to build the right one and pass
it into the handshake and tunnel constructors.

## Relationship to the `ObfuscationLayer` stack

`Transport` is a single, non-composable object. For **stackable, composable**
transforms (size padding, timing jitter, header whitening, and eventually full
protocol mimicry), the [`obfuscation`](obfuscation.md) module provides a
separate `ObfuscationLayer` trait that sits *on top of* the transport. The
stack is applied before `Transport::wrap` on send and reversed after
`Transport::unwrap` on receive. This keeps the `Transport` trait narrow while
allowing deployments to mix and match obfuscation transforms from config
without code changes. See [`obfuscation.md`](obfuscation.md) for details.
