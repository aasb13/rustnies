# Obfuscation layers

The `obfuscation` module provides **stackable, composable traffic-obfuscation
transforms** applied on top of the `Transport` layer. It is a *separate*
abstraction from [`Transport`](transport.md): `Transport` handles
wrap/unwrap semantics (the low-level envelope framing), while
`ObfuscationLayer` is an optional, ordered, stackable pipeline of transforms
applied to the packet buffer before it reaches the transport.

## Where this fits

```
send:    frame -> [L0.apply -> L1.apply -> ... -> Ln.apply] -> Transport::wrap -> wire
recv:    wire  -> Transport::unwrap -> [Ln.reverse -> ... -> L1.reverse -> L0.reverse] -> frame
```

- `Transport` is a single object with `wrap`/`unwrap`; it is **not** composable
  by itself.
- `ObfuscationLayer` is a distinct, stackable, ordered transform. Each layer
  is a pure function on a packet buffer (`apply` / `reverse`). Layers compose in
  an `ObfuscationStack`: on send they apply in order, on receive they reverse
  in **reverse** order, so the stack is a symmetric pipeline.
- The stack is **off by default**. No layer is active unless explicitly
  configured in the `[obfuscation]` section of the TOML config.

## The trait

```rust
pub trait ObfuscationLayer: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn apply(&self, frame: &[u8]) -> Vec<u8>;
    fn reverse(&self, buf: &[u8]) -> Result<Vec<u8>, ObfuscationError>;
    fn init(&self, _session_seed: &[u8; 32]) {}
    fn boxed_clone(&self) -> Box<dyn ObfuscationLayer>;
}
```

- `apply` is the send-side transform: takes the plaintext frame
  (`header || ciphertext`) and returns bytes for `Transport::wrap`.
- `reverse` is the exact inverse: takes the output of `Transport::unwrap` and
  returns the original frame.
- `init` seeds per-session keying material (from the Noise handshake hash);
  layers that don't need keying use the default no-op.
- `boxed_clone` lets a layer be held behind a trait object and duplicated across
  tasks (the handshake and tunnel each need their own stack copy).

Layers must be **deterministic inverses**: `layer.reverse(layer.apply(f)) == Ok(f)`.

## The stack

`ObfuscationStack` holds an ordered `Vec<Box<dyn ObfuscationLayer>>`. An empty
stack is the identity transform (allocation-free). When active, `apply` runs
each layer in order; `reverse` runs them in reverse order.

The stack is `Clone` (via `boxed_clone`) and `Send + Sync`, so the daemon can
build one shared stack from config, clone it per session, seed it with the
session's handshake hash via `init`, and hand it to the tunnel.

## Configuration

The `[obfuscation]` TOML section:

```toml
[obfuscation]
# Ordered list of layer names, applied in order on send, reversed on receive.
# Empty (or omitted entirely) means no obfuscation (the default).
layers = ["padding", "header_xor"]

# [padding] parameters
padding_buckets = [64, 128, 256, 512, 1024, 1500]  # output sizes (incl. 2B prefix)
padding_max = 1500                                   # hard cap on output size

# [timing] parameters
timing_max_jitter_us = 2000      # 0-2ms random send delay
timing_decoy_interval_ms = 200  # emit a decoy every ~200ms when idle
timing_decoy_max_len = 256       # decoy payload length cap
```

Unknown layer names are logged at `warn` and skipped, so a typo never prevents
the tunnel from coming up. The recognised names are:

| Name         | Layer                                                 | Purpose                                           |
|--------------|-------------------------------------------------------|---------------------------------------------------|
| `"padding"`  | `obfuscation::padding::SizePadding`                   | Pad to configurable bucket sizes (size hiding)    |
| `"timing"`   | `obfuscation::timing::TimingJitter`                  | Random send jitter + idle decoy packets           |
| `"header_xor"` | `obfuscation::header_xor::HeaderXor`                | XOR-whiten fixed header bytes per session         |

## Provided layers

### `SizePadding` (`"padding"`)

Pads each frame up to the smallest configured bucket size, prefixed by a 2-byte
big-endian length of the original frame. The pad bytes are zero. `reverse`
reads the length prefix and strips the padding. The bucketing is what defeats
size-based traffic analysis: the on-wire size becomes one of a small set of
bucket sizes rather than a continuous distribution.

Stateless and deterministic. Frames larger than the largest bucket are sent
unpadded (length-prefixed only) so they are never dropped.

### `TimingJitter` (`"timing"`)

This layer does **not modify bytes** (`apply`/`reverse` are identities). Its
value is in two advisory methods the tunnel consults:

- `next_send_delay()`: returns a randomised `Duration` in `[0, max_jitter]`
  for the tunnel to `tokio::time::sleep` before each `send_to`.
- `should_emit_decoy()`: returns true when at least `decoy_interval` has
  elapsed since the last send; the tunnel then sends a `decoy_frame()` — a
  real-shaped protocol frame with the reserved sentinel version byte
  `0x7F` — which the receiver's `handle_udp_datagram` recognises and drops
  before any crypto work.

Keeping the layer I/O-free means it composes like every other layer and the
stack stays cheap to test. The tunnel's send loop already owns the socket and
timers, so it is the natural place to apply the advised delays.

### `HeaderXor` (`"header_xor"`)

The protocol header has constant bytes at fixed offsets (e.g. `version = 0x01`
at offset 0, `packet_type` discriminants at offset 1). This layer XORs a
per-session-derived 24-byte keystream over the first `HEADER_LEN` bytes of
every frame, so there is no constant byte pattern at a fixed offset across
sessions.

The keystream is derived via HKDF-SHA256 from the Noise handshake hash (seeded
by `init` after the handshake). Both peers derive the same keystream
independently. XOR is its own inverse, so `reverse` is identical to `apply`.

**Handshake safety**: frames shorter than `HEADER_LEN` (handshake messages)
are passed through unchanged. Before `init` is called, the keystream is
all-zero and the layer is an identity. This means the layer is a no-op during
the handshake (no keystream yet) and activates for steady-state frames after
both peers have `init`ed with the same handshake hash.

**Integrity**: the AEAD tag still authenticates the original header (as AAD),
so a tampered whitened header that survives XOR produces an invalid AAD on
decrypt and is rejected by the crypto layer. This layer does not weaken
integrity.

## Future: protocol mimicry

The trait shape does not preclude a future, heavier mimicry layer (e.g.
TLS/JA3 impersonation). Such a layer would implement `ObfuscationLayer` with an
`apply` that produces a byte stream mimicking the target protocol's record
structure, and a `reverse` that parses it back. It slots into the stack
alongside the other layers without touching the protocol, crypto, FEC, or TUN
code. The only requirement is the deterministic-inverse contract.

## How the daemon wires it

1. The daemon builds an `ObfuscationStack` from the `[obfuscation]` config via
   `obfuscation::build_shared_stack`.
2. The stack (as `&ObfuscationStack`) is passed to the handshake, which applies
   / reverses it on handshake messages.
3. After the handshake, the daemon clones the stack, calls `init` with the
   handshake hash to seed any keying-based layers, and passes the initialised
   stack to `Tunnel::from_handshake`.
4. The tunnel uses `wrap_frame` / `unwrap_frame` helpers that apply the stack
   before `Transport::wrap` and reverse it after `Transport::unwrap`. When the
   stack is empty, these are allocation-free identities.

All code is in `src/obfuscation/`.