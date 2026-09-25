# Forward error correction

rustnies applies **systematic Reed-Solomon** erasure coding over GF(256) to
tunneled data, with an **adaptive controller** that scales redundancy up and
down with measured packet loss. All FEC logic lives in `src/fec/` and is
decoupled from the protocol, crypto, and transport layers: FEC only knows about
groups of symbols and their indices.

## Why Reed-Solomon

Reed-Solomon over GF(256) is an MDS (maximum distance separable) erasure code:
from an `n = k + m` group, **any** `k` surviving symbols suffice to recover all
`k` sources, regardless of *which* symbols survived. This is the same family of
codes used in QR codes, optical media, and distributed storage. It is the right
choice when erasures (not errors) are the failure mode and the erasure
positions are known, which is exactly the UDP tunnel case: each packet carries
its `fec_group` and `fec_index` in the header, so the receiver knows which
slots in a group are missing.

## GF(256) arithmetic

`src/fec/gf256.rs` implements the field with the standard irreducible polynomial
`0x11d` (`x^8 + x^4 + x^3 + x^2 + 1`) and generator `alpha = 2`. Precomputed
log/exp tables (`exp[512]`, `log[256]`) make `mul`/`div`/`inv` constant-time
table lookups. The `exp` table is 512 entries so indexing never needs masking
on the hot path (`exp[i + 255] == exp[i]`).

`solve_system(rows, n)` performs in-place Gaussian elimination with partial
pivoting over GF(256), used by the decoder.

## Reed-Solomon code

`src/fec/reed_solomon.rs` builds a systematic `(k, m)` code.

### Generator construction

1. Build the `n x k` Vandermonde matrix `V` with `V[i][j] = alpha^(i*j)`.
   Vandermonde with distinct evaluation points `alpha^0 .. alpha^(n-1)` is
   full-rank and MDS.
2. Compute `V_top^{-1}` (the inverse of the top `k x k` block) by solving
   `V_top * X = I` column-by-column via `gf256::solve_system`.
3. The systematic generator is `G = V * V_top^{-1}`. The top `k` rows of `G`
   are the identity (so the first `k` codeword symbols are the sources
   verbatim); the remaining `m` rows are the parity generator.

`G` is stored as `Vec<Vec<u8>>` and reused across groups until the adaptive
controller changes `k`/`m`.

### Encoding

`encode(sources)` takes `k` equal-length source symbols and produces `m` parity
symbols. For each parity row `i` (in `k..n`), parity byte `b` is:

```
parity[b] = XOR over j in 0..k of G[i][j] * sources[j][b]
```

(`mul` is GF(256) multiplication.) Symbols within a group must be padded to a
common length; the tunnel pads shorter packets with zeros. The receiver trims
recovered sources to the real IP packet length (carried in the TUN packet
itself).

### Decoding

`decode(symbols)` takes `n` slots, each `Option<Vec<u8>>` (`None` = erased).
The receiver knows erasure positions from the `fec_index` header field, so
decoding is by linear-system solving, not Berlekamp-Massey:

1. If no source symbols are erased, return them directly.
2. Collect surviving parity rows as equations. For each, subtract the
   contributions of already-known source symbols from the parity bytes,
   leaving an equation in only the erased unknowns.
3. Solve the resulting `u x u` system (`u = number of erased sources`) over
   GF(256) byte-by-byte. The coefficient matrix is identical across bytes, so
   only the right-hand side changes per byte position.
4. If fewer than `u` parity rows survived, the group is unrecoverable
   (`FecError::Insufficient`); those packets are lost. If the system is
   singular, `FecError::Singular`.

MDS guarantee: as long as at least `k` symbols out of `n` survive, recovery
succeeds.

### Limits

`k + m <= 255` (GF(256) symbol alphabet). The adaptive controller's defaults
(`k = 1`, `min_m = 1`, `max_m = 4`) stay well within this.

## Adaptive controller

`src/fec/adaptive.rs` defines `AdaptiveFec`, the *only* component that decides
FEC parameters. Future smarter controllers can replace it.

### State

- `k`: source symbols per group (constant by default; held so group formation
  delay stays predictable).
- `min_m`, `max_m`: parity bounds. `min_m` is the *floor the controller can
  reach on a clean link* (default 1), not a permanent minimum: it is reached
  only after the EMA smoothed loss falls below the lowest `down` band.
- `up`: loss-ratio thresholds (fractions in `[0,1]`). When the smoothed loss
  exceeds `up[i]`, use at least `i+1` parities.
- `down`: decrease thresholds; `down[i] = up[i] * 0.6` (hysteresis).
- `current_m`: current parity count. **Starts at `initial_m` (default 2)**, not
  at the floor, so the first packets carry burst protection before enough loss
  samples exist. It relaxes toward `min_m` on a clean link and ramps toward
  `max_m` once observed loss crosses a response band.
- `smoothed_loss`: EMA-smoothed loss ratio.
- `ema_alpha`: EMA smoothing factor (default `0.25`).

### Defaults (`default_for_vpn`)

```
k          = 1
min_m      = 1
max_m      = 4
current_m  = 2        (initial_m: starting redundancy, not the floor)
ema_alpha  = 0.25
up         = [0.05, 0.12, 0.22, 0.35]
down       = up[i] * 0.6
```

`k = 1` is the critical choice: every packet is its own complete FEC
group, so there are **no partial groups** and **no group-formation
latency**. This matters for sparse traffic (ICMP pings at 1 pkt/s) and
bursty traffic alike — every packet gets `m` parity copies immediately.

`min_m` defaults to **1, not 2**. With `k = 1` and `m = 1` a clean link
pays only 100% overhead (each packet + one parity twin; residual loss `p²`),
and the controller relaxes to this floor once the smoothed loss stays below
`down[0]` = 0.03. The trade-off: a 2-datagram *burst* loss (data + its
single parity twin, emitted back-to-back) is unrecoverable at `m = 1`. That
is acceptable because the controller detects the resulting unrecoverable
group and ramps `m` back to 2 (residual loss `p³`) within a handful of
packets — bursty links are re-protected almost immediately, while genuinely
clean links (the common case for a steady VPN uplink) stop paying the
permanent 200% tax. The old `min_m = 2` floor forced 3x bandwidth on *every*
link regardless of measured loss, which saturated thin uplinks and caused the
bufferbloat that made interactive browsing unusable.

`current_m` starts at **2** (`initial_m`) so the tunnel's very first packets
still get burst protection before any loss samples exist; the EMA then earns
its way down to `min_m` on a calm link. Note `min_m` must stay >= 1: with
`m = 0` no RX FEC group is ever recorded, so a lost packet produces no
recovery/eviction signal and the controller could never learn to ramp back up.

With `max_m = 4`, the code tolerates up to ~80% underlying packet loss
(any 1 of 5 symbols survives) at a bounded 400% overhead. A larger ceiling
(the previous `max_m = 20`) could amplify a modest real loss into 2000%
overhead, which saturated the link and produced *more* loss. Because the
loss input is now true wire-loss fed from FEC recovery and unrecoverable
group eviction, these thresholds see real loss rather than an artifact of
a stuck ack window. The EMA (`alpha = 0.25`) reacts quickly so a sudden
loss spike ramps redundancy within a handful of packets.

These defaults are overridable via the `[fec]` TOML section (see
`doc/daemon.md` or the config template).

### Policy (`observe(loss)`)

1. Update the smoothed loss: `s = s*(1-a) + loss*a`.
2. **Increase**: scan all `up` bands and set `current_m` to the highest band
   whose threshold is crossed (so a single large loss sample can jump straight
   to the right redundancy level, not just step by one).
3. **Decrease**: scan bands downward and reduce `current_m` to the lowest band
   whose `down` threshold the smoothed loss is below.
4. If the smoothed loss is below the lowest band's `down` threshold, drop all
   the way to `min_m` (the decrease loop alone can only reach band 1, not 0).
5. Clamp to `[min_m, max_m]`.
6. Ensure `k + m <= 255`.

Hysteresis (the `down` band being 60% of the `up` band) prevents the parity
count from oscillating when the loss hovers near a threshold.

`params()` returns the current `FecParams { k, m }` without mutating state.
The tunnel initialises the controller at `initial_m` (2) and only relaxes
toward `min_m` (1) as zero-loss samples arrive — it does **not** call
`observe(0.0)` at startup, which would snap `current_m` straight to the floor
and discard the burst protection on the first packets.

## Group lifecycle

The tunnel (`src/tunnel/mod.rs`) drives FEC groups:

### TX

- Each outgoing `Data` packet is assigned to the current group: `fec_group` =
  the current group id, `fec_index` = the position within the group (0-based),
  `fec_k`/`fec_m` advertise the group shape to the receiver.
- The plaintext packet is accumulated into `group_buffer`.
- When `group_index` reaches `k`, `flush_fec_group()` encodes `m` parity
  symbols and transmits them as `Fec` packets (with `fec_index` in `k..n`),
  then increments the group id and resets the buffer.
- A 100 ms tick flushes any partial group so a half-filled group is not held
  indefinitely at low traffic rates. A **partial** flush transmits no
  parities (see below); the real `Data` packets were already sent and
  delivered directly.

### Partial groups

When a group is flushed with fewer than `k` real packets (early flush at the
100 ms tick), the sender emits **no parity symbols** for it. The real `Data`
packets were already transmitted and delivered directly, so the peer has
them; the only thing parities would add is recoverability for a lost `Data`
in the partial group. That protection is deliberately forfeited because the
alternative — padding the missing source slots with zero placeholders and
encoding parities over them — would let the peer decode the placeholder
slots and write the (zero-filled) reconstructed symbols to its TUN as
duplicate/garbage packets. The receiver cannot distinguish a recovered
placeholder from recovered real data, so partial groups are sent without FEC
redundancy.

**With the default `k = 1`, partial groups are eliminated**: every packet
fills its group immediately, so the early-flush tick never finds a partial
group. Every packet gets `m` parity copies regardless of traffic rate. This
is why `k = 1` is the right default for a VPN that must survive unstable
links — sparse traffic (pings, DNS queries) gets the same FEC protection as
bulk transfers.

### RX

- Each `Data`/`Fec` packet is recorded into `rx_groups[group]` at its
  `fec_index`. `Data` packets are delivered to the TUN immediately and marked
  delivered in the group; `Fec` packets fill parity slots.
- Before delivering a `Data` packet, the receiver checks the group's
  `delivered` bitmap: if that source slot was already written to TUN (directly
  or by a prior FEC recovery), the packet is a late/duplicate original and the
  TUN write is suppressed. This dedup is what makes FEC recovery safe against
  out-of-order or duplicated UDP delivery.
- When a group has at least `k` surviving symbols and has not already been
  decoded, `recover_group()` runs Reed-Solomon decode. Newly recovered source
  symbols (those not already delivered directly) are written to the TUN,
  `fec_recovered` is bumped, and the recovered-symbol count is fed to both
  `AdaptiveFec::observe_unrecoverable` (to increase redundancy) and the
  congestion controller's `on_loss` (to back off). FEC recovery hides the
  loss from the user — the packet *was* delivered — but it does not erase
  the loss from the wire. Feeding it to the congestion controller is what
  breaks the runaway loop that previously pinned loss at 100%: without it,
  the sender kept flooding a lossy link, produced more loss, ramped parity
  to its 2000% ceiling, flooded the link further, and never recovered. The
  controller now shrinks the window on real loss, stops flooding, and the
  measured loss rate falls, which lets the FEC controller scale redundancy
  back down.
- A successfully decoded group is **not** removed immediately. It is marked
  `decoded` with every source slot flagged delivered, and retained until
  `RX_GROUP_TTL = 5 s` so it keeps acting as the dedup set for any originals
  that arrive after being reconstructed from parity. No further recovery is
  attempted on a decoded group.
- RX groups are evicted after `RX_GROUP_TTL = 5 s` to bound memory. When a
  group is evicted **without** having been decoded (too many erasures for
  the current parity count), the undelivered source count is fed to
  `AdaptiveFec::observe_unrecoverable`. This is the only signal that fires
  when loss exceeds the current FEC capacity — without it, the controller
  would never learn that `m` is too low and would never increase
  redundancy. The undelivered source count is also fed to the congestion
  controller's `on_loss` so the window backs off. This closed-loop
  feedback is what lets the tunnel survive bursty packet loss: the FEC
  controller ramps `m` until unrecoverable evictions stop, and the
  congestion controller stops flooding the link in the meantime.
