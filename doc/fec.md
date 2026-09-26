# Forward error correction

rustnies applies **systematic Reed-Solomon** erasure coding over GF(256) to
tunneled data, with an **adaptive controller** that scales redundancy up and
down with measured packet loss. All FEC logic lives in `src/fec/` and is
decoupled from the protocol, crypto, and transport layers: FEC only knows about
groups of symbols and their indices.

## The seam: code vs. parameters

Two independent things are often conflated here, and `rustnies` keeps them
separate on purpose:

- **Which erasure code** — the `FecScheme` trait (`src/fec/mod.rs`), selected by
  `[fec] scheme`. This is **negotiated** in the handshake, because a mismatched
  code would corrupt groups rather than fail cleanly. `reed-solomon` (the
  default) and `none` are implemented; `none` reports itself inactive, which
  pins the controller's `max_m` to zero so no parity is encoded, sent, buffered
  or decoded, and so a stale `max_m` in the config cannot resurrect parity
  against the session's negotiated wishes.
- **How much parity** — `k` / `min_m` / `max_m` / `initial_m` in `[fec]`, owned
  by `AdaptiveFec`. This is a **local sender policy**: both ends read `k` and `m`
  off every packet header, so there is nothing to negotiate, only to obey.

The split is what lets a deployment turn FEC off entirely, or move to a different
code, without touching the loss-feedback loop. See [`profiles.md`](profiles.md).

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
(`k = 1`, `min_m = 0`, `max_m = 4`) stay well within this.

## Adaptive controller

`src/fec/adaptive.rs` defines `AdaptiveFec`, the *only* component that decides
FEC parameters. Future smarter controllers can replace it.

### State

- `k`: source symbols per group (constant by default; held so group formation
  delay stays predictable).
- `min_m`, `max_m`: parity bounds. The default `min_m = 0` lets a clean link
  disable parity after sender-side ACK feedback establishes that it is unneeded.
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
min_m      = 0
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

`min_m` defaults to **0**. A clean link therefore pays no parity overhead
once sender-side ACK outcomes show sustained zero source loss. The controller
starts at `initial_m = 2` for burst protection, then uses 64-source ACK outcome
windows to raise `m` when source loss crosses a response band. This feedback
lives on the original sender, so it still works when the receiver sees no FEC
group at all.

With `max_m = 4`, the code tolerates up to ~80% underlying packet loss
(any 1 of 5 symbols survives) at a bounded 400% overhead. A larger ceiling
(the previous `max_m = 20`) could amplify a modest real loss into 2000%
overhead, which saturated the link and produced *more* loss. The loss input is
a real 64-source population derived from the sender's selective ACK ledger, so
these thresholds see actual source loss rather than a degenerate per-group
`1/1` event. The EMA (`alpha = 0.25`) reacts over completed 64-source windows
as sustained loss crosses a response band.

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
toward `min_m` (0) as zero-loss samples arrive — it does **not** call
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
  symbols are written to the TUN and counted in `fec_recovered`. The receiver
  does not change either local controller here: its congestion window and FEC
  parameters govern the opposite outbound direction. The original sender
  learns that the source sequence was absent from the peer's selective ACK
  window and updates its own congestion and FEC controllers from that feedback.
- A successfully decoded group is **not** removed immediately. It is marked
  `decoded` with every source slot flagged delivered, and retained until
  `RX_GROUP_TTL = 5 s` so it keeps acting as the dedup set for any originals
  that arrive after being reconstructed from parity. No further recovery is
  attempted on a decoded group.
- RX groups are evicted after `RX_GROUP_TTL = 5 s` to bound memory. Sender-side
  ACK accounting, rather than receiver eviction, supplies both recovered and
  completely silent source-group loss to the controller in the sending
  direction.
