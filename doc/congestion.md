# Congestion control

rustnies ships a small, TCP-inspired congestion controller that responds to
live RTT and loss measurements. It is a building block, not a high-performance
design: phase 1 wants correct, well-behaved control, and a BBR-style controller
can slot in later by replacing `CongestionController`.

All congestion logic is in `src/congestion/mod.rs` and is independent of the
protocol, crypto, FEC, and platform layers.

## Design: bytes, not packets

The window is tracked in **bytes**, not packets. A packet-counting window
cannot tell a 1400-byte bulk datagram from a 64-byte ping reply, so a window
of "4 packets" is anywhere between ~300 B and ~5 KB of actual in-flight data
depending on the workload. Every derived quantity (pacing rate, drop decision)
then inherits that error. Accounting in bytes makes the window a real
bandwidth-delay product and lets the pacer be expressed in bytes/second, which
is the only way to keep a lossy link from being flooded by a burst of
back-to-back datagrams.

## State

```rust
pub struct CongestionController {
    pub cwnd: u64,         // congestion window, in bytes
    pub ssthresh: u64,     // slow-start threshold, in bytes
    pub in_flight: u64,    // outstanding unacked bytes
    pub srtt: Duration,    // smoothed RTT (Karn/Allman EWMA)
    pub rttvar: Duration,  // smoothed RTT variance (Jacobson)
    pub rto: Duration,     // retransmission timeout
    pub last_loss: f64,    // last measured loss ratio (for stats)
    pub pacing_rate: f64,  // bytes/second (cwnd / srtt, floored and capped)
    pub mtu: u32,          // MTU for packet-count estimates
}
```

Constants:

- `MIN_CWND_BYTES = 2 * 1300` (two full-size datagrams).
- `INITIAL_CWND_BYTES = 10 * 1300` (RFC 6928 IW10, expressed in bytes).
- `INITIAL_SSTHRESH_BYTES = 64 * 1300`.
- `DEFAULT_MTU = 1400`.
- `INITIAL_PACING_RATE = 125_000` bytes/s (~1 Mbit/s, conservative).
- `MIN_PACING_RATE = 8_000` bytes/s (one-packet-at-a-time trickle floor).
- `MAX_PACING_RATE = 625_000_000` bytes/s (5 Gbit/s cap).
- `INITIAL_RTT_MS = 100` (default SRTT fallback before the first sample).

## Send gating

`may_send(len)` is the admission test for a packet of `len` bytes. It checks
**both** the congestion window and the pacer:

1. **Window check**: `len <= cwnd - in_flight`. Fails if the byte window is
   exhausted.
2. **Pacer check**: if `next_send_at` is in the future, the packet is not
   admitted yet — the caller should wait (`pacing_delay` tells it for how
   long) rather than drop.

When the window is exhausted, the tunnel **drops** the best-effort data packet
and counts it in `tx_dropped_congestion` (visible in `rustnies status`).
Sleeping instead would block the whole event loop — no UDP RX, no acks, no
pings — for the sleep on every over-window packet, turning mild congestion
into second-scale RTT spikes and burst loss. Dropping keeps latency bounded;
TCP/IP above retransmits if the payload mattered.

When the window has room but the pacer does not, the tunnel **parks** the
packet until `next_send_deadline()` and waits — rate limiting becomes delay,
not loss. This is what prevents a burst of back-to-back TUN reads from being
dumped into the path at once, which is what turns a mildly lossy link into
visible packet loss once an upstream queue overflows.

### FEC parity accounting

FEC parity packets are bulk wire traffic like data and must consume
congestion-control budget: `flush_fec_group` sends each parity through
`try_send_parity(len)`, which checks the window budget and, when there is
room, reserves the bytes *and* advances the pacer's schedule so the next data
packet is delayed by the parity's airtime. Total wire traffic (data + parity)
is therefore what the pacer paces. A full window **skips** the parity (counted
in `tx_dropped_congestion`) — parity is expendable redundancy and its data
already went out — but pacer debt alone never refuses parity, so FEC is not
disabled exactly when the path is busy. Without this, the window accounted for
only `k/(k+m)` of the real load (with the default `k=1, m=2..4`, the wire rate
is 3–5x the paced rate) and each group left as an unpaced micro-burst.

### Pacer mechanics

- The pacing rate is `cwnd / srtt` (the bandwidth that drains one window per
  RTT), clamped to `[MIN_PACING_RATE, MAX_PACING_RATE]`.
- Each admitted packet advances `next_send_at` by `len / rate` seconds.
- **Debt cap**: if the pacer has fallen more than one SRTT behind (e.g. the
  window was closed and nothing was admitted), the debt is not paid off in one
  go — the schedule restarts from now. Without this, an idle period followed by
  a burst would be throttled for the full accumulated debt.
- **Idle reset**: `reset_pacer()` clears `next_send_at` when the sender has
  been idle (nothing in flight, nothing parked), so the next packet leaves
  immediately.

## Slot lifetime (in-flight accounting)

Slot lifetime is owned by ack resolution, not by loss:

- `on_send_bytes(len)` reserves `len` bytes in flight.
- `on_ack_bytes(bytes)` releases acked bytes **and** grows the window.
- `release(bytes)` releases bytes without growing the window — used for seqs
  the peer's ack anchor jumped over (holes = lost on the wire). Growing cwnd
  on loss would be wrong; releasing the bytes is still required so the budget
  does not leak to zero on a lossy link and stall the sender forever.

`on_loss` adjusts the window **only** and never touches `in_flight`: its
signals come from inbound FEC recovery/eviction on the *receiver* side, which
has no 1:1 relationship with this side's outstanding sends — releasing
outbound slots for inbound loss would corrupt the budget accounting and could
double-release slots the ack path already freed.

## Acknowledgement

### Window growth

`on_ack_bytes(bytes)` releases `bytes` from `in_flight` and grows the window:

- If `cwnd < ssthresh`: **slow start** → `cwnd += bytes` (one byte per byte
  acked, doubling per RTT at the packet level).
- Else: **congestion avoidance** → `cwnd += bytes * mss / cwnd` (≈ +1 MSS per
  RTT).

### RTT sampling on data acks

`on_ack_with_rtt(bytes, sample)` is the single most important feedback path.
Before it existed, the **only** RTT samples came from the 500 ms Ping/Pong
probe, so a burst of data had no way to enlarge the window until the next ping
tick — the window stayed pinned at its initial value regardless of how fast the
path actually was. Data acks now fold in a fresh RTT sample, which both grows
the window through real feedback and re-derives the pacing rate.

## Loss

`on_loss(lost, total)` records the loss ratio `lost / total` into `last_loss`
and triggers **loss-proportional multiplicative decrease**:

```
factor    = clamp(1 - ratio * 0.5, 0.5, 0.875)
cwnd      = cwnd * factor
ssthresh   = cwnd   (after reduction, clamped to MIN_CWND_BYTES)
```

A pure halving per loss event over-reacts when a single packet is lost out of
a large batch (the common case on a link with a couple percent of ambient
loss): the window collapses, throughput dies, and recovery from a low cwnd is
slow. Scaling the reduction by how bad the loss actually was keeps a one-off
loss cheap while still backing off hard on sustained loss.

In the tunnel, loss signals come from two places:

1. FEC recovery: when a group is decoded and some source symbols were
   recovered (i.e. they were lost in transit), the recovered count is fed to
   **both** `AdaptiveFec::observe_unrecoverable` (to increase redundancy) and
   `CongestionController::on_loss` (to back off). FEC hides the loss from the
   user — the packet was delivered — but it does not erase the loss from the
   wire. Feeding recovery as loss is what breaks the runaway loop that
   previously pinned loss at 100%: without it, the sender kept flooding a lossy
   link, produced more loss, ramped parity to its 2000% ceiling, flooded the
   link further, and never recovered.
2. Unrecoverable loss: groups that expire without being decoded are fed to
   `on_loss` by the eviction logic as well, so the window backs off when loss
   exceeds the current FEC capacity.

## RTT estimation

`on_rtt_sample(rtt)` applies the classic Jacobson/Karels update with nanosecond
resolution:

```
diff     = |srtt - rtt|
rttvar   = (3/4) * rttvar + (1/4) * diff
srtt     = (7/8) * srtt  + (1/8) * rtt
rto      = max(srtt + max(1ms, 4*rttvar), 1ms)
```

The RTO is used by the tunnel's reliable-control retransmission loop: every
50 ms (`RTO_TICK`), unacked reliable control packets whose `rto` has elapsed
are retransmitted.

### RTT measurement via Ping/Pong

The tunnel sends a `Ping` every 500 ms carrying a 12-byte body:
`ping_seq (u32 LE) || unix_timestamp_micros (u64 LE)`. The peer echoes it back
as a `Pong`. On receiving a `Pong`, the tunnel computes
`rtt = now - timestamp_micros` and feeds it to `on_rtt_sample`. The smoothed
RTT is also published to the live stats (`rtt_ms`). Data-ack RTT samples
(both Ping/Pong and `on_ack_with_rtt`) feed the same estimator.

## Published stats

The congestion window (`cwnd`), in-flight bytes, smoothed RTT, and current
pacing rate are all published in the live stats (`rustnies status`):

```
congestion_window   — current cwnd in packets (cwnd / mtu)
in_flight           — outstanding unacked bytes
rtt_ms              — smoothed RTT in milliseconds
```

## What the controller does NOT do in phase 1

- No BBR-style bandwidth estimation.
- No ECN feedback (UDP gives us no congestion signal besides loss/RTT).
- No per-packet retransmission of *data* (data is best-effort; FEC handles
  erasures, unrecoverable groups are lost). Only reliable *control* packets are
  retransmitted on RTO.
