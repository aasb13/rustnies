# Testing

rustnies has unit tests (inline `#[cfg(test)]` modules) and an integration test.
All tests pass with zero warnings on a clean build.

```
$ cargo test
test result: ok. 402 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok.  16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Unit tests (inline modules)

### `src/protocol/session.rs`

- `replay_window_basic` — the sliding-window replay filter accepts fresh seqs,
  rejects duplicates, accepts in-window reordering, rejects below-window
  packets, and resets on a large forward jump.
- `ack_tracker_snapshot` — recording seqs advances the sliding-window ack
  anchor and produces a correct `(ack_seq, bitmap)` snapshot for the
  piggybacked ack fields, including gaps.
- `session_peer_acked` — `Session::peer_acked` correctly interprets the peer's
  `ack_seq` + `ack_bitmap` advertisement.

### `src/fec/reed_solomon.rs`

- `encode_then_decode_all_present` — encoding then decoding with no erasures
  returns the original sources.
- `recover_m_erased_data` — erasing two data symbols and one parity (out of a
  `(4, 3)` code) still recovers the originals (MDS: `k` survivors suffice).
- `recover_only_parities_survive` — a `(3, 3)` code where all source slots are
  erased but all three parities survive still recovers the sources.
- `k1_m2_recovers_two_consecutive_losses` — with `k=1, m=2`, a 2-datagram
  burst (data + a parity twin both dropped) is recovered from the surviving
  twin; losing all three remains unrecoverable.

### `src/fec/adaptive.rs`

- `scales_up_and_down` — sustained high loss drives `current_m` up to `max_m`;
  sustained zero loss drives it back down to `min_m`, exercising both the
  increase and decrease paths and the hysteresis floor.

### `src/congestion/mod.rs`

- `slow_start_then_decrease` — acks grow the byte-window in slow start; a loss
  signal triggers loss-proportional multiplicative decrease and sets `ssthresh`.
- `rtt_smooths` — repeated identical RTT samples converge the smoothed RTT and
  produce a sensible RTO (≥ SRTT, ≥ 1 ms floor).
- `rto_never_below_1ms` / `srtt_never_zero` — boundary guards on the RTT
  estimators.
- `send_budget_never_negative` — budget saturates at 0 and never underflows.
- `on_ack_releases_in_flight` / `on_ack_zero_is_noop` — acks release in-flight
  bytes and grow the window; `on_ack(0)` is a no-op.
- `on_loss_shrinks_window_and_sets_ssthresh` — loss halves the window to
  `ssthresh` but **does not** release in-flight slots (slot lifetime is owned
  by the ack-resolution path).
- `on_loss_does_not_go_below_min_cwnd` / `small_loss_is_gentler_than_total_loss`
  — cwnd clamps at `MIN_CWND_BYTES`; a 1% loss is gentler than 100% loss.
- `congestion_avoidance_grows_slower_than_slow_start` /
  `slow_start_doubles_on_batch_ack` — CA adds ~1 MSS/RTT; slow start adds
  1 MSS per acked packet.
- `release_drops_in_flight_without_growing_window` /
  `in_flight_saturating_sub_on_ack` — `release` and excess acks saturate
  in-flight to 0 without underflow.
- `pacer_limits_a_burst_to_the_pacing_rate` — back-to-back packets are rate
  limited by the pacer, not the window.
- `pacing_delay_reports_when_pacing_holds_a_packet` /
  `pacing_delay_is_none_when_window_limited` — `pacing_delay()` returns `Some`
  when pacing is the limit, `None` when the window is the limit.
- `pacing_does_not_refuse_packets_after_an_idle_period` — idle gaps don't
  accumulate unbounded pacer debt.
- `ack_with_rtt_folds_in_a_fresh_sample` — data acks feed the RTT estimator and
  raise the pacing rate (`cwnd / srtt`); no ping tick needed.
- `pacing_rate_tracks_window_over_srtt` — rate is `cwnd / srtt`, clamped to
  `[MIN_PACING_RATE, MAX_PACING_RATE]`.

### `src/crypto/noise.rs`

- `handshake_roundtrip` — a full Noise IK handshake between an initiator and a
  responder produces matching `key_i2r`, `key_r2i`, and `handshake_hash` on
  both sides, and the encrypted payload survives the round trip.

## Integration test

### `src/platform/linux.rs`

- `parse_default_route_iface_*` / `parse_default_gateway_*` — parsing the
  `ip route` output for the egress interface and gateway.
- `parse_route_line_*` / `netmask_to_prefix_*` — route-file line parsing
  (bare IP, CIDR, legacy ip/mask, IPv6, comments) and netmask validation.
- `kill_switch_rules_block_all_except_tunnel_server_lo` — the kill switch
  rules accept loopback/TUN/server-UDP and reject all other direct traffic.
- `kill_switch_fail_closed_stays_active_without_remove` — after a simulated
  drop (no teardown), the rules stay blocking (fail closed); a graceful remove
  restores direct internet.
- `kill_switch_install_is_idempotent` — re-installing does not leave duplicate
  jumps (install twice, remove once fully clears).
- `dns_leak_rules_allow_tun_block_real` — DNS via the TUN is allowed; DNS via
  the real interface is rejected; non-DNS traffic is untouched.
- `dns_and_kill_switch_chains_compose_in_order` — the DNS chain (jumped first)
  handles DNS; the kill switch chain handles everything else.
- `resolv_conf_*` — the resolv.conf swap backs up and restores the original,
  Drop restores, a stale crash backup is preserved, and an empty DNS list is
  rejected.
- `parse_iptables_chain_*` / `extract_dport_*` — parsing live `iptables -L`
  counters for the `dns-check` report (DNS chain + kill switch chain).

### `tests/end_to_end.rs`

- `end_to_end_handshake_and_data` — spins up two loopback UDP sockets, runs the
  server handshake in a task and the client handshake against it, and asserts
  that both sides agree on the session keys and session id. It also touches the
  `LinuxTunFactory` to prove the platform abstraction links. Uses an in-memory
  `MemTun` stub (implementing the `Tun` trait) so no root and no real TUN
  device is required.
- `noise_handshake_keys_match` — a direct Noise IK round trip through the
  tunnel's handshake helper types, asserting key/hash equality and that the
  derived session id is non-zero and that `Session` values can be constructed
  for both roles.
- `handshake_rejected_for_unauthorized_key` / `handshake_open_mode_accepts_all`
  — peer authorization gating.
- `kill_switch_fail_closed_on_real_tunnel_drop` — the headline kill-switch
  test: a real Noise IK session is established over loopback UDP, a `Tunnel::run`
  loop is driven, the server is killed mid-session (its socket is dropped), and
  the test confirms the client detects the drop on its own *and* the kill
  switch keeps blocking direct internet (fail closed) until a graceful
  shutdown removes the rules. A recorded in-memory firewall backend stands in
  for `iptables`, so no root is required.
- `dns_leak_prevention_with_kill_switch_compose` — verifies the combined
  policy the daemon installs (DNS chain before the kill switch chain): DNS can
  only leave via the tunnel, non-DNS direct traffic is blocked, and the server
  stays reachable; teardown clears both.

## What is and is not covered

### Covered

- Replay window correctness (reordering, duplicates, window reset).
- Ack tracker sliding-window anchor + bitmap semantics.
- Reed-Solomon encode/decode with erasures (the MDS recovery property).
- Adaptive FEC scaling up and down with hysteresis.
- Congestion control slow start, multiplicative decrease, RTT smoothing, and
  pacer-based rate limiting.
- Noise IK handshake key agreement (both sides derive identical keys).
- End-to-end handshake over real loopback UDP sockets.
- The platform TUN abstraction compiles and is mockable.
- Kill switch policy (block all non-tunnel except server/lo) and fail-closed
  lifetime across a real simulated tunnel drop.
- DNS leak prevention policy (DNS via TUN allowed, DNS via real blocked) and
  the resolv.conf swap (backup/restore, crash recovery).
- `iptables` counter parsing for the `dns-check` verification command.

### Not covered by automated tests in phase 1

- Real TUN I/O (requires root + a kernel TUN device; exercised manually).
- Real NAT forwarding (requires root + `iptables`; the `NatRules` install/remove
  is exercised manually).
- Real `iptables` rule installation for the kill switch / DNS leak prevention
  (requires root; the *rule logic* and *policy* are verified with a recorded
  backend and `evaluate_packet`, but the actual `iptables` shell-out is not).
- FEC recovery under live packet loss on a real link.
- Multi-client server fan-out (not implemented in phase 1).
- Obfuscation transports (the `Transport` trait is tested via `PlainTransport`
  and `TaggedTransport` compilation; no behaviour to verify yet).

## Running the tests

```sh
cargo test            # all tests
cargo test --lib      # unit tests only
cargo test --test end_to_end   # integration test only
cargo test -- --nocapture      # show println/eprintln output
```

The integration test uses `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`
so the server-side handshake task and the client-side handshake run
concurrently on real sockets.
