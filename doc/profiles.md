# Protocol profiles

A **profile** is the set of implementations a session runs. This document covers
what is swappable, how the two peers agree, and how to add a new option.

Start with [`architecture.md`](architecture.md) for the layer stack and
[`protocol.md`](protocol.md) for the wire format.

## The model

`rustnies` separates the protocol's *wire format* from the *implementations* the
wire format is driven by. The 24-byte header, the `PacketType` taxonomy and
`PROTOCOL_VERSION` are fixed. Everything else is selected per session from
config:

| Part | Trait | Registry | Config section | Negotiated? |
|---|---|---|---|---|
| Key exchange | `protocol::handshake::Handshake` | `protocol::handshake` | `[handshake] kex` | **no** — must match |
| Handshake envelope | `transport::Transport` | `transport` | `[transport] handshake` | **no** — must match |
| AEAD cipher | `crypto::suite::AeadCipher` | `crypto::suite` | `[crypto] aead` | yes |
| Data envelope | `transport::Transport` | `transport` | `[transport] data` | yes |
| FEC erasure code | `fec::FecScheme` | `fec` | `[fec] scheme` | yes |
| Congestion control | `congestion::CongestionControl` | `congestion` | `[congestion] algorithm` | **no** — local |
| Obfuscation layers | `obfuscation::ObfuscationLayer` | `obfuscation` | `[obfuscation] layers` | no — config-pinned both ends |

### Why some parts are not negotiated

Three categories, and the reason differs in each case:

* **Invisible to the peer.** A congestion window describes only what *this*
  sender has put on the wire and what came back. There is nothing to agree on,
  so each side uses its own `[congestion]` setting. Offering a preference list
  here would be meaningless.
* **Needed before a negotiation channel exists.** The KEX carries the
  negotiation, and so does the transport that wraps the KEX messages. Both must
  be named identically in the two configs. A mismatch is *detected* (the
  handshake cannot be parsed) and reported, never negotiated away.
* **Not shared state at all.** Obfuscation layers must be configured
  identically on both peers because they are keyed from the handshake hash
  independently on each side; there is no channel to negotiate them over and
  none is needed. This is the pre-existing phase-1 design, unchanged.

Everything else — the cipher, the data envelope, the FEC code — is shared state
that a mismatch would silently corrupt, so it *is* negotiated.

## The negotiation channel

Noise IK already provides one, in the right place, at zero cost:

* **Message 2 has a payload slot that phase 1 left empty.** The responder puts
  its selection there. The payload is encrypted and `mix_hash`ed by the KEX, so
  the selection is confidential and tamper-evident. A peer that predates
  negotiation simply ignores the extra bytes — the change is purely additive.
* **Message 1 has no payload slot.** Appending one is a wire change: a peer that
  predates it hands the longer buffer to the AEAD as the encrypted static key
  and the whole message fails. So the client's capability offer is **opt-in**
  (`[handshake] propose = true`, off by default). With the default the responder
  picks its own first preference and the initiator validates the answer.

### Wire formats

Both payloads start with a format-version byte, and a peer that does not
recognise the version rejects the payload rather than misparsing it.

The offer (message 1, when proposing) is three id lists:

```text
[0] format version
[1] cipher count,     then cipher count     x u8
[ ] transport count,  then transport count  x u8
[ ] fec count,        then fec count        x u8
```

The selection (message 2) is fixed at six bytes:

```text
[0] format version
[1] cipher id
[2] transport id          (0 = reuse the handshake envelope)
[3] fec id
[4..6] data-transport framing tag
```

Ids are stable and never reused. An id this build does not implement is
reported as `id#N` in logs and error messages, which is exactly the case worth
seeing.

### The selection rule

The server is authoritative. For each negotiated part, in order:

1. **The server's own preference wins.** Walk its configured candidates in order
   and take the first the client also lists.
2. **Compatibility fallback.** If none of the server's candidates is supported,
   take the first candidate *the client* listed that this build can run. This is
   what makes a mixed-version fleet work: an older client still connects to a
   newer server, and the server validates before committing rather than forcing
   its own preference onto a peer that cannot execute it.
3. Otherwise there is genuinely nothing both ends can run, and the handshake is
   rejected. A profile is accepted or rejected as a **unit** — half-negotiating
   would build a session whose transport keys are guaranteed wrong.

A client that sent no offer, or said nothing about a given part, leaves that
part entirely to the server.

## Why a cipher mismatch is safe

The negotiated cipher is folded into the HKDF that derives the per-direction
application keys (`AeadCipher::key_schedule`, see [`crypto.md`](crypto.md)):

```text
info = "rustnies-transport-keys" || <the suite's key_schedule()>
```

Two peers that disagree about the suite therefore derive *different* keys, so
the first data packet fails its tag check. A suite mismatch can only ever
surface as an authentication failure on packet one — never as a session that
appears to connect and then misbehaves.

This is also why the initiator does not need to know the suite before reading
message 2: `read_message_2` takes a closure over the freshly decrypted payload
and derives the keys with whatever the payload says. The responder, which chose
the suite, derives them the same way before encrypting the payload.

## Configuration

```toml
[handshake]
kex = "noise-ik"      # must match on both peers; hard error if unknown
propose = false       # client advertises its capabilities in message 1

[crypto]
aead = ["chacha20poly1305"]   # ordered preference; first entry is the default

[transport]
handshake = "plain"                                # must match on both peers
data = ["same-as-handshake"]                       # ordered preference
tag_hex = "abcd"          # server-side only; travels in the selection

[fec]
scheme = ["reed-solomon"]   # ordered preference; "none" disables parity
k = 1
min_m = 0
max_m = 4
initial_m = 2

[congestion]
algorithm = "tcp-reno"   # "none" disables rate limiting; purely local
```

TOML only, matching `[obfuscation]` and `[fec]`. There are no CLI flags for
these sections.

### Defaults and compatibility

The defaults are exactly the pre-negotiation protocol:

* `propose = false`, so message 1 is byte-identical to before.
* `data = ["same-as-handshake"]`, so no envelope is negotiated and the data
  envelope *is* the handshake envelope.
* Message 2 gains six payload bytes, which a peer that predates negotiation
  ignores.

So a default-configured pair still talks to an un-updated peer, and a new peer
talking to an old one falls back to the old profile rather than failing.

### `[transport] tag_hex` is server-side only

The framing tag travels inside the responder's selection, so a client never has
to configure one. It applies **only** to the negotiated data envelope: the
handshake envelope is encoded before any session key material exists, so it
always uses the compiled-in default tag (`transport::DEFAULT_TAG`) on both
peers.

### Unknown-name policy

| Part | On an unknown name |
|---|---|
| `[handshake] kex` | hard error |
| `[transport] handshake` | hard error |
| `[transport] data` | hard error |
| `[crypto] aead` | hard error |
| `[fec] scheme` | hard error |
| `[congestion] algorithm` | hard error |
| `[obfuscation] layers` | `warn!` and skip |

The asymmetry is deliberate. A wrong name in any of the first six leaves the two
peers in different configurations, and the symptom — a session that appears to
connect and then drops every packet, or a handshake that times out with no
diagnostic — is very hard to trace back to a typo. Refusing to start with the
offending string in the message is far kinder. An unknown obfuscation layer only
degrades confidentiality; the tunnel still works, so degrading it beats
refusing.

All six are validated **once**, at config-resolution time
(`LocalProfile::from_role_config`), not per handshake.

## What a session runs

`Tunnel` holds a single `ResolvedProfile` rather than four separate fields, so
it is impossible to build a tunnel that mixes, say, one party's cipher with
another party's envelope:

```rust
pub struct ResolvedProfile {
    pub cipher: Box<dyn AeadCipher>,
    pub transport: Box<dyn Transport>,
    pub fec: Box<dyn FecScheme>,
    pub congestion: Box<dyn CongestionControl>,
    pub selection: Selection,
}
```

`Clone` is cheap (each part is behind a `boxed_clone`), except congestion:
controller state is per-tunnel, so a clone rebuilds a fresh one. A server builds
one profile per accepted handshake and each session gets its own.

The selected profile is logged once per session:

```
INFO session profile negotiated profile="cipher=chacha20poly1305 transport=tagged fec=none congestion=tcp-reno(local)"
```

## Available implementations

| Config name | Effect |
|---|---|
| `chacha20poly1305` | ChaCha20-Poly1305 (RFC 8439), 96-bit nonce. The default and only cipher. |
| `plain` | Identity envelope. The default. |
| `tagged` | Prepends a 2-byte marker (`[transport] tag_hex`, default `"RN"`). |
| `same-as-handshake` | Not a real envelope: "reuse the handshake envelope for data". The default, and requires no negotiation. |
| `reed-solomon` | Systematic Reed-Solomon over GF(256). The default. |
| `none` (FEC) | No parity. Pins the controller's `max_m` to zero regardless of the `k`/`min_m`/`max_m`/`initial_m` values in config, so a stale `max_m` cannot resurrect parity against the session's negotiated wishes. |
| `tcp-reno` | Slow start + multiplicative decrease + pacing. The default. |
| `none` (congestion) | Unbounded window, no pacer. Right for a path whose bottleneck is the *peer's* receive rate; wrong for a shared or lossy one. A diagnostic and lab aid, not a default. |

## Adding a new option

Every part follows the same four steps. Concretely, for a second AEAD:

1. **Implement the trait.** In `crypto/suite.rs`, add a struct implementing
   `AeadCipher` plus a `#[cfg(test)] fn from_id` arm, and give it a
   `key_schedule()` string that is *unique* — domain separation only works if no
   two suites share a context.
2. **Assign a stable wire id.** Add a `CIPHER_*` constant. Never reuse or
   renumber an existing one; a peer's cached id must keep meaning the same thing.
3. **Register the name.** Add a `select_cipher` arm and a `CipherKind` variant.
   That is the whole registry — names are plain `&str` in a `match`, so a new
   name is a one-line change and needs no serde tag or dynamic lookup.
4. **Document and test.** Add the name to the table above, add the id and
   `key_schedule` uniqueness assertions to `crypto::suite`'s tests, and add a
   `key-derivation isolation` case: same handshake, different suite ⇒ different
   keys.

Nothing in `tunnel/`, `daemon/`, or the config plumbing needs to change. Those
all go through `LocalProfile::from_role_config` and `ResolvedProfile`, which are
written against the traits.

For a new *FEC code* or *congestion controller* the same four steps apply
against `fec::FecScheme` / `congestion::CongestionControl`. Two things are worth
checking when adding a congestion controller: implement
`CongestionControl::set_cwnd` if it has a tunable window, and keep
`try_send_parity` refusing only on window exhaustion — dropping redundancy
because of *pacing* would disable FEC exactly when the path is busy.

## See also

- [`protocol.md`](protocol.md) — the wire format, which this document
  deliberately does not make configurable
- [`crypto.md`](crypto.md) — key derivation and the suite binding
- [`obfuscation.md`](obfuscation.md) — the stackable-transform registry, the
  model the profile registries follow
- [`transport.md`](transport.md) — the envelope abstraction
- [`fec.md`](fec.md), [`congestion.md`](congestion.md) — the two strategies and
  their local tuning parameters
