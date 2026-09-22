# Cryptography

rustnies uses only standard, audited cryptographic primitives. No custom
cryptography is invented.

| Purpose | Primitive | Crate |
|---------|-----------|-------|
| Key exchange | X25519 (ephemeral + static) | `x25519-dalek` |
| Key derivation | HKDF-SHA256 | `hkdf`, `sha2` |
| Transcript hash | SHA-256 | `sha2` |
| AEAD | ChaCha20-Poly1305 (RFC 8439) | `chacha20poly1305` |
| Secret zeroisation | `Zeroize` on `StaticSecret` / `HandshakeResult` | `zeroize` |
| RNG | OS RNG (`OsRng`) | `rand` |

All crypto lives in `src/crypto/`.

## Noise IK handshake

The handshake follows the Noise Protocol Framework **IK** pattern. We implement
it faithfully against the spec rather than designing a new protocol. The
protocol name is:

```
Noise_IK_25519_ChaChaPoly_SHA256
```

SHA-256 is used as the Noise hash (a standard, valid choice; BLAKE2s would also
be valid but SHA-256 minimises dependencies).

### Message flow

The initiator (client) must already know the responder's (server's) static
public key, distributed out of band. `s` denotes a static key, `e` an
ephemeral key.

```
<- s                               (responder static known to initiator)
-> e, es, s, ss                    message 1 (initiator -> responder)
<- e, ee, se                       message 2 (responder -> initiator)
```

Token meanings (DH operations mixed into the chaining key via `MixKey`):

- `e` -> mix the new ephemeral public key into the transcript hash (`MixHash`).
- `es` -> `DH(e_initiator, s_responder)`.
- `s` -> encrypt the initiator's static public key under the current
  handshake key/hash (`EncryptAndHash`).
- `ss` -> `DH(s_initiator, s_responder)`.
- `ee` -> `DH(e_initiator, e_responder)`.
- `se` -> `DH(s_initiator, e_responder)`.

The implementation is in `src/crypto/noise.rs`:

- `NoiseHandshake::new(role, local_keypair, peer_static)` initialises the
  state: `h = SHA256(protocol_name)`, `ck = h`.
- `write_message_1()` / `read_message_1(msg)` handle message 1.
- `write_message_2(payload)` / `read_message_2(msg)` handle message 2 and
  return the decrypted payload plus the `HandshakeResult`.
- `split()` runs Noise's `Split()` and HKDF-derives the two application keys.

### Why `StaticSecret` for the ephemeral

`x25519-dalek`'s `EphemeralSecret::diffie_hellman` takes `self` by value and
wipes it, so a single ephemeral can only be used for one DH. Noise IK requires
*two* DHs from the same ephemeral (`es`+`ss` on the initiator, `ee`+`se` on the
responder). We therefore use `StaticSecret` for the ephemeral as well as the
static key. The ephemeral is freshly generated per handshake (so each handshake
uses a unique ephemeral, preserving Noise's "use once" intent) and
`StaticSecret::diffie_hellman` borrows `&self`, allowing multiple DHs. The
`Zeroize` impl on `StaticSecret` wipes the bytes on drop.

### Application keys

After `Split()`, HKDF-SHA256 derives two 32-byte application keys from the
final chaining key:

```
okm = HKDF-Expand(ck, "rustnies-transport-keys", 64)
key_i2r = okm[ 0..32]   // initiator -> responder
key_r2i = okm[32..64]   // responder -> initiator
```

`HandshakeResult` carries `key_i2r`, `key_r2i`, and the final `handshake_hash`
(which binds the transcript and is used to derive the session id).

### Session id

`session_id_from_hash(h)` takes the first 4 bytes of the handshake hash
(big-endian) and returns a non-zero `u32`. Both sides derive the same id, which
is carried in every packet header and folded into the AEAD nonce.

### Loss tolerance

The handshake is the only reliable phase. The client retries the full handshake
(a fresh ephemeral each attempt) until it receives a valid message 2; the
server responds to each valid message 1. This is driven by
`src/tunnel/handshake.rs` (see [daemon.md](daemon.md)).

## Per-packet AEAD

`src/crypto/aead.rs` wraps ChaCha20-Poly1305. Each packet is encrypted with:

- **Key**: `key_i2r` (initiator->responder) or `key_r2i` (responder->initiator).
- **Nonce**: a deterministic 96-bit value, constructed by `make_nonce`:

  ```
  nonce[0..4]  = session_id      (little-endian)
  nonce[4..8]  = seq             (little-endian)
  nonce[8]     = direction bit   (0 = i2r, 1 = r2i)
  nonce[9..12] = 0x00 0x00 0x00
  ```

  The `direction` bit lets the two directions reuse seq numbers without a
  (key, nonce) collision. Because `seq` is monotonic per direction and the key
  differs per direction, each (key, nonce) pair is used exactly once.

- **AAD**: the 24-byte packet header. This authenticates routing/sequencing
  metadata without encrypting it.
- **Plaintext**: the TUN packet (for `Data`), the parity symbol (for `Fec`),
  the 12-byte RTT probe (for `Ping`/`Pong`), or empty/key-confirmation bytes
  (for control types).

`encrypt` returns `ciphertext || tag` (16-byte tag). `decrypt` verifies the tag
and returns the plaintext or a `CryptoError::Decryption`. A failed tag drops
the packet silently; the receiver does not distinguish "wrong key" from
"corrupted" from "replay after restart".

`TAG_LEN = 16`.

## Key management

`src/crypto/keys.rs` defines `KeyPair` (a `StaticSecret` + `PublicKey`).

- `KeyPair::generate()` -> fresh keypair from `OsRng`.
- `KeyPair::load_or_create(path)` -> if `path` exists, reads 32 raw secret
  bytes; otherwise generates a new keypair and writes the 32 secret bytes to
  `path` with `0600` permissions on Unix. This is how the daemon provisions
  long-term static keys.
- `KeyPair::public_bytes()` -> the 32-byte public key.

The CLI `keygen` subcommand uses `load_or_create` to provision a key file and
prints the public key as 64 hex characters. The client takes the server's
public key via `--server-key <hex>`.

## What is NOT done in phase 1

- No key rotation mid-session.
- No post-quantum key exchange.
- No pre-shared-key hybrid mode.
- No identity hiding for the responder (IK reveals the responder's static
  public key to anyone who sends message 1; this is inherent to IK and
  acceptable for phase 1).
