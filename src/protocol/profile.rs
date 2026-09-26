//! Protocol profiles: which implementation of each swappable part a session
//! uses, and how the two peers agree on it.
//!
//! # The model
//!
//! A **profile** is the set of swappable implementations one session runs:
//!
//! | Part | Trait | Registry | Negotiated? |
//! |---|---|---|---|
//! | AEAD cipher | [`crate::crypto::suite::AeadCipher`] | `crypto::suite` | yes |
//! | Data transport | [`crate::transport::Transport`] | `transport` | yes |
//! | FEC scheme | [`crate::fec::FecScheme`] | `fec` | yes |
//! | Congestion control | [`crate::congestion::CongestionControl`] | `congestion` | **no** (local) |
//! | Key exchange | [`super::handshake::Handshake`] | `protocol::handshake` | **no** (must match) |
//! | Handshake transport | [`crate::transport::Transport`] | `transport` | **no** (must match) |
//!
//! Everything marked "negotiated" is shared state the two peers must agree on.
//! Everything marked "no" is either invisible to the peer (congestion) or is
//! needed *before* a negotiation channel exists (the KEX itself, and the
//! transport that wraps the KEX messages).
//!
//! The server is authoritative: it picks, from its own ordered preference, the
//! first candidate the client also supports.
//!
//! # The negotiation channel
//!
//! Noise IK already provides one, for free, and in the right place:
//!
//! * **Message 2's payload is already an encrypted, `mix_hash`ed slot that
//!   phase 1 leaves empty.** The server puts its [`Selection`] there. This is
//!   purely additive — a peer that does not understand it ignores it — and it is
//!   authenticated, so the selection cannot be tampered with in flight.
//! * **Message 1 has no payload slot.** Appending one is a wire change (a peer
//!   that predates it fails to decrypt the encrypted static key), so the
//!   client's [`ClientOffer`] is opt-in via `[handshake] propose = true` and is
//!   off by default. With the default the server just picks its own first
//!   preference and the client validates the answer.
//!
//! The negotiated cipher is additionally folded into the Noise transport-key
//! HKDF (see [`crate::crypto::suite::AeadCipher::key_schedule`]), so a peer
//! that somehow ended up with a different cipher derives different keys and the
//! session fails on its first data packet rather than misbehaving.
//!
//! # What is *not* here
//!
//! The wire format itself. The 24-byte header, the `PacketType` taxonomy and
//! `PROTOCOL_VERSION` are deliberately fixed: swapping them would be a
//! protocol version bump, not a config knob, and a stale peer could not be told
//! so gracefully.

use std::sync::Arc;

use crate::congestion::{CongestionControl, build_congestion};
use crate::crypto::suite::{AeadCipher, CipherKind, DEFAULT_CIPHER, select_cipher};
use crate::fec::{DEFAULT_FEC_SCHEME, FecScheme, FecSchemeKind, select_fec_scheme};
use crate::protocol::frame::{self as frame_codec, DEFAULT_FRAME_CODEC, FrameCodec};
use crate::transport::{
    DEFAULT_TAG, TRANSPORT_SAME_AS_HANDSHAKE, Transport, build_transport_id, transport_id,
    transport_name,
};

/// Format version of the negotiation payloads. Bumped only for an incompatible
/// change to the encodings below; both peers reject a version they do not know
/// rather than misparse it.
pub const NEGOTIATION_VERSION: u8 = 1;

/// Maximum alternatives the offer encoding can carry for one part. A cap keeps
/// a hostile or buggy peer from making us allocate an unbounded list during a
/// handshake, and is far above any realistic preference list.
pub const MAX_OFFER_ALTERNATIVES: usize = 32;

/// Which negotiated part an id belongs to. Used only for logs and error
/// messages, which is why it is a string rather than an enum with a trait.
pub type Part = &'static str;

pub const PART_CIPHER: Part = "cipher";
pub const PART_TRANSPORT: Part = "transport";
pub const PART_FEC: Part = "fec";
/// The header codec — how a [`PacketHeader`] is serialised. Negotiated like any
/// other part, because two peers must agree on it byte-for-byte or every frame
/// after the handshake is misparsed.
pub const PART_FRAME: Part = "frame";

/// Byte length of a `Selection` that predates the frame codec.
///
/// Message 2's payload slot was 6 bytes; the codec id is a 7th, appended. A
/// short payload is therefore read as "v1-fixed", which is what a
/// pre-seam server meant by it. This is the same additive rule the message-1
/// offer follows: old peers keep working, new peers get the extra field.
pub const SELECTION_LEGACY_LEN: usize = 6;

/// Errors from resolving or negotiating a profile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The peer sent a payload whose format version we do not implement.
    #[error("unsupported negotiation payload version {0}")]
    UnsupportedVersion(u8),
    /// A payload was structurally invalid (truncated, or an alternative list
    /// exceeding [`MAX_OFFER_ALTERNATIVES`]).
    #[error("malformed negotiation payload: {0}")]
    Malformed(&'static str),
    /// The peer sent a part id we do not implement.
    #[error("server selected unsupported {part} {id}")]
    UnsupportedPart {
        /// Which part of the profile the id belongs to.
        part: Part,
        /// The rejected id.
        id: u8,
    },
    /// The client offered nothing the server can use.
    #[error("no common {part}: server offers {server:?}, client offers {client:?}")]
    NoCommonPart {
        /// Which part of the profile had no overlap.
        part: Part,
        /// The server's ordered candidate names.
        server: Vec<String>,
        /// The client's ordered candidate names.
        client: Vec<String>,
    },
    /// A config value did not resolve to an implementation.
    #[error("config error: {0}")]
    Config(String),
}

impl ProfileError {
    fn malformed(why: &'static str) -> Self {
        ProfileError::Malformed(why)
    }

    /// Build a "this peer cannot run what you picked" error.
    pub fn unsupported(part: Part, id: u8) -> Self {
        ProfileError::UnsupportedPart { part, id }
    }
}

/// Human-readable name for a part id, falling back to `id#N` for ids this build
/// does not know (which is exactly the case worth reporting).
pub fn part_name(part: Part, id: u8) -> String {
    let known = match part {
        PART_CIPHER => CipherKind::from_id(id).map(|k| k.name().to_string()),
        PART_TRANSPORT => transport_name(id).map(str::to_string),
        PART_FEC => FecSchemeKind::from_id(id).map(|k| k.name().to_string()),
        PART_FRAME => frame_codec::frame_codec_by_id(id)
            .ok()
            .map(|c| c.name().to_string()),
        _ => None,
    };
    known.unwrap_or_else(|| format!("id#{id}"))
}

// ---------------------------------------------------------------------------
// Client offer: "here is everything I can do", in preference order
// ---------------------------------------------------------------------------

/// The ordered set of implementations a peer can use for the negotiated parts.
///
/// Stored as wire ids rather than names so encoding is a straight copy and
/// decoding never has to consult a registry. The first entry of each list is the
/// default; the rest are fallbacks so a mixed-version deployment can connect
/// either way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientOffer {
    /// AEAD cipher ids, most preferred first.
    pub cipher_ids: Vec<u8>,
    /// Data transport ids, most preferred first. Deliberately excludes the
    /// [`TRANSPORT_SAME_AS_HANDSHAKE`] marker, which means "nothing to
    /// negotiate" and is not an id.
    pub transport_ids: Vec<u8>,
    /// FEC scheme ids, most preferred first.
    pub fec_ids: Vec<u8>,
    /// Header codec ids, most preferred first.
    pub frame_ids: Vec<u8>,
}

impl ClientOffer {
    /// Build an offer from this side's resolved config preferences, keeping only
    /// the parts that are genuinely negotiable.
    ///
    /// A `transports` preference consisting solely of
    /// [`TRANSPORT_SAME_AS_HANDSHAKE`] contributes **no** transport ids: both
    /// peers already agree, because the handshake envelope is config-pinned.
    /// That is what makes the default configuration need no transport
    /// negotiation at all.
    pub fn from_prefs(prefs: &ProfilePrefs) -> Self {
        Self {
            cipher_ids: prefs.cipher_ids().into_iter().flatten().collect(),
            transport_ids: prefs.transport_ids().into_iter().flatten().collect(),
            fec_ids: prefs.fec_ids().into_iter().flatten().collect(),
            frame_ids: prefs.frame_ids().into_iter().flatten().collect(),
        }
    }

    /// `true` when the offer constrains nothing, so the server is free to pick
    /// its own first preference for every part.
    pub fn is_empty(&self) -> bool {
        self.cipher_ids.is_empty() && self.transport_ids.is_empty() && self.fec_ids.is_empty()
    }

    fn ids_for(&self, part: Part) -> &[u8] {
        match part {
            PART_CIPHER => &self.cipher_ids,
            PART_TRANSPORT => &self.transport_ids,
            PART_FEC => &self.fec_ids,
            PART_FRAME => &self.frame_ids,
            _ => &[],
        }
    }

    fn names_for(&self, part: Part) -> Vec<String> {
        self.ids_for(part)
            .iter()
            .map(|id| part_name(part, *id))
            .collect()
    }

    /// Encode for the message-1 payload.
    ///
    /// ```text
    /// [0] format version
    /// [1] cipher count,     then cipher count     x u8
    /// [ ] transport count,  then transport count  x u8
    /// [ ] fec count,        then fec count        x u8
    /// [ ] frame count,      then frame count      x u8
    /// ```
    ///
    /// The frame list is last and therefore optional: a decoder that stops after
    /// three lists still parses, which is what keeps a pre-seam client working.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            5 + self.cipher_ids.len()
                + self.transport_ids.len()
                + self.fec_ids.len()
                + self.frame_ids.len(),
        );
        out.push(NEGOTIATION_VERSION);
        for list in [
            &self.cipher_ids,
            &self.transport_ids,
            &self.fec_ids,
            &self.frame_ids,
        ] {
            let n = list.len().min(MAX_OFFER_ALTERNATIVES);
            out.push(n as u8);
            out.extend_from_slice(&list[..n]);
        }
        out
    }

    /// Decode a message-1 payload. An empty payload is `Ok(None)`, not an error:
    /// that is what a peer with `propose = false` sends.
    pub fn decode(payload: &[u8]) -> Result<Option<Self>, ProfileError> {
        if payload.is_empty() {
            return Ok(None);
        }
        let mut cur = Cursor::new(payload)?;
        let cipher_ids = cur.take_list()?;
        let transport_ids = cur.take_list()?;
        let fec_ids = cur.take_list()?;
        // Absent means the peer predates the frame codec; it can only be
        // running the default, so that is what it gets.
        let frame_ids = if cur.at_end() {
            vec![frame_codec::FRAME_V1_FIXED]
        } else {
            cur.take_list()?
        };
        Ok(Some(Self {
            cipher_ids,
            transport_ids,
            fec_ids,
            frame_ids,
        }))
    }
}

/// A bounds-checked reader over a negotiation payload.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Result<Self, ProfileError> {
        let version = *buf
            .first()
            .ok_or(ProfileError::malformed("empty payload"))?;
        if version != NEGOTIATION_VERSION {
            return Err(ProfileError::UnsupportedVersion(version));
        }
        Ok(Self { buf, pos: 1 })
    }

    /// `true` when every declared list has been consumed.
    fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take_list(&mut self) -> Result<Vec<u8>, ProfileError> {
        let n = *self
            .buf
            .get(self.pos)
            .ok_or(ProfileError::malformed("truncated list length"))? as usize;
        self.pos += 1;
        if n > MAX_OFFER_ALTERNATIVES {
            return Err(ProfileError::malformed("alternative list too long"));
        }
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ProfileError::malformed("list length overflows"))?;
        if end > self.buf.len() {
            return Err(ProfileError::malformed("truncated list body"));
        }
        let out = self.buf[self.pos..end].to_vec();
        self.pos = end;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Server selection
// ---------------------------------------------------------------------------

/// The server's answer: one id per negotiated part, plus the framing tag for
/// the data transport.
///
/// ```text
/// [0] format version
/// [1] cipher id
/// [2] transport id
/// [3] fec id
/// [4..6] data-transport framing tag
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// Negotiated AEAD cipher, also bound into the transport-key HKDF.
    pub cipher: u8,
    /// Negotiated data-transport envelope.
    pub transport: u8,
    /// Negotiated FEC scheme.
    pub fec: u8,
    /// Framing tag for the data transport. Carried here so a custom
    /// `[transport] tag_hex` needs no matching client config.
    pub transport_tag: [u8; 2],
    /// Negotiated header codec. Appended last so a 6-byte (pre-seam) payload
    /// still decodes, defaulting to [`frame_codec::FRAME_V1_FIXED`].
    pub frame: u8,
}

/// The sentinel transport id meaning "reuse the handshake envelope". It is
/// deliberately outside the range of real transport ids, which start at 1, so a
/// decoder can never confuse a real selection with the marker.
pub const TRANSPORT_SAME_AS_HANDSHAKE_ID: u8 = 0;

impl Selection {
    /// The default selection: the rustnies defaults for every part, with the
    /// handshake envelope reused for data.
    ///
    /// This is also what an empty message-2 payload decodes to, which is how a
    /// peer that predates negotiation keeps working.
    pub fn defaults() -> Self {
        Self {
            cipher: CipherKind::ChaCha20Poly1305.id(),
            transport: TRANSPORT_SAME_AS_HANDSHAKE_ID,
            fec: FecSchemeKind::ReedSolomon.id(),
            transport_tag: DEFAULT_TAG,
            frame: frame_codec::FRAME_V1_FIXED,
        }
    }

    /// Whether the data envelope is the handshake envelope, i.e. nothing was
    /// negotiated for the transport.
    pub fn reuses_handshake_transport(&self) -> bool {
        self.transport == TRANSPORT_SAME_AS_HANDSHAKE_ID
    }

    /// Encode for the message-2 payload.
    pub fn encode(&self) -> Vec<u8> {
        vec![
            NEGOTIATION_VERSION,
            self.cipher,
            self.transport,
            self.fec,
            self.transport_tag[0],
            self.transport_tag[1],
            self.frame,
        ]
    }

    /// Decode a message-2 payload.
    ///
    /// An empty payload yields the defaults rather than an error: a server that
    /// does not negotiate simply sends nothing, and the client must then fall
    /// back to its own configured profile.
    pub fn decode(payload: &[u8]) -> Result<Self, ProfileError> {
        if payload.is_empty() {
            return Ok(Self::defaults());
        }
        if payload[0] != NEGOTIATION_VERSION {
            return Err(ProfileError::UnsupportedVersion(payload[0]));
        }
        if payload.len() < SELECTION_LEGACY_LEN {
            return Err(ProfileError::malformed("selection shorter than 6 bytes"));
        }
        // A 6-byte payload predates the frame codec; the only codec it could
        // have meant is the one that was then the only codec.
        let frame = match payload.get(6) {
            Some(&f) => f,
            None => frame_codec::FRAME_V1_FIXED,
        };
        Ok(Self {
            cipher: payload[1],
            transport: payload[2],
            fec: payload[3],
            transport_tag: [payload[4], payload[5]],
            frame,
        })
    }

    /// Verify the selection is something this peer can actually run.
    ///
    /// Called by the **client** before it builds its tunnel, so an incompatible
    /// server fails the handshake with a readable error instead of producing a
    /// session whose every packet fails to authenticate.
    pub fn check(&self) -> Result<(), ProfileError> {
        for (part, id) in [
            (PART_CIPHER, self.cipher),
            (PART_TRANSPORT, self.transport),
            (PART_FEC, self.fec),
            (PART_FRAME, self.frame),
        ] {
            let known = match part {
                PART_CIPHER => CipherKind::from_id(id).is_some(),
                PART_TRANSPORT => {
                    id == TRANSPORT_SAME_AS_HANDSHAKE_ID || transport_name(id).is_some()
                }
                PART_FEC => FecSchemeKind::from_id(id).is_some(),
                PART_FRAME => frame_codec::frame_codec_by_id(id).is_ok(),
                _ => false,
            };
            if !known {
                return Err(ProfileError::unsupported(part, id));
            }
        }
        Ok(())
    }

    /// A stable one-line description, for the session-up log.
    pub fn describe(&self, congestion: &str) -> String {
        format!(
            "cipher={} transport={} fec={} frame={} congestion={congestion}(local)",
            self.cipher_name(),
            self.transport_name(),
            self.fec_name(),
            self.frame_name(),
        )
    }

    fn cipher_name(&self) -> String {
        part_name(PART_CIPHER, self.cipher)
    }

    fn frame_name(&self) -> String {
        part_name(PART_FRAME, self.frame)
    }

    fn transport_name(&self) -> String {
        if self.reuses_handshake_transport() {
            TRANSPORT_SAME_AS_HANDSHAKE.to_string()
        } else {
            part_name(PART_TRANSPORT, self.transport)
        }
    }

    fn fec_name(&self) -> String {
        part_name(PART_FEC, self.fec)
    }
}

/// Resolve the server's selection given the client's offer (if any).
///
/// Per part, in order:
///
/// 1. **The server's own preference wins.** Walk its configured candidates in
///    order and take the first one the client also lists. This is the
///    server-authoritative rule: the operator's ordering is what decides.
/// 2. **Compatibility fallback.** If none of the server's candidates is
///    supported, take the first candidate *the client* listed that this build
///    can actually run. This is what makes a mixed-version fleet work: a client
///    that only speaks an older code still connects to a newer server, and the
///    server validates before committing rather than forcing its own preference
///    onto a peer that cannot execute it.
/// 3. Otherwise there is genuinely nothing both ends can run, and
///    [`ProfileError::NoCommonPart`] is returned — the handshake is rejected
///    rather than proceeding with something that will fail later.
///
/// A client that sent no offer (or said nothing about this part) leaves the
/// choice entirely to the server, so step 1 short-circuits to its first
/// candidate.
pub fn negotiate(
    prefs: &ProfilePrefs,
    offer: Option<&ClientOffer>,
    data_tag: [u8; 2],
) -> Result<Selection, ProfileError> {
    let cipher = pick(
        PART_CIPHER,
        &prefs.cipher_ids(),
        &prefs.cipher_names(),
        offer,
        || Selection::defaults().cipher,
        |id| CipherKind::from_id(id).is_some(),
    )?;
    let transport = pick(
        PART_TRANSPORT,
        &prefs.transport_ids(),
        &prefs.transport_names(),
        offer,
        || TRANSPORT_SAME_AS_HANDSHAKE_ID,
        |id| crate::transport::transport_name(id).is_some(),
    )?;
    let fec = pick(
        PART_FEC,
        &prefs.fec_ids(),
        &prefs.fec_names(),
        offer,
        || Selection::defaults().fec,
        |id| FecSchemeKind::from_id(id).is_some(),
    )?;

    let frame = pick(
        PART_FRAME,
        &prefs.frame_ids(),
        &prefs.frame_names(),
        offer,
        || Selection::defaults().frame,
        |id| frame_codec::frame_codec_by_id(id).is_ok(),
    )?;

    let sel = Selection {
        cipher,
        transport,
        fec,
        transport_tag: data_tag,
        frame,
    };
    sel.check()?;
    Ok(sel)
}

fn pick(
    part: Part,
    candidate_ids: &[Option<u8>],
    candidate_names: &[String],
    offer: Option<&ClientOffer>,
    terminal: impl Fn() -> u8,
    buildable: impl Fn(u8) -> bool,
) -> Result<u8, ProfileError> {
    let offer_ids: &[u8] = match offer {
        None => &[],
        Some(o) => o.ids_for(part),
    };

    if offer_ids.is_empty() {
        // The client constrains nothing for this part: the server's first real
        // candidate wins, or the terminal `same-as-handshake` marker if it has
        // none.
        return Ok(candidate_ids
            .iter()
            .flatten()
            .next()
            .copied()
            .unwrap_or_else(terminal));
    }

    // Step 1: the server's preference order, filtered by what the client offers.
    for id in candidate_ids.iter().flatten() {
        if offer_ids.contains(id) {
            return Ok(*id);
        }
    }
    // Step 2: compatibility fallback to the client's ordering, but only for
    // something this build can actually run.
    for id in offer_ids {
        if buildable(*id) {
            tracing::debug!(
                part,
                chosen = %part_name(part, *id),
                "no server preference matched; falling back to a client-offered option"
            );
            return Ok(*id);
        }
    }
    Err(ProfileError::NoCommonPart {
        part,
        server: candidate_names.to_vec(),
        client: offer.map(|o| o.names_for(part)).unwrap_or_default(),
    })
}

// ---------------------------------------------------------------------------
// Local (pre-handshake) configuration
// ---------------------------------------------------------------------------

/// The ordered, config-resolved preferences for the negotiated parts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfilePrefs {
    /// AEAD cipher names, most preferred first.
    pub ciphers: Vec<String>,
    /// Data transport names, most preferred first. May contain
    /// [`TRANSPORT_SAME_AS_HANDSHAKE`].
    pub transports: Vec<String>,
    /// FEC scheme names, most preferred first.
    pub fecs: Vec<String>,
    /// Header codec names, most preferred first.
    pub frames: Vec<String>,
}

impl ProfilePrefs {
    /// Validate every configured name, reporting the first unknown one.
    ///
    /// Called once at config-resolution time so a typo fails at startup rather
    /// than during a handshake. An empty list resolves to the defaults, matching
    /// "no section means defaults".
    pub fn resolve(
        ciphers: &[String],
        transports: &[String],
        fecs: &[String],
        frames: &[String],
    ) -> Result<Self, ProfileError> {
        let ciphers = non_empty_or(ciphers, DEFAULT_CIPHER);
        for name in &ciphers {
            select_cipher(name).map_err(|e| ProfileError::Config(e.to_string()))?;
        }
        let transports = non_empty_or(transports, TRANSPORT_SAME_AS_HANDSHAKE);
        for name in &transports {
            if name.trim() == TRANSPORT_SAME_AS_HANDSHAKE {
                continue;
            }
            if transport_id(name).is_none() {
                return Err(ProfileError::Config(format!(
                    "unknown transport {name:?} (supported: plain, tagged)"
                )));
            }
        }
        let fecs = non_empty_or(fecs, DEFAULT_FEC_SCHEME);
        for name in &fecs {
            select_fec_scheme(name).map_err(|e| ProfileError::Config(e.to_string()))?;
        }
        let frames = non_empty_or(frames, DEFAULT_FRAME_CODEC);
        for name in &frames {
            frame_codec::build_frame_codec(name)
                .map_err(|e| ProfileError::Config(e.to_string()))?;
        }
        Ok(Self {
            ciphers,
            transports,
            fecs,
            frames,
        })
    }

    /// Candidate ids per part, in preference order. A `None` entry is the
    /// `same-as-handshake` marker for the transport part.
    fn cipher_ids(&self) -> Vec<Option<u8>> {
        self.ciphers
            .iter()
            .filter_map(|n| select_cipher(n).ok())
            .map(|k| Some(k.id()))
            .collect()
    }

    fn transport_ids(&self) -> Vec<Option<u8>> {
        self.transports
            .iter()
            .map(|n| {
                if n.trim() == TRANSPORT_SAME_AS_HANDSHAKE {
                    None
                } else {
                    transport_id(n)
                }
            })
            .collect()
    }

    fn fec_ids(&self) -> Vec<Option<u8>> {
        self.fecs
            .iter()
            .filter_map(|n| select_fec_scheme(n).ok())
            .map(|k| Some(k.id()))
            .collect()
    }

    /// Header codec ids, in preference order.
    fn frame_ids(&self) -> Vec<Option<u8>> {
        self.frames
            .iter()
            .filter_map(|n| frame_codec::build_frame_codec(n).ok())
            .map(|c| Some(c.wire_id()))
            .collect()
    }

    fn frame_names(&self) -> Vec<String> {
        self.frames.clone()
    }

    fn cipher_names(&self) -> Vec<String> {
        self.ciphers.clone()
    }

    fn transport_names(&self) -> Vec<String> {
        self.transports
            .iter()
            .map(|n| {
                if n.trim() == TRANSPORT_SAME_AS_HANDSHAKE {
                    TRANSPORT_SAME_AS_HANDSHAKE.to_string()
                } else {
                    part_name(PART_TRANSPORT, transport_id(n).unwrap_or(0))
                }
            })
            .collect()
    }

    fn fec_names(&self) -> Vec<String> {
        self.fecs.clone()
    }

    /// The default preferences: rustnies defaults for every negotiated part, no
    /// transport negotiation, and the local TCP-inspired controller.
    pub fn rustnies_default() -> Self {
        Self {
            ciphers: vec![DEFAULT_CIPHER.to_string()],
            transports: vec![TRANSPORT_SAME_AS_HANDSHAKE.to_string()],
            fecs: vec![DEFAULT_FEC_SCHEME.to_string()],
            frames: vec![DEFAULT_FRAME_CODEC.to_string()],
        }
    }
}

fn non_empty_or(list: &[String], default: &str) -> Vec<String> {
    if list.is_empty() {
        vec![default.to_string()]
    } else {
        list.to_vec()
    }
}

/// Everything a side knows about its own profile before the handshake, plus the
/// parts that are not negotiated at all.
pub struct LocalProfile {
    /// The KEX name from `[handshake] kex`. **Not** negotiable — it is what
    /// carries the negotiation — so it must be named identically in both peers'
    /// configs. Checked at startup on both sides.
    pub kex_name: String,
    /// Ordered preferences for the negotiated parts.
    pub prefs: ProfilePrefs,
    /// Envelope for message 1 / message 2. Config-pinned: it cannot be
    /// negotiated, because it is what carries the negotiation. It therefore
    /// always uses [`crate::transport::DEFAULT_TAG`] for the `tagged` transport;
    /// `[transport] tag_hex` applies only to the negotiated data envelope.
    pub handshake_transport: Box<dyn Transport>,
    /// Framing tag for the negotiated data transport.
    pub data_tag: [u8; 2],
    /// Config name of the local congestion controller. Never negotiated — a
    /// congestion window is invisible to the peer. Held as a *name* rather than
    /// a controller because controller state is per-tunnel: a server builds one
    /// [`LocalProfile`] and must hand each session its own controller, which
    /// [`LocalProfile::new_congestion`] does.
    pub congestion_name: String,
    /// Whether to append a [`ClientOffer`] to message 1. Off by default,
    /// because appending is a wire change an older peer cannot parse.
    pub propose: bool,
}

impl std::fmt::Debug for LocalProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalProfile")
            .field("kex", &self.kex_name)
            .field("ciphers", &self.prefs.ciphers)
            .field("transports", &self.prefs.transports)
            .field("fecs", &self.prefs.fecs)
            .field("handshake_transport", &self.handshake_transport.name())
            .field("data_tag", &self.data_tag)
            .field("congestion", &self.congestion_name)
            .field("propose", &self.propose)
            .finish()
    }
}

impl LocalProfile {
    /// The offer this side would send, or `None` when it does not propose.
    pub fn offer(&self) -> Option<ClientOffer> {
        self.propose.then(|| ClientOffer::from_prefs(&self.prefs))
    }

    /// Build a fresh congestion controller for one session.
    ///
    /// Called once per accepted handshake. The controller is *stateful* (window,
    /// in-flight accounting, pacer schedule), so it must never be shared between
    /// two tunnels.
    pub fn new_congestion(&self) -> Box<dyn CongestionControl> {
        build_congestion(&self.congestion_name)
            .expect("LocalProfile validates the congestion name in from_config")
    }
}

// ---------------------------------------------------------------------------
// The negotiated, runnable profile
// ---------------------------------------------------------------------------

/// The concrete implementations one session runs, all built from a
/// [`Selection`].
///
/// Cheap to clone (each part is a `Box<dyn …>` behind a `boxed_clone`), so a
/// server builds the profile once per accepted handshake and every tunnel in
/// that session gets its own copy.
pub struct ResolvedProfile {
    /// Per-packet AEAD. Also determines the transport-key HKDF context.
    pub cipher: Box<dyn AeadCipher>,
    /// Steady-state envelope.
    pub transport: Box<dyn Transport>,
    /// Erasure code.
    pub fec: Box<dyn FecScheme>,
    /// Header codec: how a `PacketHeader` becomes bytes. Shared by `Arc` because
    /// it is stateless and the server hands the same one to every session.
    pub codec: Arc<dyn FrameCodec>,
    /// Local rate limiting.
    pub congestion: Box<dyn CongestionControl>,
    /// The selection this was built from, kept for logs and stats.
    pub selection: Selection,
}

impl ResolvedProfile {
    /// Build from a selection the peer has already agreed to.
    ///
    /// `session_seed` is the handshake hash, passed to [`Transport::init`] so a
    /// keyed transport derives the same material on both sides. `congestion` is
    /// the caller's own local controller and is deliberately *not* taken from
    /// the selection.
    pub fn from_selection(
        selection: &Selection,
        session_seed: &[u8; 32],
        congestion: Box<dyn CongestionControl>,
    ) -> Result<Self, ProfileError> {
        selection.check()?;
        let cipher = CipherKind::from_id(selection.cipher)
            .ok_or_else(|| ProfileError::unsupported(PART_CIPHER, selection.cipher))?
            .build();
        let transport = build_transport_id(selection.transport, selection.transport_tag)
            .ok_or_else(|| ProfileError::unsupported(PART_TRANSPORT, selection.transport))?;
        transport.init(session_seed);
        let fec = FecSchemeKind::from_id(selection.fec)
            .ok_or_else(|| ProfileError::unsupported(PART_FEC, selection.fec))?
            .build();
        let codec = frame_codec::frame_codec_by_id(selection.frame)
            .map_err(|_| ProfileError::unsupported(PART_FRAME, selection.frame))?;
        Ok(Self {
            cipher,
            transport,
            fec,
            codec,
            congestion,
            selection: *selection,
        })
    }

    /// Build a profile whose data envelope reuses the handshake envelope.
    ///
    /// This is the default path: no transport was negotiated, so the data
    /// envelope *is* the handshake envelope. The negotiated transport is ignored
    /// in that case, which is why the marker id never reaches
    /// [`Self::from_selection`].
    pub fn with_handshake_transport(
        selection: &Selection,
        session_seed: &[u8; 32],
        handshake_transport: &dyn Transport,
        congestion: Box<dyn CongestionControl>,
    ) -> Result<Self, ProfileError> {
        if !selection.reuses_handshake_transport() {
            return Self::from_selection(selection, session_seed, congestion);
        }
        let transport = handshake_transport.boxed_clone();
        transport.init(session_seed);
        let cipher = CipherKind::from_id(selection.cipher)
            .ok_or_else(|| ProfileError::unsupported(PART_CIPHER, selection.cipher))?
            .build();
        let fec = FecSchemeKind::from_id(selection.fec)
            .ok_or_else(|| ProfileError::unsupported(PART_FEC, selection.fec))?
            .build();
        let codec = frame_codec::frame_codec_by_id(selection.frame)
            .map_err(|_| ProfileError::unsupported(PART_FRAME, selection.frame))?;
        Ok(Self {
            cipher,
            transport,
            fec,
            codec,
            congestion,
            selection: *selection,
        })
    }

    /// The cipher's transport-key HKDF context, which the Noise handshake needs
    /// *before* the application keys are derived.
    pub fn key_schedule(&self) -> &'static [u8] {
        self.cipher.key_schedule()
    }

    /// One-line description for the session-up log.
    pub fn describe(&self) -> String {
        self.selection.describe(self.congestion.name())
    }
}

impl std::fmt::Debug for ResolvedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedProfile")
            .field("cipher", &self.cipher.name())
            .field("transport", &self.transport.name())
            .field("fec", &self.fec.name())
            .field("frame", &self.codec.name())
            .field("congestion", &self.congestion.name())
            .field("selection", &self.selection)
            .finish()
    }
}

impl Clone for ResolvedProfile {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.boxed_clone(),
            transport: self.transport.boxed_clone(),
            fec: self.fec.boxed_clone(),
            // The codec is stateless, so sharing it is correct (unlike
            // congestion, whose window is per-tunnel state).
            codec: self.codec.clone(),
            // Congestion state is per-tunnel and must not be shared, so rebuild
            // from the name. Every name a ResolvedProfile can hold was produced
            // by a registry lookup, so this cannot fail; if a new controller
            // ever needed constructor arguments this becomes a stored
            // constructor closure instead.
            congestion: build_congestion(self.congestion.name())
                .expect("resolved congestion name is always selectable"),
            selection: self.selection,
        }
    }
}

/// Validate a `[congestion] algorithm` config name and return it normalised.
///
/// Only the *name* is validated here; the controller itself is built per session
/// by [`LocalProfile::new_congestion`], because its state must not be shared.
pub fn local_congestion_name(algorithm: &str) -> Result<String, ProfileError> {
    crate::congestion::select_congestion(algorithm)
        .map_err(|e| ProfileError::Config(e.to_string()))?;
    let name = algorithm.trim();
    Ok(if name.is_empty() {
        crate::congestion::DEFAULT_CONGESTION.to_string()
    } else {
        name.to_string()
    })
}

impl LocalProfile {
    /// Assemble this side's profile from resolved config.
    ///
    /// Every configured name is validated *here*, once, so a typo fails at
    /// startup with the offending string in the message rather than surfacing
    /// as a handshake timeout or a mid-session decrypt failure later. The
    /// unknown-name policy is deliberately per part:
    ///
    /// * cipher / FEC / congestion — **hard error**. A silent fallback would
    ///   put the two peers in different configurations, and the symptom (a
    ///   session that appears to connect and then drops every packet) is very
    ///   hard to diagnose.
    /// * handshake / data transport — also **hard error** for the handshake
    ///   envelope and for any data entry that is not
    ///   [`TRANSPORT_SAME_AS_HANDSHAKE`], because a mismatch is equally fatal
    ///   and is the operator's own config talking.
    ///
    /// The one warn-and-skip case left in the codebase is the obfuscation layer
    /// list, where an unknown layer degrades confidentiality but leaves the
    /// tunnel working.
    // Eight named config sections; the alternative is a struct of them, which
    // would be a second place to forget a field.
    #[allow(clippy::too_many_arguments)]
    pub fn from_config(
        kex_name: &str,
        propose: bool,
        handshake_transport: &str,
        ciphers: &[String],
        transports: &[String],
        fecs: &[String],
        data_tag: [u8; 2],
        congestion_algorithm: &str,
        frames: &[String],
    ) -> Result<Self, ProfileError> {
        // Validate the KEX up front. It is the one part both peers must agree
        // on and the one part that cannot be negotiated, so a typo is fatal on
        // either side.
        crate::protocol::handshake::select_handshake(kex_name)
            .map_err(|e| ProfileError::Config(e.to_string()))?;
        if crate::transport::transport_id(handshake_transport).is_none() {
            return Err(ProfileError::Config(format!(
                "unknown [transport] handshake envelope {handshake_transport:?} (supported: plain, tagged)"
            )));
        }
        let prefs = ProfilePrefs::resolve(ciphers, transports, fecs, frames)?;
        Ok(Self {
            kex_name: kex_name.trim().to_string(),
            prefs,
            // The handshake envelope is unkeyed by construction (it wraps the
            // handshake, so no session key material exists yet) and always uses
            // the compiled-in default tag, which is what lets both peers derive
            // the same envelope from config alone.
            handshake_transport: crate::transport::build_transport(
                handshake_transport,
                crate::transport::DEFAULT_TAG,
            ),
            data_tag,
            congestion_name: local_congestion_name(congestion_algorithm)?,
            propose,
        })
    }
}

impl LocalProfile {
    /// Assemble a [`LocalProfile`] from the four config sections that describe
    /// the swappable protocol parts.
    ///
    /// This is the single entry point both the server and the client daemon
    /// use, so the two resolve a config file into a profile through exactly the
    /// same validation and the same defaults. Everything is validated here, once,
    /// at config-resolution time.
    pub fn from_role_config(
        handshake: &crate::config::HandshakeConfig,
        crypto: &crate::config::CryptoConfig,
        transport: &crate::config::TransportConfig,
        fec: &crate::config::FecConfig,
        congestion: &crate::config::CongestionConfig,
        frame: &crate::config::FrameConfig,
    ) -> Result<Self, ProfileError> {
        let data_tag = crate::transport::parse_tag(transport.tag_hex.as_deref())
            .map_err(|e| ProfileError::Config(format!("[transport] tag_hex: {e}")))?;
        Self::from_config(
            &handshake.kex,
            handshake.propose,
            &transport.handshake,
            &crypto.aead,
            &transport.data,
            &fec.scheme,
            data_tag,
            &congestion.algorithm,
            &frame.codec,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::{CONGESTION_NONE, DEFAULT_CONGESTION};
    use crate::crypto::suite::{CIPHER_CHACHA20POLY1305, DEFAULT_CIPHER};
    use crate::fec::{DEFAULT_FEC_SCHEME, FEC_NONE, FEC_NONE_ID, FEC_REED_SOLOMON};
    use crate::transport::{
        DEFAULT_TAG, TRANSPORT_PLAIN, TRANSPORT_SAME_AS_HANDSHAKE, TRANSPORT_TAGGED,
        default_transport,
    };

    fn prefs(ciphers: &[&str], transports: &[&str], fecs: &[&str]) -> ProfilePrefs {
        prefs_with_frames(ciphers, transports, fecs, &[DEFAULT_FRAME_CODEC])
    }

    fn prefs_with_frames(
        ciphers: &[&str],
        transports: &[&str],
        fecs: &[&str],
        frames: &[&str],
    ) -> ProfilePrefs {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        ProfilePrefs::resolve(&v(ciphers), &v(transports), &v(fecs), &v(frames))
            .expect("test prefs must resolve")
    }

    fn offer(ciphers: &[u8], transports: &[u8], fecs: &[u8]) -> ClientOffer {
        offer_with_frames(ciphers, transports, fecs, &[frame_codec::FRAME_V1_FIXED])
    }

    fn offer_with_frames(
        ciphers: &[u8],
        transports: &[u8],
        fecs: &[u8],
        frames: &[u8],
    ) -> ClientOffer {
        ClientOffer {
            cipher_ids: ciphers.to_vec(),
            transport_ids: transports.to_vec(),
            fec_ids: fecs.to_vec(),
            frame_ids: frames.to_vec(),
        }
    }

    /// The genuine rejection case: a client offering a codec id this build does
    /// not implement. That is the only way the frame part can fail to
    /// negotiate, since a peer can only offer ids from its own registry -- which
    /// is what a mixed-version fleet actually produces.
    #[test]
    fn an_offer_naming_an_unknown_codec_is_rejected_outright() {
        let prefs = prefs_with_frames(&[], &[], &[], &["v1-fixed"]);
        let offer = offer_with_frames(&[], &[], &[], &[200, 201]); // ids nothing implements
        let err = negotiate(&prefs, Some(&offer), DEFAULT_TAG).unwrap_err();
        assert!(
            matches!(
                err,
                ProfileError::NoCommonPart {
                    part: PART_FRAME,
                    ..
                }
            ),
            "expected a frame NoCommonPart, got {err:?}"
        );
    }

    /// Every codec the registry knows must be negotiable, and a selection
    /// naming any of them must pass `check`. Otherwise a peer could be told to
    /// run a codec this build cannot build.
    #[test]
    fn every_known_codec_id_negotiates_and_validates() {
        for (name, id) in [
            ("v1-fixed", frame_codec::FRAME_V1_FIXED),
            ("v2-tlv", frame_codec::FRAME_V2_TLV),
        ] {
            let prefs = prefs_with_frames(&[], &[], &[], &[name]);
            let offer = offer_with_frames(&[], &[], &[], &[id]);
            let sel = negotiate(&prefs, Some(&offer), DEFAULT_TAG)
                .unwrap_or_else(|e| panic!("{name} must negotiate: {e}"));
            assert_eq!(sel.frame, id);
            sel.check()
                .unwrap_or_else(|e| panic!("{name} must pass check: {e}"));
            let built = ResolvedProfile::with_handshake_transport(
                &sel,
                &[0u8; 32],
                &*default_transport(),
                build_congestion(DEFAULT_CONGESTION).unwrap(),
            );
            assert!(
                built.is_ok(),
                "{name} must be instantiable: {:?}",
                built.err()
            );
            assert_eq!(
                built.unwrap().codec.name(),
                name,
                "the built codec must match"
            );
        }
    }

    /// A server's *preference order* is a preference, not a constraint: if the
    /// client offers only something else that this build can run, the fallback
    /// picks it. Pinned because it surprises operators who expect their server
    /// config to be binding.
    #[test]
    fn a_server_preference_does_not_override_a_buildable_client_offer() {
        let prefs = prefs_with_frames(&[], &[], &[], &["v1-fixed"]);
        let offer = offer_with_frames(&[], &[], &[], &[frame_codec::FRAME_V2_TLV]);
        let sel = negotiate(&prefs, Some(&offer), DEFAULT_TAG).unwrap();
        assert_eq!(
            sel.frame,
            frame_codec::FRAME_V2_TLV,
            "the client's only buildable option wins over the server's list"
        );
    }

    // ---- Preference resolution ----

    #[test]
    fn empty_lists_resolve_to_the_rustnies_defaults() {
        let p = ProfilePrefs::resolve(&[], &[], &[], &[]).unwrap();
        assert_eq!(p, ProfilePrefs::rustnies_default());
        assert_eq!(p.ciphers, [DEFAULT_CIPHER]);
        assert_eq!(p.fecs, [DEFAULT_FEC_SCHEME]);
        assert_eq!(p.transports, [TRANSPORT_SAME_AS_HANDSHAKE]);
    }

    #[test]
    fn unknown_names_are_rejected_at_resolve_time() {
        for (c, t, f) in [
            (
                ["aes-gcm"],
                [TRANSPORT_SAME_AS_HANDSHAKE],
                [DEFAULT_FEC_SCHEME],
            ),
            ([DEFAULT_CIPHER], ["tls-front"], [DEFAULT_FEC_SCHEME]),
            ([DEFAULT_CIPHER], [TRANSPORT_SAME_AS_HANDSHAKE], ["ldpc"]),
        ] {
            let err = ProfilePrefs::resolve(
                &c.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                &t.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                &f.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                &[],
            )
            .unwrap_err();
            assert!(
                matches!(err, ProfileError::Config(_)),
                "expected a config error for {c:?}/{t:?}/{f:?}, got {err:?}"
            );
        }
    }

    // ---- Offer encoding ----

    #[test]
    fn offer_roundtrips_through_encode_decode() {
        let o = offer(
            &[CIPHER_CHACHA20POLY1305],
            &[TRANSPORT_TAGGED],
            &[FEC_REED_SOLOMON, FEC_NONE_ID],
        );
        let bytes = o.encode();
        assert_eq!(ClientOffer::decode(&bytes).unwrap(), Some(o));
    }

    #[test]
    fn empty_offer_encodes_to_a_valid_empty_payload() {
        let bytes = offer(&[], &[], &[]).encode();
        let back = ClientOffer::decode(&bytes).unwrap().unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn offer_decode_rejects_a_bad_version() {
        let mut bytes = offer(&[1], &[], &[]).encode();
        bytes[0] = 7;
        assert_eq!(
            ClientOffer::decode(&bytes).unwrap_err(),
            ProfileError::UnsupportedVersion(7)
        );
    }

    /// A truncated offer is rejected — with exactly one exception: a payload
    /// that ends cleanly after the third list is a *valid* pre-seam offer, and
    /// must decode with the default frame codec. That is the compat rule that
    /// lets a client built before the codec existed negotiate with a server
    /// built after it.
    #[test]
    fn offer_decode_rejects_a_truncated_body_but_accepts_a_pre_frame_payload() {
        let full = offer(&[1, 2], &[3], &[4]).encode();
        // The length of the legacy (three-list) encoding: version + three
        // (count, body) pairs.
        let legacy_len = 1 + 1 + 2 + 1 + 1 + 1 + 1;

        for cut in 1..full.len() {
            let decoded = ClientOffer::decode(&full[..cut]);
            if cut == legacy_len {
                let got = decoded
                    .expect("a three-list payload is a valid legacy offer")
                    .expect("a non-empty payload decodes to Some");
                assert_eq!(
                    got,
                    ClientOffer {
                        cipher_ids: vec![1, 2],
                        transport_ids: vec![3],
                        fec_ids: vec![4],
                        // Absent means the default, which is the only codec
                        // that existed when the payload was written.
                        frame_ids: vec![frame_codec::FRAME_V1_FIXED],
                    },
                    "a payload ending after the third list is the legacy format"
                );
            } else {
                assert!(
                    matches!(decoded, Err(ProfileError::Malformed(_))),
                    "truncating to {cut} bytes must be rejected, got {decoded:?}"
                );
            }
        }
    }

    /// The legacy encoding must still decode, because that is the whole point
    /// of the append-only rule.
    #[test]
    fn a_three_list_offer_decodes_with_the_default_frame_codec() {
        let legacy = vec![NEGOTIATION_VERSION, 1, 7, 0, 1, 8];
        let o = ClientOffer::decode(&legacy)
            .expect("legacy offer must decode")
            .expect("a non-empty payload decodes to Some");
        assert_eq!(o.cipher_ids, [7]);
        assert!(o.transport_ids.is_empty());
        assert_eq!(o.fec_ids, [8]);
        assert_eq!(o.frame_ids, [frame_codec::FRAME_V1_FIXED]);
    }

    /// Likewise a 6-byte `Selection` (pre-seam) must decode to the default
    /// codec, and a 7-byte one must carry it.
    #[test]
    fn a_legacy_selection_decodes_to_the_default_frame_codec() {
        let legacy = vec![NEGOTIATION_VERSION, 1, 2, 1, 0xAA, 0xBB];
        let sel = Selection::decode(&legacy).expect("legacy selection must decode");
        assert_eq!(sel.frame, frame_codec::FRAME_V1_FIXED);
        assert_eq!(sel.cipher, 1);
        assert_eq!(sel.transport_tag, [0xAA, 0xBB]);

        let mut with_frame = legacy.clone();
        with_frame.push(9);
        let sel = Selection::decode(&with_frame).unwrap();
        assert_eq!(sel.frame, 9, "a 7th byte is the codec id");
    }

    #[test]
    fn offer_decode_rejects_an_over_long_list() {
        let mut bytes = vec![NEGOTIATION_VERSION, (MAX_OFFER_ALTERNATIVES + 1) as u8];
        bytes.extend(std::iter::repeat_n(1u8, MAX_OFFER_ALTERNATIVES + 1));
        assert!(matches!(
            ClientOffer::decode(&bytes),
            Err(ProfileError::Malformed(_))
        ));
    }

    #[test]
    fn offer_from_prefs_drops_the_same_as_handshake_marker() {
        // `same-as-handshake` is not an id, and both peers already agree on the
        // envelope, so it must not turn into an offer entry.
        let o = ClientOffer::from_prefs(&prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[DEFAULT_FEC_SCHEME],
        ));
        assert!(o.transport_ids.is_empty());
        assert!(!o.is_empty(), "cipher and fec are still offered");
    }

    #[test]
    fn offer_from_prefs_keeps_real_transports() {
        let o = ClientOffer::from_prefs(&prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE, "tagged"],
            &[DEFAULT_FEC_SCHEME],
        ));
        assert_eq!(o.transport_ids, [TRANSPORT_TAGGED]);
    }

    // ---- Selection encoding ----

    #[test]
    fn selection_roundtrips_through_encode_decode() {
        let sel = Selection {
            cipher: CIPHER_CHACHA20POLY1305,
            transport: TRANSPORT_TAGGED,
            fec: FEC_NONE_ID,
            transport_tag: [0xAA, 0xBB],
            frame: frame_codec::FRAME_V1_FIXED,
        };
        assert_eq!(Selection::decode(&sel.encode()).unwrap(), sel);
    }

    #[test]
    fn an_empty_selection_payload_means_the_defaults() {
        // A server that predates negotiation sends nothing; the client must fall
        // back to its own defaults rather than failing.
        assert_eq!(Selection::decode(&[]).unwrap(), Selection::defaults());
    }

    #[test]
    fn selection_decode_rejects_a_bad_version_or_short_body() {
        let mut bad_version = Selection::defaults().encode();
        bad_version[0] = 200;
        assert_eq!(
            Selection::decode(&bad_version).unwrap_err(),
            ProfileError::UnsupportedVersion(200)
        );
        let short = vec![NEGOTIATION_VERSION, 1, 1, 1];
        assert!(matches!(
            Selection::decode(&short),
            Err(ProfileError::Malformed(_))
        ));
    }

    #[test]
    fn selection_check_rejects_unknown_ids() {
        for (part, sel) in [
            (
                PART_CIPHER,
                Selection {
                    cipher: 99,
                    ..Selection::defaults()
                },
            ),
            (
                PART_TRANSPORT,
                Selection {
                    transport: 99,
                    ..Selection::defaults()
                },
            ),
            (
                PART_FEC,
                Selection {
                    fec: 99,
                    ..Selection::defaults()
                },
            ),
        ] {
            assert_eq!(
                sel.check().unwrap_err(),
                ProfileError::unsupported(part, 99)
            );
        }
        // The `same-as-handshake` sentinel is explicitly valid for the transport.
        assert!(Selection::defaults().check().is_ok());
    }

    // ---- The negotiation matrix ----

    #[test]
    fn no_offer_lets_the_server_pick_its_first_preference() {
        let p = prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[FEC_NONE, DEFAULT_FEC_SCHEME],
        );
        let sel = negotiate(&p, None, DEFAULT_TAG).unwrap();
        assert_eq!(sel.fec, FEC_NONE_ID, "server's first preference wins");
        assert!(sel.reuses_handshake_transport());
    }

    #[test]
    fn an_empty_offer_also_leaves_the_choice_to_the_server() {
        let p = prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[DEFAULT_FEC_SCHEME],
        );
        let sel = negotiate(&p, Some(&offer(&[], &[], &[])), DEFAULT_TAG).unwrap();
        assert_eq!(sel, Selection::defaults());
    }

    #[test]
    fn the_server_prefers_its_own_order_over_the_clients() {
        // Server wants Reed-Solomon first, `none` second. The client offers both
        // but lists `none` first. The server's ordering must win.
        let p = prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[DEFAULT_FEC_SCHEME, FEC_NONE],
        );
        let client = offer(
            &[CIPHER_CHACHA20POLY1305],
            &[],
            &[FEC_NONE_ID, FEC_REED_SOLOMON],
        );
        let sel = negotiate(&p, Some(&client), DEFAULT_TAG).unwrap();
        assert_eq!(sel.fec, FEC_REED_SOLOMON);
    }

    #[test]
    fn the_server_skips_candidates_the_client_cannot_do() {
        // Server wants `none` first but the client only does Reed-Solomon.
        let p = prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[FEC_NONE, DEFAULT_FEC_SCHEME],
        );
        let client = offer(&[CIPHER_CHACHA20POLY1305], &[], &[FEC_REED_SOLOMON]);
        let sel = negotiate(&p, Some(&client), DEFAULT_TAG).unwrap();
        assert_eq!(sel.fec, FEC_REED_SOLOMON);
    }

    #[test]
    fn a_client_only_option_the_server_can_run_is_the_compatibility_fallback() {
        // Server has no candidate the client supports. The client lists one this
        // build can run, so the session must still come up rather than fail.
        let p = prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[FEC_NONE],
        );
        let client = offer(&[CIPHER_CHACHA20POLY1305], &[], &[FEC_REED_SOLOMON]);
        let sel = negotiate(&p, Some(&client), DEFAULT_TAG).unwrap();
        assert_eq!(sel.fec, FEC_REED_SOLOMON);
    }

    #[test]
    fn no_overlap_at_all_is_rejected() {
        // The client offers only ids no build implements. There is nothing both
        // ends can run, so the handshake must be refused rather than proceeding
        // with a profile that will fail on the first packet.
        let p = prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[DEFAULT_FEC_SCHEME],
        );
        let client = offer(&[201], &[], &[202]);
        let err = negotiate(&p, Some(&client), DEFAULT_TAG).unwrap_err();
        match err {
            ProfileError::NoCommonPart {
                part,
                server,
                client,
            } => {
                assert_eq!(part, PART_CIPHER);
                assert_eq!(server, [DEFAULT_CIPHER]);
                assert_eq!(client, ["id#201"]);
            }
            other => panic!("expected NoCommonPart, got {other:?}"),
        }
    }

    #[test]
    fn a_data_transport_is_negotiated_when_either_side_lists_one() {
        let p = prefs(
            &[DEFAULT_CIPHER],
            &["tagged", TRANSPORT_SAME_AS_HANDSHAKE],
            &[DEFAULT_FEC_SCHEME],
        );
        let client = offer(
            &[CIPHER_CHACHA20POLY1305],
            &[TRANSPORT_TAGGED],
            &[FEC_REED_SOLOMON],
        );
        let sel = negotiate(&p, Some(&client), [0x99, 0x88]).unwrap();
        assert_eq!(sel.transport, TRANSPORT_TAGGED);
        assert_eq!(
            sel.transport_tag,
            [0x99, 0x88],
            "the server's tag is carried"
        );
    }

    #[test]
    fn a_client_that_offers_no_transport_keeps_the_handshake_envelope() {
        // The marker is "nothing to negotiate": with a `same-as-handshake` data
        // preference and a client that says nothing about transports, the data
        // envelope *is* the handshake envelope.
        let p = prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[DEFAULT_FEC_SCHEME],
        );
        let client = offer(&[CIPHER_CHACHA20POLY1305], &[], &[FEC_REED_SOLOMON]);
        let sel = negotiate(&p, Some(&client), DEFAULT_TAG).unwrap();
        assert!(sel.reuses_handshake_transport());
    }

    #[test]
    fn a_client_may_override_the_marker_with_a_real_transport() {
        // The server is happy with `same-as-handshake`, but the client explicitly
        // offers `plain`, which the server can run. The compatibility fallback
        // takes it, so the client gets the envelope it asked for. Over a `plain`
        // handshake envelope the two are byte-identical, which is exactly why
        // this is safe.
        let p = prefs(
            &[DEFAULT_CIPHER],
            &[TRANSPORT_SAME_AS_HANDSHAKE],
            &[DEFAULT_FEC_SCHEME],
        );
        let client = offer(
            &[CIPHER_CHACHA20POLY1305],
            &[TRANSPORT_PLAIN],
            &[FEC_REED_SOLOMON],
        );
        let sel = negotiate(&p, Some(&client), DEFAULT_TAG).unwrap();
        assert_eq!(sel.transport, TRANSPORT_PLAIN);
        assert!(!sel.reuses_handshake_transport());
    }

    // ---- ResolvedProfile ----

    fn resolved(sel: &Selection) -> ResolvedProfile {
        ResolvedProfile::with_handshake_transport(
            sel,
            &[7u8; 32],
            &crate::transport::PlainTransport,
            crate::congestion::build_congestion(DEFAULT_CONGESTION).unwrap(),
        )
        .expect("selection is buildable")
    }

    #[test]
    fn a_default_resolved_profile_uses_the_handshake_envelope() {
        let r = resolved(&Selection::defaults());
        assert_eq!(r.cipher.name(), DEFAULT_CIPHER);
        assert_eq!(r.transport.name(), "plain");
        assert_eq!(r.fec.name(), DEFAULT_FEC_SCHEME);
        assert_eq!(r.congestion.name(), DEFAULT_CONGESTION);
    }

    #[test]
    fn a_negotiated_transport_replaces_the_handshake_envelope() {
        let sel = Selection {
            transport: TRANSPORT_TAGGED,
            transport_tag: [0x11, 0x22],
            ..Selection::defaults()
        };
        let r = ResolvedProfile::from_selection(
            &sel,
            &[0u8; 32],
            crate::congestion::build_congestion(DEFAULT_CONGESTION).unwrap(),
        )
        .unwrap();
        assert_eq!(r.transport.name(), "tagged");
        let wire = r.transport.wrap(b"hi");
        assert_eq!(&wire[..2], &[0x11, 0x22]);
    }

    #[test]
    fn a_no_fec_profile_reports_itself_inactive() {
        let sel = Selection {
            fec: FEC_NONE_ID,
            ..Selection::defaults()
        };
        let r = resolved(&sel);
        assert!(!r.fec.active());
        assert_eq!(r.fec.name(), FEC_NONE);
    }

    #[test]
    fn a_no_congestion_profile_never_refuses_a_send() {
        let sel = Selection::defaults();
        let mut r = ResolvedProfile::with_handshake_transport(
            &sel,
            &[0u8; 32],
            &crate::transport::PlainTransport,
            crate::congestion::build_congestion(CONGESTION_NONE).unwrap(),
        )
        .unwrap();
        assert_eq!(r.congestion.name(), CONGESTION_NONE);
        assert!(r.congestion.may_send(100_000));
    }

    #[test]
    fn an_unbuildable_selection_is_an_error_not_a_panic() {
        let sel = Selection {
            cipher: 240,
            ..Selection::defaults()
        };
        assert!(
            ResolvedProfile::from_selection(
                &sel,
                &[0u8; 32],
                crate::congestion::build_congestion(DEFAULT_CONGESTION).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn cloning_a_profile_rebuilds_congestion_state() {
        let sel = Selection {
            fec: FEC_NONE_ID,
            ..Selection::defaults()
        };
        let a = resolved(&sel);
        let mut b = a.clone();
        // Same configuration...
        assert_eq!(a.describe(), b.describe());
        // ...but independent congestion state, so one tunnel's window can never
        // throttle another's.
        b.congestion.on_send_bytes(5_000);
        assert_eq!(b.congestion.snapshot().in_flight, 5_000);
        assert_eq!(a.congestion.snapshot().in_flight, 0);
    }

    #[test]
    fn describe_names_every_part() {
        let d = resolved(&Selection::defaults()).describe();
        assert!(d.contains("cipher=chacha20poly1305"), "{d}");
        assert!(d.contains("transport=same-as-handshake"), "{d}");
        assert!(d.contains("fec=reed-solomon"), "{d}");
        assert!(d.contains("congestion=tcp-reno(local)"), "{d}");
    }

    // ---- LocalProfile ----

    #[test]
    fn a_default_local_profile_proposes_nothing() {
        let p = LocalProfile::from_role_config(
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        assert!(!p.propose);
        assert!(p.offer().is_none());
        assert_eq!(p.handshake_transport.name(), "plain");
        assert_eq!(p.congestion_name, DEFAULT_CONGESTION);
    }

    #[test]
    fn propose_true_makes_the_offer_available() {
        let p = LocalProfile::from_role_config(
            &crate::config::HandshakeConfig {
                kex: "noise-ik".into(),
                propose: true,
            },
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        let o = p.offer().expect("propose = true must produce an offer");
        assert_eq!(o.cipher_ids, [CIPHER_CHACHA20POLY1305]);
        assert_eq!(o.fec_ids, [FEC_REED_SOLOMON]);
    }

    #[test]
    fn a_bad_tag_hex_is_a_config_error() {
        let err = LocalProfile::from_role_config(
            &Default::default(),
            &Default::default(),
            &crate::config::TransportConfig {
                handshake: "plain".into(),
                data: vec![TRANSPORT_SAME_AS_HANDSHAKE.into()],
                tag_hex: Some("nothex".into()),
            },
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ProfileError::Config(_)), "got {err:?}");
    }

    #[test]
    fn a_good_tag_hex_is_applied_to_the_data_envelope() {
        let p = LocalProfile::from_role_config(
            &Default::default(),
            &Default::default(),
            &crate::config::TransportConfig {
                handshake: "plain".into(),
                data: vec!["tagged".into()],
                tag_hex: Some("abcd".into()),
            },
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(p.data_tag, [0xAB, 0xCD]);
        // The handshake envelope is unaffected: it is unkeyed and config-pinned
        // to the compiled-in default tag on both peers.
        assert_eq!(p.handshake_transport.name(), "plain");
    }

    #[test]
    fn an_unknown_handshake_envelope_is_rejected() {
        let err = LocalProfile::from_role_config(
            &Default::default(),
            &Default::default(),
            &crate::config::TransportConfig {
                handshake: "quic".into(),
                data: vec![TRANSPORT_SAME_AS_HANDSHAKE.into()],
                tag_hex: None,
            },
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap_err();
        assert!(matches!(err, ProfileError::Config(_)), "got {err:?}");
    }

    #[test]
    fn new_congestion_returns_independent_controllers() {
        let p = LocalProfile::from_role_config(
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        let mut a = p.new_congestion();
        let b = p.new_congestion();
        a.on_send_bytes(4_000);
        assert_eq!(a.snapshot().in_flight, 4_000);
        assert_eq!(
            b.snapshot().in_flight,
            0,
            "controllers must not share state"
        );
    }

    #[test]
    fn local_congestion_name_normalises_and_validates() {
        assert_eq!(local_congestion_name("").unwrap(), DEFAULT_CONGESTION);
        assert_eq!(local_congestion_name("  tcp-reno  ").unwrap(), "tcp-reno");
        assert_eq!(local_congestion_name("none").unwrap(), "none");
        assert!(local_congestion_name("bbr").is_err());
    }

    // ---- part_name ----

    #[test]
    fn part_name_resolves_known_ids_and_marks_unknown_ones() {
        assert_eq!(
            part_name(PART_CIPHER, CIPHER_CHACHA20POLY1305),
            DEFAULT_CIPHER
        );
        assert_eq!(part_name(PART_FEC, FEC_REED_SOLOMON), DEFAULT_FEC_SCHEME);
        assert_eq!(part_name(PART_TRANSPORT, TRANSPORT_TAGGED), "tagged");
        assert_eq!(part_name(PART_CIPHER, 222), "id#222");
    }
}
