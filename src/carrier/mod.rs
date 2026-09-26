//! The carrier seam: what the protocol's bytes actually travel over.
//!
//! # Why this seam exists
//!
//! Phase 1 hard-coded [`tokio::net::UdpSocket`]: the daemon bound one, the
//! tunnel held an `Arc<UdpSocket>` and called `send_to(&wire, peer)`, and the
//! server demuxed many sessions off one shared socket by `recv_from`. Every
//! one of those sites assumed **datagram semantics** — that one send is one
//! delivery, that frames are self-delimiting, and that a peer may send from a
//! new source address (roaming).
//!
//! Those are exactly the assumptions a stream transport does not give you. So
//! the seam is defined in terms of *messages*, not bytes: a [`Carrier`] always
//! hands its caller exactly one whole protocol message and owns whatever
//! framing is needed to achieve that.
//!
//! # Datagram vs stream
//!
//! [`Carrier::preserves_boundaries`] is the key method here.
//!
//! - **Datagram** carriers (`udp`) already delimit: one `send` is one message,
//!   and the receiver learns the sender's current address each time. That is
//!   what makes NAT roaming work.
//! - **Stream** carriers (`tcp`) length-delimit with a 2-byte big-endian
//!   prefix (see [`STREAM_LEN_PREFIX`]) and hold the connection open. A stream
//!   cannot roam: [`Carrier::send`] ignores a changed `peer`.
//!
//! The protocol never learns which it got. That is deliberate — it is what
//! keeps the codec from having to invent a length field of its own.
//!
//! # The listener side
//!
//! A server needs a *listener*, and the two shapes differ in a way that
//! matters: a datagram listener yields more datagrams from one socket forever,
//! while a stream listener yields a **new connection** per client.
//! [`CarrierListener`] unifies both into one [`Inbound`] stream so the server's
//! select loop has a single arm.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// A boxed future, keeping the traits object-safe without an async-trait
/// dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// A bidirectional pipe for protocol messages.
///
/// Sends take `&self` so one carrier can be shared: the server's socket is
/// used by every session concurrently, which is why this is an
/// `Arc<dyn Carrier>` rather than an owned handle.
pub trait Carrier: Send + Sync + 'static {
    /// Config name, e.g. `"udp"`. Stable; appears in the config file.
    fn name(&self) -> &'static str;

    /// Whether one `send` is one self-delimiting message that arrives intact.
    ///
    /// `false` means this carrier length-delimits and reassembles, so
    /// [`Carrier::recv`] yields a whole message either way. The practical
    /// difference shows up as roaming — see [`Carrier::supports_roaming`].
    fn preserves_boundaries(&self) -> bool;

    /// Whether the peer address may change mid-session.
    ///
    /// A stream carrier is pinned to its connection and returns `false`; the
    /// tunnel then skips its roam-detection bookkeeping instead of treating a
    /// fixed address as a suspicious change.
    fn supports_roaming(&self) -> bool {
        self.preserves_boundaries()
    }

    /// Send one protocol message toward `peer`.
    ///
    /// `peer` is ignored by a non-roaming carrier, which is already connected.
    fn send(&self, data: &[u8], peer: SocketAddr) -> BoxFuture<'_, io::Result<()>>;

    /// Receive exactly one whole protocol message, with the address it came
    /// from.
    ///
    /// Implementations must not return a partial message.
    fn recv(&self) -> BoxFuture<'_, io::Result<(Bytes, SocketAddr)>>;

    /// Hand-roll a clone. Object safety precludes `Clone`.
    ///
    /// Both implementations are genuinely cheap: each holds its halves behind
    /// an `Arc`, so cloning shares the socket rather than duplicating it.
    fn box_clone(&self) -> Box<dyn Carrier>;
}

impl Clone for Box<dyn Carrier> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

/// One inbound event on a [`CarrierListener`].
pub enum Inbound {
    /// A self-delimiting message from `from`. Datagram carriers only.
    Datagram { data: Bytes, from: SocketAddr },
    /// A newly accepted connection. Stream carriers only.
    ///
    /// A stream connection *is* a session's identity — several sessions cannot
    /// share one — so the server runs the handshake directly on `carrier`
    /// rather than peek-routing it like a datagram.
    Connection {
        carrier: Arc<dyn Carrier>,
        from: SocketAddr,
    },
}

impl std::fmt::Debug for Inbound {
    /// Hand-rolled because a `dyn Carrier` is not `Debug`. A stream connection
    /// prints as its kind only — a socket handle in a log is noise.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Datagram { data, from } => f
                .debug_struct("Datagram")
                .field("len", &data.len())
                .field("from", &from)
                .finish(),
            Self::Connection { carrier, from } => f
                .debug_struct("Connection")
                .field("carrier", &carrier.name())
                .field("from", &from)
                .finish(),
        }
    }
}

impl Inbound {
    /// The source address, for logging and rate limiting.
    pub fn from(&self) -> SocketAddr {
        match self {
            Self::Datagram { from, .. } | Self::Connection { from, .. } => *from,
        }
    }

    /// Short kind name for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Datagram { .. } => "datagram",
            Self::Connection { .. } => "connection",
        }
    }
}

/// The server's accept side.
pub trait CarrierListener: Send + Sync + 'static {
    /// Config name of the carrier this listener serves.
    fn name(&self) -> &'static str;

    /// Mirrors [`Carrier::preserves_boundaries`] for the connections it
    /// yields, so the server knows whether to expect [`Inbound::Connection`] or
    /// [`Inbound::Datagram`].
    fn preserves_boundaries(&self) -> bool;

    /// Await the next inbound event.
    fn next_event(&self) -> BoxFuture<'_, io::Result<Inbound>>;

    /// The carrier a server answers datagrams on, if this listener has one.
    ///
    /// `Some` for a datagram listener: the socket is shared, so one server can
    /// answer every session from it. `None` for a stream listener, where a
    /// session's carrier is the connection it arrived on (see
    /// [`Inbound::Connection`]).
    fn sender(&self) -> Option<Arc<dyn Carrier>>;
}

/// Length prefix a stream carrier puts in front of each message.
///
/// Big-endian so the common case (messages under 256 bytes) puts the length in
/// the first byte.
pub const STREAM_LEN_PREFIX: usize = 2;

/// Largest single message a stream carrier will accept, in bytes.
///
/// The 2-byte prefix caps this structurally, and it sits above the largest
/// frame the protocol can produce (a full-MTU payload plus header, AEAD tag and
/// envelope), so a legitimate message never gets rejected.
pub const STREAM_MAX_MESSAGE: usize = 65535;

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

/// The UDP carrier: one socket, shared by every session.
///
/// Sends use `&self` (`UdpSocket::send_to` takes `&self`), so concurrent sends
/// need no lock. Receives are serialised through a single reader task.
pub struct UdpCarrier {
    sock: Arc<UdpSocket>,
    /// Address reported by `recv` when the socket gives an unspecified source.
    ///
    /// Not reachable on a real UDP socket (every datagram has a source), but it
    /// keeps the type total and mirrors the stream carrier's shape.
    fallback_peer: SocketAddr,
}

impl UdpCarrier {
    /// Wrap an already-bound socket.
    pub fn new(sock: Arc<UdpSocket>, fallback_peer: SocketAddr) -> Self {
        Self {
            sock,
            fallback_peer,
        }
    }

    /// The underlying socket, for callers that need socket options.
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.sock
    }
}

impl Carrier for UdpCarrier {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn preserves_boundaries(&self) -> bool {
        true
    }

    fn send(&self, data: &[u8], peer: SocketAddr) -> BoxFuture<'_, io::Result<()>> {
        let sock = self.sock.clone();
        let data = data.to_vec();
        Box::pin(async move { sock.send_to(&data, peer).await.map(|_| ()) })
    }

    fn recv(&self) -> BoxFuture<'_, io::Result<(Bytes, SocketAddr)>> {
        let fallback = self.fallback_peer;
        let sock = self.sock.clone();
        Box::pin(async move {
            let mut buf = vec![0u8; 65535];
            let (n, from) = sock.recv_from(&mut buf).await?;
            buf.truncate(n);
            let from = if from.ip().is_unspecified() {
                fallback
            } else {
                from
            };
            Ok((Bytes::from(buf), from))
        })
    }

    fn box_clone(&self) -> Box<dyn Carrier> {
        Box::new(Self {
            sock: self.sock.clone(),
            fallback_peer: self.fallback_peer,
        })
    }
}

/// The server's UDP accept side: more datagrams from one socket, forever.
///
/// This is what lets a single socket serve many sessions.
pub struct UdpListener {
    sock: Arc<UdpSocket>,
    fallback_peer: SocketAddr,
}

impl UdpListener {
    /// Wrap an already-bound socket.
    pub fn new(sock: Arc<UdpSocket>, fallback_peer: SocketAddr) -> Self {
        Self {
            sock,
            fallback_peer,
        }
    }

    /// The underlying socket, for socket options.
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.sock
    }
}

impl CarrierListener for UdpListener {
    fn name(&self) -> &'static str {
        "udp"
    }

    fn preserves_boundaries(&self) -> bool {
        true
    }

    fn next_event(&self) -> BoxFuture<'_, io::Result<Inbound>> {
        let fallback = self.fallback_peer;
        let sock = self.sock.clone();
        Box::pin(async move {
            let mut buf = vec![0u8; 65535];
            let (n, from) = sock.recv_from(&mut buf).await?;
            buf.truncate(n);
            let from = if from.ip().is_unspecified() {
                fallback
            } else {
                from
            };
            Ok(Inbound::Datagram {
                data: Bytes::from(buf),
                from,
            })
        })
    }

    fn sender(&self) -> Option<Arc<dyn Carrier>> {
        // The same socket, shared: a server answers every session from it.
        Some(Arc::new(UdpCarrier::new(
            self.sock.clone(),
            self.fallback_peer,
        )))
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// The TCP carrier: one connection, length-delimited.
///
/// Halves sit behind `Arc` so `box_clone` genuinely shares the connection
/// rather than duplicating it — a stream cannot be duplicated at the socket
/// level, so "clone" here must mean "another handle to the same one".
pub struct TcpCarrier {
    write: Arc<Mutex<OwnedWriteHalf>>,
    read: Arc<Mutex<ReadState>>,
    peer: SocketAddr,
}

struct ReadState {
    stream: OwnedReadHalf,
    /// Bytes received but not yet consumed as a whole message.
    leftover: Vec<u8>,
}

impl TcpCarrier {
    /// Split a connected stream into a carrier.
    pub fn new(stream: TcpStream, peer: SocketAddr) -> io::Result<Self> {
        // Nagle would hold our small pong/ack frames behind a delayed ACK, and
        // the protocol is latency-sensitive (RTT probes, keepalives).
        stream.set_nodelay(true)?;
        let (read, write) = stream.into_split();
        Ok(Self {
            write: Arc::new(Mutex::new(write)),
            read: Arc::new(Mutex::new(ReadState {
                stream: read,
                leftover: Vec::new(),
            })),
            peer,
        })
    }

    /// Connect to `remote` and wrap the resulting connection.
    pub async fn connect(remote: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(remote).await?;
        Self::new(stream, remote)
    }

    /// Read one length-delimited message, reassembling across reads.
    async fn read_message(&self) -> io::Result<Bytes> {
        let mut st = self.read.lock().await;
        let mut chunk = [0u8; 8192];
        loop {
            // Drain any whole message already buffered before touching the
            // socket: a previous read usually over-read several messages.
            if let Some(msg) = take_message(&mut st.leftover) {
                return Ok(msg);
            }
            let n = st.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    if st.leftover.is_empty() {
                        "carrier closed"
                    } else {
                        "carrier closed mid-message"
                    },
                ));
            }
            st.leftover.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Pull one length-delimited message off the front of `buf`, if complete.
///
/// Trailing bytes stay in `buf` for the next call — that is the reassembly.
fn take_message(buf: &mut Vec<u8>) -> Option<Bytes> {
    if buf.len() < STREAM_LEN_PREFIX {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len == 0 {
        // A zero-length message is not a legal frame. Returning `None` keeps
        // the reader waiting for more bytes rather than spinning, and the
        // reader's own length check rejects the empty message once the socket
        // delivers the rest of whatever is coming.
        return None;
    }
    if buf.len() < STREAM_LEN_PREFIX + len {
        return None;
    }
    let msg = buf[STREAM_LEN_PREFIX..STREAM_LEN_PREFIX + len].to_vec();
    buf.drain(..STREAM_LEN_PREFIX + len);
    Some(Bytes::from(msg))
}

impl Carrier for TcpCarrier {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn preserves_boundaries(&self) -> bool {
        false
    }

    fn supports_roaming(&self) -> bool {
        // A stream connection is pinned; the peer address cannot change.
        false
    }

    fn send(&self, data: &[u8], _peer: SocketAddr) -> BoxFuture<'_, io::Result<()>> {
        if data.len() > STREAM_MAX_MESSAGE {
            // Must not truncate: `as u16` would silently corrupt the length
            // and desynchronise the stream permanently.
            let len = data.len();
            return Box::pin(async move {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("message of {len} bytes exceeds the stream carrier limit"),
                ))
            });
        }
        let mut framed = Vec::with_capacity(STREAM_LEN_PREFIX + data.len());
        framed.extend_from_slice(&(data.len() as u16).to_be_bytes());
        framed.extend_from_slice(data);
        Box::pin(async move {
            let mut w = self.write.lock().await;
            w.write_all(&framed).await?;
            w.flush().await
        })
    }

    fn recv(&self) -> BoxFuture<'_, io::Result<(Bytes, SocketAddr)>> {
        Box::pin(async move { Ok((self.read_message().await?, self.peer)) })
    }

    fn box_clone(&self) -> Box<dyn Carrier> {
        // Shares the same connection. A stream socket cannot be duplicated
        // below this layer, so "clone" necessarily means "another handle".
        Box::new(Self {
            write: self.write.clone(),
            read: self.read.clone(),
            peer: self.peer,
        })
    }
}

/// The server's TCP accept side: a new connection per client.
pub struct TcpListenerHandle {
    listener: TcpListener,
}

impl TcpListenerHandle {
    /// Bind a TCP listener.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }

    /// The bound address, for logs and for tests that need port 0.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

impl CarrierListener for TcpListenerHandle {
    fn name(&self) -> &'static str {
        "tcp"
    }

    fn preserves_boundaries(&self) -> bool {
        false
    }

    fn next_event(&self) -> BoxFuture<'_, io::Result<Inbound>> {
        Box::pin(async move {
            let (stream, from) = self.listener.accept().await?;
            let carrier = TcpCarrier::new(stream, from)?;
            Ok(Inbound::Connection {
                carrier: Arc::new(carrier),
                from,
            })
        })
    }

    fn sender(&self) -> Option<Arc<dyn Carrier>> {
        // No shared socket: each session answers on its own connection.
        None
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Every carrier name this build implements.
pub const KNOWN_CARRIERS: &[&str] = &["udp", "tcp"];

/// Whether a carrier name is known to this build.
///
/// Config validation calls this so an unknown name is a hard error at startup
/// rather than a failed connect later.
pub fn is_known_carrier(name: &str) -> bool {
    KNOWN_CARRIERS.contains(&name)
}

/// Bind a server-side listener for the named carrier.
pub async fn bind_carrier_listener(
    name: &str,
    addr: SocketAddr,
) -> io::Result<Box<dyn CarrierListener>> {
    match name {
        "udp" => {
            let sock = Arc::new(UdpSocket::bind(addr).await?);
            Ok(Box::new(UdpListener::new(sock, addr)))
        }
        "tcp" => Ok(Box::new(TcpListenerHandle::bind(addr).await?)),
        other => Err(unknown_carrier(other)),
    }
}

/// Connect a client-side carrier to `remote`.
pub async fn connect_carrier(name: &str, remote: SocketAddr) -> io::Result<Box<dyn Carrier>> {
    match name {
        "udp" => {
            // A fresh ephemeral port per connection attempt, mirroring the
            // client's previous behaviour of binding a new socket each time.
            let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
            // `connect` is advisory for UDP: it fixes a default peer and lets
            // the OS surface ICMP port-unreachable, but we still `send_to` an
            // explicit address so roaming can move it.
            let _ = sock.connect(remote).await;
            Ok(Box::new(UdpCarrier::new(sock, remote)))
        }
        "tcp" => Ok(Box::new(TcpCarrier::connect(remote).await?)),
        other => Err(unknown_carrier(other)),
    }
}

fn unknown_carrier(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "unknown carrier {name:?}; this build implements {}",
            KNOWN_CARRIERS.join(", ")
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// Drive a TCP listener's accept once and hand back the accepted carrier.
    async fn accept_one(l: &TcpListenerHandle) -> Arc<dyn Carrier> {
        match l.next_event().await.unwrap() {
            Inbound::Connection { carrier, .. } => carrier,
            other => panic!("tcp listener must yield a connection, got {}", other.kind()),
        }
    }

    #[test]
    fn registry_knows_exactly_udp_and_tcp() {
        assert!(is_known_carrier("udp"));
        assert!(is_known_carrier("tcp"));
        assert!(!is_known_carrier("quic"));
        assert!(!is_known_carrier(""));
        assert!(!is_known_carrier("UDP"), "names are case-sensitive");
        assert_eq!(KNOWN_CARRIERS, ["udp", "tcp"]);
    }

    // -- take_message: the reassembly primitive ---------------------------

    #[test]
    fn take_message_needs_the_prefix_first() {
        let mut buf = vec![0x00];
        assert!(take_message(&mut buf).is_none(), "1 byte < 2-byte prefix");
    }

    #[test]
    fn take_message_needs_the_whole_body() {
        let mut buf = vec![0x00, 0x04, 1, 2];
        assert!(
            take_message(&mut buf).is_none(),
            "declared 4 bytes, only 2 present"
        );
    }

    #[test]
    fn take_message_yields_one_message_and_keeps_the_remainder() {
        let mut buf = vec![0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x00, 0x02, 0xDD, 0xEE];
        let first = take_message(&mut buf).expect("first message is complete");
        assert_eq!(&first[..], &[0xAA, 0xBB, 0xCC]);
        let second = take_message(&mut buf).expect("second message is complete");
        assert_eq!(&second[..], &[0xDD, 0xEE]);
        assert!(take_message(&mut buf).is_none(), "buffer drained");
    }

    #[test]
    fn take_message_reassembles_across_arbitrary_splits() {
        // The same five bytes delivered one at a time must reassemble, and
        // must not yield early.
        let wire = [0x00u8, 0x03, 0xAA, 0xBB, 0xCC];
        let mut buf = Vec::new();
        for (i, b) in wire.iter().enumerate() {
            buf.push(*b);
            let got = take_message(&mut buf);
            if i + 1 < wire.len() {
                assert!(got.is_none(), "must not yield at byte {}", i + 1);
            } else {
                assert_eq!(&got.expect("complete on the last byte")[..], &wire[2..]);
            }
        }
    }

    #[test]
    fn take_message_handles_a_max_length_message() {
        let len = STREAM_MAX_MESSAGE;
        let mut buf = Vec::with_capacity(STREAM_LEN_PREFIX + len);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
        buf.extend(std::iter::repeat_n(0x5A, len));
        let got = take_message(&mut buf).expect("max-length message is complete");
        assert_eq!(got.len(), len);
    }

    #[test]
    fn a_zero_length_message_never_completes() {
        // Otherwise a corrupt stream would spin the reader forever.
        let mut buf = vec![0x00, 0x00];
        assert!(take_message(&mut buf).is_none());
    }

    // -- UDP ---------------------------------------------------------------

    #[tokio::test]
    async fn udp_carrier_round_trips_a_message() {
        let server = Arc::new(UdpSocket::bind(loopback()).await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let client = UdpCarrier::new(
            Arc::new(UdpSocket::bind(loopback()).await.unwrap()),
            server_addr,
        );

        client.send(b"hello", server_addr).await.unwrap();
        let mut buf = vec![0u8; 64];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_ne!(
            from.ip(),
            std::net::Ipv4Addr::UNSPECIFIED,
            "a real datagram always has a source"
        );
    }

    #[tokio::test]
    async fn udp_listener_yields_datagrams() {
        let server = Arc::new(UdpSocket::bind(loopback()).await.unwrap());
        let addr = server.local_addr().unwrap();
        let client = UdpCarrier::new(Arc::new(UdpSocket::bind(loopback()).await.unwrap()), addr);

        let listener = UdpListener::new(server, addr);
        client.send(b"one", addr).await.unwrap();
        client.send(b"two", addr).await.unwrap();
        for expected in [b"one", b"two"] {
            let ev = listener.next_event().await.unwrap();
            assert_eq!(ev.kind(), "datagram");
            match ev {
                Inbound::Datagram { data, .. } => assert_eq!(&data[..], expected),
                _ => unreachable!(),
            }
        }
    }

    #[tokio::test]
    async fn udp_carrier_preserves_one_message_per_send() {
        // The datagram guarantee the whole seam rests on: no coalescing.
        let server = Arc::new(UdpSocket::bind(loopback()).await.unwrap());
        let addr = server.local_addr().unwrap();
        let client = UdpCarrier::new(Arc::new(UdpSocket::bind(loopback()).await.unwrap()), addr);
        client.send(b"aaaa", addr).await.unwrap();
        client.send(b"bbbb", addr).await.unwrap();

        let listener = UdpListener::new(server, addr);
        let a = listener.next_event().await.unwrap();
        let b = listener.next_event().await.unwrap();
        let (Inbound::Datagram { data: a, .. }, Inbound::Datagram { data: b, .. }) = (a, b) else {
            panic!("expected two datagrams");
        };
        assert_eq!(&a[..], b"aaaa");
        assert_eq!(&b[..], b"bbbb");
    }

    #[tokio::test]
    async fn connect_carrier_udp_binds_an_ephemeral_port() {
        let server = Arc::new(UdpSocket::bind(loopback()).await.unwrap());
        let addr = server.local_addr().unwrap();
        let carrier = connect_carrier("udp", addr).await.unwrap();
        assert_eq!(carrier.name(), "udp");
        assert!(carrier.preserves_boundaries());
        assert!(carrier.supports_roaming(), "udp roams");

        carrier.send(b"x", addr).await.unwrap();
        let mut b = vec![0u8; 8];
        let (n, _) = server.recv_from(&mut b).await.unwrap();
        assert_eq!(&b[..n], b"x");
    }

    // -- TCP ---------------------------------------------------------------

    #[tokio::test]
    async fn tcp_carrier_round_trips_several_messages_in_order() {
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpCarrier::connect(addr).await.unwrap();
        let server = accept_one(&listener).await;

        let task = tokio::spawn(async move {
            let a = server.recv().await.unwrap().0;
            let b = server.recv().await.unwrap().0;
            server.send(b"pong-1", addr).await.unwrap();
            server.send(b"pong-2", addr).await.unwrap();
            (a, b)
        });

        client.send(b"one", addr).await.unwrap();
        client.send(b"two", addr).await.unwrap();
        let (a, b) = task.await.unwrap();
        assert_eq!(&a[..], b"one");
        assert_eq!(&b[..], b"two");
        assert_eq!(&client.recv().await.unwrap().0[..], b"pong-1");
        assert_eq!(&client.recv().await.unwrap().0[..], b"pong-2");
    }

    #[tokio::test]
    async fn tcp_carrier_reassembles_a_message_split_across_writes() {
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Dial raw so we control how the bytes are chopped up.
        let mut raw = TcpStream::connect(addr).await.unwrap();
        let server = accept_one(&listener).await;
        let got = tokio::spawn(async move { server.recv().await.unwrap().0 });

        let body = b"reassembled-payload";
        let mut framed = Vec::new();
        framed.extend_from_slice(&(body.len() as u16).to_be_bytes());
        framed.extend_from_slice(body);
        // Write one byte at a time with a yield between, so the reader
        // genuinely sees the message arrive in pieces.
        for b in &framed {
            raw.write_all(&[*b]).await.unwrap();
            raw.flush().await.unwrap();
            tokio::task::yield_now().await;
        }
        assert_eq!(&got.await.unwrap()[..], body);
    }

    #[tokio::test]
    async fn tcp_carrier_handles_two_messages_in_one_write() {
        // The over-read case: one write carrying two whole messages, plus a
        // partial third.
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut raw = TcpStream::connect(addr).await.unwrap();
        let server = accept_one(&listener).await;

        let mut wire = Vec::new();
        for body in [&b"first"[..], &b"second"[..]] {
            wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
            wire.extend_from_slice(body);
        }
        // A partial third message: prefix says 5, only 2 bytes follow.
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(&b"th"[..]);
        raw.write_all(&wire).await.unwrap();
        raw.flush().await.unwrap();

        assert_eq!(&server.recv().await.unwrap().0[..], b"first");
        assert_eq!(&server.recv().await.unwrap().0[..], b"second");
    }

    #[tokio::test]
    async fn tcp_carrier_reports_a_clean_close() {
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpCarrier::connect(addr).await.unwrap();
        let server = accept_one(&listener).await;
        // Dropping the last server handle closes the socket.
        drop(server);
        let err = client.recv().await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn tcp_carrier_ignores_the_peer_argument() {
        // A stream is pinned: sending to a "new" address must still reach the
        // connected peer rather than erroring or going nowhere.
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpCarrier::connect(addr).await.unwrap();
        let server = accept_one(&listener).await;

        let bogus: SocketAddr = "192.0.2.1:9".parse().unwrap();
        client.send(b"still-arrives", bogus).await.unwrap();
        assert_eq!(&server.recv().await.unwrap().0[..], b"still-arrives");
    }

    #[tokio::test]
    async fn tcp_carrier_reports_the_pinned_peer_and_no_roaming() {
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpCarrier::connect(addr).await.unwrap();
        assert!(!client.preserves_boundaries());
        assert!(!client.supports_roaming(), "a stream is pinned");

        let server = accept_one(&listener).await;
        client.send(b"x", addr).await.unwrap();
        let (_, from) = server.recv().await.unwrap();
        assert_eq!(from.ip(), addr.ip());
    }

    #[tokio::test]
    async fn tcp_box_clone_shares_the_connection() {
        // Cloning must yield another handle to the same stream, not a second
        // socket: a message sent via the clone must be readable from the
        // original.
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpCarrier::connect(addr).await.unwrap();
        let server = accept_one(&listener).await;

        let cloned = client.box_clone();
        cloned.send(b"via-clone", addr).await.unwrap();
        assert_eq!(&server.recv().await.unwrap().0[..], b"via-clone");
        client.send(b"via-original", addr).await.unwrap();
        assert_eq!(&server.recv().await.unwrap().0[..], b"via-original");
    }

    #[tokio::test]
    async fn tcp_send_refuses_an_oversized_message() {
        // Truncating the length to u16 would desynchronise the stream
        // permanently, so this must be a hard error.
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpCarrier::connect(addr).await.unwrap();
        let _server = accept_one(&listener).await;

        let too_big = vec![0u8; STREAM_MAX_MESSAGE + 1];
        let err = client.send(&too_big, addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("exceeds"));
    }

    #[tokio::test]
    async fn a_maximum_size_message_survives_the_length_prefix() {
        // The boundary: exactly STREAM_MAX_MESSAGE must go through, because
        // 65535 is the largest value a 2-byte prefix can express.
        let listener = TcpListenerHandle::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpCarrier::connect(addr).await.unwrap();
        let server = accept_one(&listener).await;

        let body = vec![0xABu8; STREAM_MAX_MESSAGE];
        let got = tokio::spawn({
            let server = server.clone();
            async move { server.recv().await.unwrap().0 }
        });
        client.send(&body, addr).await.unwrap();
        assert_eq!(got.await.unwrap().len(), STREAM_MAX_MESSAGE);
    }

    // -- registry errors ---------------------------------------------------

    #[tokio::test]
    async fn bind_and_connect_reject_an_unknown_carrier() {
        let e = match bind_carrier_listener("quic", loopback()).await {
            Err(e) => e,
            Ok(_) => panic!("an unknown carrier must not bind"),
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("quic"));
        assert!(
            e.to_string().contains("udp, tcp"),
            "error lists what exists"
        );

        let e = match connect_carrier("quic", "127.0.0.1:1".parse().unwrap()).await {
            Err(e) => e,
            Ok(_) => panic!("an unknown carrier must not connect"),
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }
}
