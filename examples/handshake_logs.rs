//! Verification harness: exercises the exact production handshake-logging path
//! (`tunnel::handshake::respond_message_1`, the per-datagram primitive the
//! multi-client server dispatcher calls) with real Noise IK message-1 packets
//! and a live tracing subscriber at info level, so the printed output matches
//! what a real `rustnies server` emits.
//!
//! Run: `cargo run --example handshake_logs`

use std::net::SocketAddr;

use rustnies::crypto::keys::KeyPair;
use rustnies::crypto::noise::{HandshakeRole, NoiseHandshake};
use rustnies::obfuscation::ObfuscationStack;
use rustnies::protocol::profile::LocalProfile;
use rustnies::tunnel::handshake::{Authorizer, respond_message_1};

/// The rustnies default profile: plain envelope, ChaCha20-Poly1305, the
/// TCP-inspired controller, no client proposal. Matches what the daemon builds
/// from a config file with no `[handshake]`/`[crypto]`/`[transport]` sections.
fn default_profile() -> LocalProfile {
    LocalProfile::from_role_config(
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
        &Default::default(),
    )
    .expect("the default config must resolve to a usable profile")
}

fn clone_keypair(kp: &KeyPair) -> KeyPair {
    let bytes = kp.secret.to_bytes();
    let secret = rustnies::crypto::keys::StaticSecret::from(bytes);
    let public = rustnies::crypto::keys::PublicKey::from(&secret);
    KeyPair { secret, public }
}

fn build_msg1(
    client_kp: &KeyPair,
    server_pub: rustnies::crypto::keys::PublicKey,
    profile: &LocalProfile,
) -> Vec<u8> {
    let mut hs = NoiseHandshake::new(
        HandshakeRole::Initiator,
        clone_keypair(client_kp),
        Some(server_pub),
    );
    // Append the profile offer when the client is configured to propose, which
    // is what a real client does; the server accepts both shapes.
    let m1 = hs
        .write_message_1(&profile.offer().map(|o| o.encode()).unwrap_or_default())
        .unwrap();
    profile.handshake_transport.wrap(&m1)
}

fn run(
    label: &str,
    server_kp: &KeyPair,
    profile: &LocalProfile,
    wire: &[u8],
    from: SocketAddr,
    authorizer: Option<Authorizer<'_>>,
) {
    println!("\n========== {label} ==========");
    let obf = ObfuscationStack::new();
    let res = respond_message_1(server_kp, profile, &obf, wire, from, authorizer);
    println!(
        "-> respond_message_1 returned {}",
        if res.is_some() {
            "Some (accepted)"
        } else {
            "None (not accepted)"
        }
    );
}

#[tokio::main]
async fn main() {
    // Match the daemon's subscriber: default info, honour RUST_LOG.
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();

    let server_kp = KeyPair::generate();
    let authorized_client = KeyPair::generate();
    let rogue_client = KeyPair::generate();
    let profile = default_profile();
    let from: SocketAddr = "203.0.113.7:51820".parse().unwrap();

    // Authorizer that only admits `authorized_client` (named "alice").
    let allowed_bytes = authorized_client.public_bytes();
    let auth_fn: Box<dyn Fn(&rustnies::crypto::keys::PublicKey) -> (bool, Option<String>)> =
        Box::new(move |pk| {
            if pk.to_bytes() == allowed_bytes {
                (true, Some("alice".to_string()))
            } else {
                (false, None)
            }
        });

    // 1. Unauthorized key: a real, well-formed Noise message 1 from a client
    //    whose static key is NOT in the authorized list.
    let rogue_wire = build_msg1(&rogue_client, server_kp.public, &profile);
    run(
        "CASE 1: unauthorized client key (real handshake, not in authorized list)",
        &server_kp,
        &profile,
        &rogue_wire,
        from,
        Some(&*auth_fn),
    );

    // 2. Authorized key: a real Noise message 1 from the authorized client.
    let good_wire = build_msg1(&authorized_client, server_kp.public, &profile);
    run(
        "CASE 2: authorized client key (in authorized list as 'alice')",
        &server_kp,
        &profile,
        &good_wire,
        from,
        Some(&*auth_fn),
    );

    // 3. Handshake failed (crypto/parsing error): a real message 1 built for a
    //    DIFFERENT server key, so the server's Noise decryption of the static
    //    key fails.
    let other_server = KeyPair::generate();
    let wrong_wire = build_msg1(&authorized_client, other_server.public, &profile);
    run(
        "CASE 3: handshake failed (built for the wrong server key)",
        &server_kp,
        &profile,
        &wrong_wire,
        from,
        Some(&*auth_fn),
    );

    // 4. Garbage / scan traffic: a too-short datagram. Stays at debug, so it
    //    should NOT appear at the default info level.
    let garbage = vec![0u8; 11];
    run(
        "CASE 4: garbage/scan datagram (too short; debug-only, invisible at info)",
        &server_kp,
        &profile,
        &garbage,
        from,
        Some(&*auth_fn),
    );

    println!("\n========== done ==========");
}
