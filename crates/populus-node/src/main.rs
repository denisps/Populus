//! Populus node executable.

use std::{net::IpAddr, process::ExitCode};

use populus_crypto::node_id;
use populus_network::parse_multiaddr;
use populus_node::{NetworkIdentity, Node, NodeEvent};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return ExitCode::from(2);
    };
    let Some(address) = args.next() else {
        print_usage();
        return ExitCode::from(2);
    };
    let Some(identity_ip) = args.next() else {
        print_usage();
        return ExitCode::from(2);
    };
    if command != "listen" || args.next().is_some() {
        print_usage();
        return ExitCode::from(2);
    }

    let identity = match parse_network_identity(&identity_ip) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("populus-node: invalid network identity: {error}");
            return ExitCode::FAILURE;
        }
    };
    match listen(&address, identity).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("populus-node: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("Usage: populus-node listen <multiaddr> <network-identity-ip>");
    eprintln!("  The eligible public identity IP is independent of the listen address.");
}

fn parse_network_identity(
    identity_ip: &str,
) -> Result<NetworkIdentity, Box<dyn std::error::Error + Send + Sync>> {
    Ok(NetworkIdentity::from_ip(identity_ip.parse::<IpAddr>()?)?)
}

async fn listen(
    address: &str,
    identity: NetworkIdentity,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut node = Node::new(node_id(&identity))?;
    node.listen_on(parse_multiaddr(address)?)?;
    println!("PeerId: {}", node.peer_id());
    println!("NodeId: {}", node.node_id());

    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                break;
            }
            event = node.next_event() => match event {
                NodeEvent::DirectVoteRequest {
                    vote: Ok(vote),
                    channel,
                    ..
                } => {
                    println!(
                        "Received direct vote: content={} client={} day={}",
                        vote.content_id(),
                        vote.client_id(),
                        vote.day().value()
                    );
                    if let Err(error) = node.send_response(channel, Vec::new()) {
                        eprintln!("Failed to send direct vote response: {error:?}");
                    }
                }
                NodeEvent::DirectVoteRequest { vote: Err(error), .. } => {
                    eprintln!("Rejected malformed direct vote: {error}");
                }
                NodeEvent::Transport(event) => println!("{event:?}"),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::parse_network_identity;
    use populus_crypto::node_id;

    #[test]
    fn executable_derives_node_id_from_the_configured_identity() {
        let first = parse_network_identity("8.8.8.8").expect("eligible identity");
        let second = parse_network_identity("1.1.1.1").expect("eligible identity");
        assert_ne!(node_id(&first), node_id(&second));
        assert!(parse_network_identity("127.0.0.1").is_err());
    }
}
