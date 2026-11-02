//! Populus node executable.

use std::{
    net::{IpAddr, Ipv4Addr},
    process::ExitCode,
};

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
    if command != "listen" || args.next().is_some() {
        print_usage();
        return ExitCode::from(2);
    }

    match listen(&address).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("populus-node: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("Usage: populus-node listen <multiaddr>");
}

async fn listen(address: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let identity = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))?;
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
                NodeEvent::DirectVoteRequest { vote: Ok(vote), .. } => {
                    println!(
                        "Received direct vote: content={} client={} day={}",
                        vote.content_id(),
                        vote.client_id(),
                        vote.day().value()
                    );
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
