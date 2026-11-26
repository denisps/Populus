//! Runnable Populus transport process.

use std::{path::PathBuf, process::ExitCode};

use populus_network::parse_multiaddr;
use populus_node::{
    ApplicationErrorCode, ApplicationMessage, FilePeerIdentityStore, IdentityManagerConfig,
    PopulusProcess, ProcessEvent,
};
use populus_protocol::PUBLIC_NETWORK_ID;
use populus_types::NetworkId;
use tracing::{Level, error, info, warn};

const DEFAULT_LISTEN: &str = "/ip4/0.0.0.0/tcp/4001";
const DEFAULT_IDENTITY_PATH: &str = ".populus/peer.key";
const MAX_CONFIGURED_NODE_IDS: usize = 64;

#[derive(Debug)]
struct RunOptions {
    listen_addresses: Vec<String>,
    bootstrap_addresses: Vec<String>,
    identity_key_path: PathBuf,
    max_node_ids: usize,
    network_id: NetworkId,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            listen_addresses: vec![DEFAULT_LISTEN.to_owned()],
            bootstrap_addresses: Vec::new(),
            identity_key_path: PathBuf::from(DEFAULT_IDENTITY_PATH),
            max_node_ids: 4,
            network_id: PUBLIC_NETWORK_ID,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    if let Err(error) = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .try_init()
    {
        eprintln!("populus-node: failed to initialize tracing: {error}");
        return ExitCode::FAILURE;
    }

    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--help" || argument == "help")
    {
        print_usage();
        return ExitCode::SUCCESS;
    }
    if arguments.first().is_none_or(|command| command != "run") {
        print_usage();
        return ExitCode::from(2);
    }
    let options = match parse_options(&arguments[1..]) {
        Ok(options) => options,
        Err(error) => {
            error!(%error, "invalid command-line configuration");
            print_usage();
            return ExitCode::from(2);
        }
    };

    match run(options).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "node process stopped");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: populus-node run [--config FILE] [--network-id HEX] [--listen MULTIADDR] \
         [--bootstrap MULTIADDR] [--identity-key FILE] [--max-node-ids N] \
         "
    );
    eprintln!("Defaults: listen on {DEFAULT_LISTEN}; persist PeerId in {DEFAULT_IDENTITY_PATH}.");
    eprintln!("The default network ID is the fixed public Populus network.");
}

fn parse_options(arguments: &[String]) -> Result<RunOptions, String> {
    let mut options = RunOptions::default();
    let mut config_path = None;
    let mut config_index = 0;
    while config_index < arguments.len() {
        let option = &arguments[config_index];
        let Some(value) = arguments.get(config_index + 1) else {
            return Err(format!("missing value for {option}"));
        };
        if option == "--config" && config_path.replace(PathBuf::from(value)).is_some() {
            return Err("--config may be supplied only once".to_owned());
        }
        config_index += 2;
    }
    if let Some(path) = config_path {
        parse_config_file(&path, &mut options)?;
    }

    let mut index = 0;
    let mut command_line_listen = false;
    while index < arguments.len() {
        let option = arguments
            .get(index)
            .ok_or_else(|| "missing option".to_owned())?;
        index += 1;
        if option == "--config" {
            index += 1;
            continue;
        }
        let value = arguments
            .get(index)
            .ok_or_else(|| format!("missing value for {option}"))?;
        index += 1;
        match option.as_str() {
            "--listen" => {
                if !command_line_listen {
                    options.listen_addresses.clear();
                    command_line_listen = true;
                }
                options.listen_addresses.push(value.clone());
            }
            "--bootstrap" => options.bootstrap_addresses.push(value.clone()),
            "--identity-key" => options.identity_key_path = PathBuf::from(value),
            "--max-node-ids" => {
                options.max_node_ids = value
                    .parse()
                    .map_err(|_| "max-node-ids must be an integer".to_owned())?;
            }
            "--network-id" => {
                options.network_id = value.parse().map_err(|error| {
                    format!("network-id must be 64 lowercase hex characters: {error}")
                })?;
            }
            _ => return Err(format!("unknown option: {option}")),
        }
    }
    if options.max_node_ids == 0 || options.max_node_ids > MAX_CONFIGURED_NODE_IDS {
        return Err(format!(
            "max-node-ids must be between 1 and {MAX_CONFIGURED_NODE_IDS}"
        ));
    }
    Ok(options)
}

fn parse_config_file(path: &std::path::Path, options: &mut RunOptions) -> Result<(), String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read config {}: {error}", path.display()))?;
    let mut configured_listen = false;
    for (line_index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid config line {}", line_index + 1))?;
        let key = key.trim();
        let value = value.trim();
        let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            &value[1..value.len() - 1]
        } else {
            value
        };
        match key {
            "listen" => {
                if !configured_listen {
                    options.listen_addresses.clear();
                    configured_listen = true;
                }
                options.listen_addresses.push(value.to_owned());
            }
            "bootstrap" => options.bootstrap_addresses.push(value.to_owned()),
            "identity_key" => options.identity_key_path = PathBuf::from(value),
            "max_node_ids" => {
                options.max_node_ids = value.parse().map_err(|_| {
                    format!("invalid max_node_ids on config line {}", line_index + 1)
                })?;
            }
            "network_id" => {
                options.network_id = value.parse().map_err(|error| {
                    format!(
                        "invalid network_id on config line {}: {error}",
                        line_index + 1
                    )
                })?;
            }
            _ => {
                return Err(format!(
                    "unknown config key {key:?} on line {}",
                    line_index + 1
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run(options: RunOptions) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let identity_config = IdentityManagerConfig {
        max_active_nodes: options.max_node_ids,
        ..IdentityManagerConfig::default()
    };
    let store = FilePeerIdentityStore::new(options.identity_key_path);
    let mut process = PopulusProcess::with_identity_store_and_network(
        &store,
        identity_config,
        options.network_id,
    )?;
    info!(peer_id = %process.peer_id(), "persistent Populus process identity loaded");
    info!(network_id = %process.network_id(), "configured Populus network");

    for address in options.listen_addresses {
        process.listen_on(parse_multiaddr(&address)?)?;
        info!(%address, "listener requested");
    }
    let bootstrap = options
        .bootstrap_addresses
        .iter()
        .map(|address| parse_multiaddr(address))
        .collect::<Result<Vec<_>, _>>()?;
    let bootstrap_count = process.bootstrap(bootstrap)?;
    info!(bootstrap_count, "bootstrap attempts started");

    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                info!("graceful shutdown requested");
                break;
            }
            event = process.next_event() => {
                match event {
                    ProcessEvent::Transport(event) => info!(?event, "transport event"),
                    ProcessEvent::IdentityObservation { peer, results } => {
                        for (observer_node_id, result) in results {
                            match result {
                                Ok(lifecycle) => info!(%peer, %observer_node_id, ?lifecycle, "public identity observation updated"),
                                Err(error) => warn!(%peer, %observer_node_id, %error, "public identity observation rejected"),
                            }
                        }
                    }
                    ProcessEvent::UnverifiedIdentityObserver { peer } => {
                        warn!(%peer, "address observation ignored because sender has no verified active NodeId binding");
                    }
                    ProcessEvent::DirectVoteRequest { peer, vote, channel } => {
                        let code = match vote {
                            Ok(vote) => {
                                info!(%peer, content_id = %vote.content_id(), day = vote.day().value(), "direct vote received");
                                ApplicationErrorCode::NoActiveAuthority
                            }
                            Err(error) => {
                                warn!(%peer, %error, "direct vote rejected");
                                ApplicationErrorCode::InvalidRequest
                            }
                        };
                        if let Err(error) = process.send_response(
                            channel,
                            &ApplicationMessage::Error { code },
                        ) {
                            warn!(%peer, %error, "direct vote refusal could not be sent");
                        }
                    }
                    ProcessEvent::DirectVoteAccepted {
                        peer,
                        content_id,
                        outcome,
                    } => info!(
                        %peer,
                        %content_id,
                        estimate = outcome.provisional_estimate,
                        current_minute_deliveries = outcome.current_minute_deliveries,
                        delegation_recommended = outcome.delegation_recommended,
                        "direct vote accepted"
                    ),
                    ProcessEvent::DirectVoteRejected { peer, error } => {
                        warn!(%peer, %error, "direct vote rejected by authority state machine");
                    }
                    ProcessEvent::NoActiveAuthority { peer, content_id } => {
                        warn!(%peer, %content_id, "no active authority state for requested content");
                    }
                    ProcessEvent::PopularityQueryServed {
                        peer,
                        content_id,
                        estimate,
                        finalized,
                    } => info!(%peer, %content_id, estimate, finalized, "signed popularity query served"),
                    ProcessEvent::PopularityQueryRejected { peer, error } => {
                        warn!(%peer, %error, "popularity query rejected by authority state machine");
                    }
                    ProcessEvent::DelegatedReportAccepted {
                        peer,
                        scope,
                        sequence,
                    } => info!(%peer, content_id = %scope.0, day = scope.1.value(), view = scope.2, sequence, "delegated ingest report accepted"),
                    ProcessEvent::DelegatedReportRejected { peer, error } => {
                        warn!(%peer, %error, "delegated ingest report rejected");
                    }
                    ProcessEvent::DelegatedIngestAcknowledged {
                        peer,
                        scope,
                        sequence,
                        completed,
                    } => info!(%peer, content_id = %scope.0, day = scope.1.value(), view = scope.2, sequence, completed, "delegated ingest report acknowledgement applied"),
                    ProcessEvent::DelegatedIngestAckRejected { peer, error } => {
                        warn!(%peer, %error, "delegated ingest acknowledgement rejected");
                    }
                    ProcessEvent::CandidateRegistrationAccepted {
                        peer,
                        node_id,
                        registration_hash,
                    } => info!(%peer, %node_id, ?registration_hash, "candidate registration accepted"),
                    ProcessEvent::CandidateRegistrationRejected { peer, error } => {
                        warn!(%peer, %error, "candidate registration rejected");
                    }
                    ProcessEvent::CandidateRegistrationAcknowledged {
                        peer,
                        registration_hash,
                    } => info!(%peer, ?registration_hash, "candidate registration acknowledged"),
                    ProcessEvent::ApplicationRequest { peer, message, channel } => {
                        warn!(%peer, ?message, "unsupported application request");
                        if let Err(error) = process.send_response(
                            channel,
                            &ApplicationMessage::Error {
                                code: ApplicationErrorCode::UnsupportedOperation,
                            },
                        ) {
                            warn!(%peer, %error, "unsupported-operation response could not be sent");
                        }
                    }
                    ProcessEvent::ApplicationResponse { peer, message, .. } => {
                        info!(%peer, ?message, "application response received");
                    }
                    ProcessEvent::InvalidApplicationRequest { peer, error, channel } => {
                        warn!(%peer, %error, "malformed application request");
                        if let Err(error) = process.send_response(
                            channel,
                            &ApplicationMessage::Error {
                                code: ApplicationErrorCode::InvalidRequest,
                            },
                        ) {
                            warn!(%peer, %error, "invalid-request response could not be sent");
                        }
                    }
                    ProcessEvent::ResponseRejected { peer, error } => {
                        warn!(%peer, ?error, "application response failed");
                    }
                    ProcessEvent::InvalidApplicationResponse {
                        peer,
                        transport_request_id,
                        error,
                    } => warn!(%peer, ?transport_request_id, %error, "invalid application response"),
                    ProcessEvent::OutboundRequestRejected { peer, error } => {
                        warn!(%peer, ?error, "automatic peer discovery request rejected");
                    }
                    ProcessEvent::InvalidLocalApplicationMessage { peer, error } => {
                        error!(%peer, %error, "local application message encoding failed");
                    }
                    ProcessEvent::InvalidDiscoveredContact { peer } => {
                        warn!(%peer, "routing contact failed validation");
                    }
                    ProcessEvent::DiscoveryLimitReached { peer } => {
                        warn!(%peer, "discovered-contact cache reached its configured bound");
                    }
                    ProcessEvent::ContactDialRejected { peer, reason } => {
                        warn!(%peer, %reason, "discovered contact could not be dialed");
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::path::PathBuf;

    use super::parse_options;
    use populus_protocol::PUBLIC_NETWORK_ID;

    #[test]
    fn command_line_overrides_defaults_and_repeated_values_are_supported() {
        let arguments = [
            "--listen".to_owned(),
            "/ip4/127.0.0.1/tcp/0".to_owned(),
            "--listen".to_owned(),
            "/ip4/127.0.0.1/udp/0/quic-v1".to_owned(),
            "--bootstrap".to_owned(),
            "/ip4/8.8.8.8/tcp/4001/p2p/12D3KooWJ5y7QYV4e7k2v3bWJ8C5w8PwE2Z7v3Y8YxYv1x3q".to_owned(),
            "--max-node-ids".to_owned(),
            "2".to_owned(),
        ];
        let options = parse_options(&arguments).expect("valid options");
        assert_eq!(options.listen_addresses.len(), 2);
        assert_eq!(options.bootstrap_addresses.len(), 1);
        assert_eq!(options.max_node_ids, 2);
    }

    #[test]
    fn invalid_identity_limits_are_rejected() {
        for value in ["0", "65", "not-a-number"] {
            let arguments = ["--max-node-ids".to_owned(), value.to_owned()];
            assert!(parse_options(&arguments).is_err());
        }
    }

    #[test]
    fn network_id_defaults_to_public_and_config_option_requires_a_path() {
        let defaults = parse_options(&[]).expect("defaults are valid");
        assert_eq!(defaults.network_id, PUBLIC_NETWORK_ID);
        assert!(
            parse_options(&["--config".to_owned()])
                .expect_err("missing config path is rejected")
                .contains("missing value for --config")
        );
        assert!(parse_options(&["--network-id".to_owned(), "invalid".to_owned()]).is_err());
    }

    #[test]
    fn option_values_are_not_reinterpreted_as_config_flags() {
        let arguments = [
            "--identity-key".to_owned(),
            "--config".to_owned(),
            "--network-id".to_owned(),
            "0".repeat(64),
        ];
        let options = parse_options(&arguments).expect("option values are tokenized once");
        assert_eq!(options.identity_key_path, PathBuf::from("--config"));
        assert_eq!(options.network_id.to_bytes(), [0; 32]);
    }
}
