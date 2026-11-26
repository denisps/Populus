//! Runnable Populus transport process.

use std::{path::PathBuf, process::ExitCode};

use populus_cluster::GenesisManifest;
use populus_network::parse_multiaddr;
use populus_node::{
    ApplicationErrorCode, ApplicationMessage, FilePeerIdentityStore, IdentityManagerConfig,
    PopulusProcess, ProcessEvent,
};
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
    genesis_manifest_path: Option<PathBuf>,
    genesis_trust_key_path: Option<PathBuf>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            listen_addresses: vec![DEFAULT_LISTEN.to_owned()],
            bootstrap_addresses: Vec::new(),
            identity_key_path: PathBuf::from(DEFAULT_IDENTITY_PATH),
            max_node_ids: 4,
            genesis_manifest_path: None,
            genesis_trust_key_path: None,
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
        "Usage: populus-node run [--config FILE] [--listen MULTIADDR] \
         [--bootstrap MULTIADDR] [--identity-key FILE] [--max-node-ids N] \
         [--genesis-manifest FILE --genesis-trust-key FILE]"
    );
    eprintln!("Defaults: listen on {DEFAULT_LISTEN}; persist PeerId in {DEFAULT_IDENTITY_PATH}.");
    eprintln!(
        "Genesis requires a signed four-member manifest and an out-of-band raw 32-byte trust key."
    );
}

fn parse_options(arguments: &[String]) -> Result<RunOptions, String> {
    let mut options = RunOptions::default();
    let config_path = arguments
        .windows(2)
        .find(|pair| pair[0] == "--config")
        .map(|pair| PathBuf::from(&pair[1]));
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
            "--genesis-manifest" => {
                options.genesis_manifest_path = Some(PathBuf::from(value));
            }
            "--genesis-trust-key" => {
                options.genesis_trust_key_path = Some(PathBuf::from(value));
            }
            _ => return Err(format!("unknown option: {option}")),
        }
    }
    if options.genesis_manifest_path.is_some() != options.genesis_trust_key_path.is_some() {
        return Err(
            "--genesis-manifest and --genesis-trust-key must be supplied together".to_owned(),
        );
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
            "genesis_manifest" => {
                options.genesis_manifest_path = Some(PathBuf::from(value));
            }
            "genesis_trust_key" => {
                options.genesis_trust_key_path = Some(PathBuf::from(value));
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
    let mut process = PopulusProcess::with_identity_store(&store, identity_config)?;
    info!(peer_id = %process.peer_id(), "persistent Populus process identity loaded");
    let genesis_addresses = match (
        options.genesis_manifest_path,
        options.genesis_trust_key_path,
    ) {
        (Some(manifest_path), Some(trust_key_path)) => {
            let manifest_bytes = std::fs::read(&manifest_path)?;
            let manifest = GenesisManifest::deserialize(&manifest_bytes)?;
            let trust_key_bytes = std::fs::read(&trust_key_path)?;
            let trusted_public_key: [u8; 32] =
                trust_key_bytes.as_slice().try_into().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "genesis trust-key file must contain exactly 32 raw bytes",
                    )
                })?;
            let addresses = process.configure_genesis_manifest(manifest, trusted_public_key)?;
            info!(
                manifest = %manifest_path.display(),
                "explicit signed genesis manifest loaded; awaiting direct-member quorum"
            );
            addresses
        }
        (None, None) => Vec::new(),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--genesis-manifest and --genesis-trust-key must be supplied together",
            )
            .into());
        }
    };

    for address in options.listen_addresses {
        process.listen_on(parse_multiaddr(&address)?)?;
        info!(%address, "listener requested");
    }
    let bootstrap = options
        .bootstrap_addresses
        .iter()
        .map(|address| parse_multiaddr(address))
        .collect::<Result<Vec<_>, _>>()?;
    let bootstrap_count = process.bootstrap(bootstrap.into_iter().chain(genesis_addresses))?;
    info!(bootstrap_count, "bootstrap attempts started");

    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result?;
                info!("graceful shutdown requested");
                break;
            }
            event = process.next_event() => {
                if let Some(node_id) = process.try_activate_genesis_manifest()? {
                    info!(%node_id, "signed genesis membership and direct observation quorum activated");
                }
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

    use super::parse_options;

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
}
