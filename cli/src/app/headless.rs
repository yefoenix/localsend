//! The headless `send --to` mode: discover the destination, send the files
//! or the text message, exit with the transfer result. There is no keyboard and no overlay — only
//! the network events a send needs are handled, and incoming transfer
//! requests are declined.

use super::gui_devices;
use super::sending::{self, Payload, SendState};
use super::status;
use super::target::TargetSelector;
use super::{AppEvent, Network, discovery, spawn_staged_discovery, start_network, stop_network};
use crate::sanitize;
use crate::storage::Repository;
use crate::ui::{Category, Ui};
use crate::util;
use localsend::discovery::{
    ChannelStatus, DeviceChannel, DiscoveredDevice, DiscoveryEvent, DiscoveryHandle, HttpChannel,
    StatefulDevice,
};
use localsend::http::client::v2::LsHttpClientV2;
use localsend::http::dto_v2::RegisterDtoV2;
use localsend::http::server::v2::{PrepareUploadDecisionV2, ServerEventV2};
use localsend::model::discovery::{PROTOCOL_VERSION_V2, ProtocolType};
use localsend::model::discovery::DeviceType;
use localsend::multicast::DEFAULT_PORT;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a direct register probe may take before the destination is
/// considered unreachable. LocalSend peers answer in milliseconds; anything
/// slower is not worth waiting for in the agent fast path.
const DIRECT_REGISTER_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) async fn run(
    mut storage: Repository,
    target: TargetSelector,
    payload: Payload,
    gui_devices: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Fast path: when the destination is a literal IP address, dial it
    // directly. No server is started (so no local port is occupied and the
    // GUI can keep owning 53317), and no discovery is needed (so the send
    // starts immediately instead of after a network scan).
    if let TargetSelector::Ip(ip) = &target {
        return run_direct(storage, *ip, DEFAULT_PORT, ProtocolType::Https, payload).await;
    }

    // GUI-assisted fast path: when the destination is an alias, try to
    // resolve it from the GUI's device snapshot first. The GUI is the
    // authority on where a device currently is: it discovers continuously
    // while the CLI is not running, and re-confirms devices when they change
    // their IP. Resolving from the snapshot lets the agent send immediately,
    // without occupying a port or scanning the network.
    if let TargetSelector::Alias(alias) = &target {
        match gui_devices::resolve_alias(gui_devices.as_deref(), alias)? {
            Some(resolved) => {
                // The snapshot stores the host as an IP (or scoped IPv6).
                // Parse it like the IP fast path does.
                let host = resolved.channel.host.split('%').next().unwrap_or(&resolved.channel.host);
                if let Ok(ip) = host.parse::<IpAddr>() {
                    let protocol = match resolved.channel.protocol.as_str() {
                        "http" => ProtocolType::Http,
                        _ => ProtocolType::Https,
                    };
                    return run_direct(storage, ip, resolved.channel.port, protocol, payload).await;
                }
                // Non-IP hosts in the snapshot are unexpected; fall through to
                // the CLI's own discovery below.
            }
            None => {
                // No snapshot or unknown alias: fall back to discovery.
            }
        }
    }

    let mut ui = Ui::new();
    let identity = storage.identity.clone();
    let (events_tx, mut events_rx) = mpsc::channel::<AppEvent>(64);
    let Network {
        server,
        server_stop_tx,
        server_tx: _,
        mut server_rx,
        discovery,
        mut discovery_rx,
        discovery_stop_tx,
    } = start_network(&identity).await?;

    // Probe the destination's address directly when `--to` is an IP.
    let mut known_channels = storage.paired.known_http_channels();
    if let Some(channel) = target.direct_channel()
        && !known_channels.contains(&channel)
    {
        known_channels.insert(0, channel);
    }
    spawn_staged_discovery(
        discovery.clone(),
        events_tx.clone(),
        known_channels,
        identity.port,
    );
    ui.log_plain(&format!("Discovering destination {target}..."));

    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut send: Option<SendState> = None;
    let result = loop {
        let event = tokio::select! {
            Some(event) = events_rx.recv() => event,
            Some(event) = server_rx.recv() => AppEvent::Server(event),
            Some(event) = discovery_rx.recv() => AppEvent::Discovery(event),
            _ = tick.tick() => AppEvent::Tick,
        };
        match event {
            AppEvent::Server(event) => {
                handle_server_event(&mut ui, &storage, &discovery, &mut send, event)
            }
            AppEvent::Discovery(event) => {
                handle_discovery(&mut ui, &mut storage, &discovery, event)
            }
            AppEvent::Tick => render_progress(&mut ui, &mut send),
            AppEvent::Log { category, text } => ui.log(category, &text),
            AppEvent::DiscoveryFinished => {
                match start_send(&mut ui, &storage, &discovery, &target, &payload, &events_tx) {
                    Ok(state) => send = Some(state),
                    Err(reason) => break Err(anyhow::anyhow!(reason)),
                }
            }
            AppEvent::SendSessionStarted {
                session_id,
                accepted_bytes,
            } => {
                if let Some(send) = &mut send {
                    send.session_id = Some(session_id);
                    send.total_bytes = accepted_bytes;
                }
            }
            AppEvent::SendEnded { success } => {
                break match success {
                    true => Ok(()),
                    false => Err(anyhow::anyhow!("Transfer failed")),
                };
            }
            // No keyboard, no accepted receive sessions and no web links in
            // this mode.
            AppEvent::Key(_) | AppEvent::ReceiveFileResult { .. } | AppEvent::Web(_) => {}
        }
    };
    ui.set_status(None);
    stop_network(&server, Some(server_stop_tx), &discovery, discovery_stop_tx).await;
    result
}

/// Sends to a literal IP address without starting a local server or running
/// discovery. This is the agent fast path: it occupies no local port, starts
/// immediately, and works alongside a GUI instance that owns port 53317.
async fn run_direct(
    storage: Repository,
    ip: IpAddr,
    port: u16,
    protocol: ProtocolType,
    payload: Payload,
) -> anyhow::Result<()> {
    let identity = storage.identity.clone();
    let host = ip.to_string();

    // Register with the destination over HTTPS. The register response carries
    // the device's alias, version and certificate fingerprint, which is all
    // the send task needs to address it.
    let client = LsHttpClientV2::try_new(
        &identity.key_pem,
        &identity.cert_pem,
        None,
        Some(DIRECT_REGISTER_TIMEOUT),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {e}"))?;

    let response = client
        .register(protocol, &host, port, register_dto(&identity))
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Destination {host}:{port} was not reachable: {e}"
            )
        })?;

    let fingerprint = response
        .cert_fingerprint
        .clone()
        .unwrap_or_else(|| response.body.fingerprint.clone());
    let channel = HttpChannel {
        host: host.clone(),
        port,
        protocol,
    };
    let device = StatefulDevice {
        device: DiscoveredDevice {
            alias: response.body.alias.clone(),
            version: response.body.version.clone(),
            device_model: response.body.device_model.clone(),
            device_type: response.body.device_type,
            fingerprint,
            channel: DeviceChannel::Http(channel.clone()),
            download: response.body.download,
        },
        channels: HashMap::from([(DeviceChannel::Http(channel), ChannelStatus::Available)]),
        logs: Vec::new(),
    };

    let mut ui = Ui::new();
    let (events_tx, mut events_rx) = mpsc::channel::<AppEvent>(64);
    ui.log_plain(&format!("Sending to {} ({host})...", sanitize::single_line(&response.body.alias)));

    // Spawn the send task. The returned state is only used for progress
    // rendering in the interactive flow; here the send runs in the background
    // and reports through the event channel.
    match payload {
        Payload::Files(paths) => {
            sending::spawn_send(
                &mut ui,
                identity,
                device,
                paths,
                events_tx.clone(),
            )
            .map_err(anyhow::Error::msg)?;
        }
        Payload::Text(text) => {
            sending::spawn_send_text(
                &mut ui,
                identity,
                device,
                text,
                events_tx.clone(),
            )
            .map_err(anyhow::Error::msg)?;
        }
    }

    // Wait for the terminal event of the send task.
    while let Some(event) = events_rx.recv().await {
        match event {
            AppEvent::SendEnded { success } => {
                return if success {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Transfer failed"))
                };
            }
            AppEvent::Log { category, text } => ui.log(category, &text),
            _ => {}
        }
    }

    Err(anyhow::anyhow!("Send task ended without a result"))
}

/// Builds this device's `register` payload for the direct fast path.
fn register_dto(identity: &crate::storage::Identity) -> RegisterDtoV2 {
    RegisterDtoV2 {
        alias: identity.alias.clone(),
        version: PROTOCOL_VERSION_V2.to_string(),
        device_model: Some("CLI".to_string()),
        device_type: Some(DeviceType::Headless),
        fingerprint: identity.fingerprint.clone(),
        port: identity.port,
        protocol: ProtocolType::Https,
        download: false,
    }
}

/// Resolves the destination among the discovered devices and spawns the send
/// task towards it.
fn start_send(
    ui: &mut Ui,
    storage: &Repository,
    discovery: &DiscoveryHandle,
    target: &TargetSelector,
    payload: &Payload,
    events_tx: &mpsc::Sender<AppEvent>,
) -> Result<SendState, String> {
    let fingerprint = target.resolve(&discovery.devices())?;
    let device = discovery
        .device_by_fingerprint(&fingerprint)
        .ok_or_else(|| format!("Destination {target} was not discovered"))?;
    match payload {
        Payload::Files(paths) => sending::spawn_send(
            ui,
            storage.identity.clone(),
            device,
            paths.clone(),
            events_tx.clone(),
        ),
        Payload::Text(text) => sending::spawn_send_text(
            ui,
            storage.identity.clone(),
            device,
            text.clone(),
            events_tx.clone(),
        ),
    }
}

fn handle_server_event(
    ui: &mut Ui,
    storage: &Repository,
    discovery: &Arc<DiscoveryHandle>,
    send: &mut Option<SendState>,
    event: ServerEventV2,
) {
    match event {
        // Peers answer the startup announcement by registering here; this is
        // how the destination usually enters the device store.
        ServerEventV2::Register { ip, info } => {
            discovery::device_confirmed(
                discovery,
                &storage.identity.fingerprint,
                ip.to_string(),
                info,
            );
        }
        ServerEventV2::PrepareUpload {
            info, decision_tx, ..
        } => {
            // Receiving needs the interactive Y/N prompt; decline instead of
            // leaving the sender hanging.
            let _ = decision_tx.send(PrepareUploadDecisionV2::Decline);
            ui.log(
                Category::Receive,
                &format!(
                    "{}: Declined the incoming request (busy sending)",
                    sanitize::single_line(&info.alias)
                ),
            );
        }
        ServerEventV2::CancelReceived { ip, session_id } => {
            if let Some(send) = send
                && send.session_id.as_deref() == Some(session_id.as_str())
                && send.host == ip.to_string()
            {
                send.cancel.by_peer.store(true, Ordering::Relaxed);
                send.cancel.token.cancel();
            }
        }
        ServerEventV2::ListenerFailed { error } => {
            ui.log(Category::Receive, &format!("Server stopped: {error}"));
        }
        // No receive session is ever accepted; dropping the responders
        // rejects the requests.
        ServerEventV2::FileUpload { .. }
        | ServerEventV2::SessionEnd { .. }
        | ServerEventV2::PrepareUploadAborted { .. } => {}
    }
}

fn handle_discovery(
    ui: &mut Ui,
    storage: &mut Repository,
    discovery: &DiscoveryHandle,
    event: DiscoveryEvent,
) {
    let device = match &event {
        DiscoveryEvent::Discovered { device } | DiscoveryEvent::Updated { device } => device,
        DiscoveryEvent::MulticastFailed => {
            ui.log(
                Category::Discovery,
                "Multicast stopped, no longer hearing announcements",
            );
            return;
        }
    };
    discovery::refresh_paired_channels(ui, &mut storage.paired, discovery, &device.fingerprint);

    let DiscoveryEvent::Discovered { device } = event else {
        // Re-confirmations update the store silently.
        return;
    };
    let host = device
        .http()
        .map(|http| http.host.as_str())
        .unwrap_or("unknown address");
    ui.log(
        Category::Discovery,
        &format!("{} ({host})", sanitize::single_line(&device.alias)),
    );
}

/// The status line: the progress bar of the running transfer.
fn render_progress(ui: &mut Ui, send: &mut Option<SendState>) {
    let Some(send) = send else {
        ui.set_status(None);
        return;
    };
    let done = send.sent.load(Ordering::Relaxed);
    let speed = send.speed.update(done);
    let width = util::terminal_width().saturating_sub(1);
    ui.set_status(Some(status::transfer_status(
        Category::Send,
        &send.alias,
        done,
        send.total_bytes,
        speed,
        width,
    )));
}