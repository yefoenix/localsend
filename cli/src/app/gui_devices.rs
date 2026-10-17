//! Reads the device snapshot written by the LocalSend GUI.
//!
//! The GUI, while running, continuously discovers devices and mirrors its
//! known-device table to `devices.json` (next to the executable in portable
//! mode). The CLI reads this snapshot to resolve `--to <alias>` to the
//! device's latest confirmed address without starting its own discovery.
//! This is what makes "the GUI knows the device, the agent sends to it" work:
//! a device that changed its IP is re-confirmed by the GUI and the snapshot
//! is rewritten, so the alias always resolves to the current address.

use anyhow::Context;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Current schema version of the GUI device snapshot.
const SNAPSHOT_VERSION: u32 = 1;

/// A channel the GUI confirmed a device on.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuiDeviceChannel {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

/// One known device as written by the GUI.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuiDevice {
    pub alias: String,
    pub version: String,
    #[serde(default)]
    pub device_model: Option<String>,
    #[serde(default)]
    pub device_type: Option<String>,
    pub fingerprint: String,
    #[serde(default)]
    pub download: bool,
    pub channels: Vec<GuiDeviceChannel>,
}

/// The snapshot document.
#[derive(Debug, Deserialize)]
struct Snapshot {
    #[serde(default)]
    version: u32,
    devices: Vec<GuiDevice>,
}

/// A resolved destination from the GUI snapshot.
#[derive(Debug, Clone)]
pub struct GuiResolvedTarget {
    /// The device's alias, as written by the GUI.
    pub alias: String,
    /// The fingerprint of the device.
    pub fingerprint: String,
    /// The best confirmed channel.
    pub channel: GuiDeviceChannel,
}

/// Locates the GUI device snapshot.
///
/// Resolution order:
/// 1. an explicitly configured path (`--gui-devices` / `LOCALSEND_GUI_DEVICES`);
/// 2. the directory of the CLI executable (typical portable deployment:
///    CLI and GUI live side by side);
/// 3. the GUI's local application data directories for installed builds;
/// 4. the current working directory.
pub fn locate_snapshot(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    // The CLI executable's own directory.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("devices.json"));
        }
    }

    // Installed GUI builds on Windows.
    #[cfg(windows)]
    {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            let base = PathBuf::from(local_app_data);
            candidates.push(base.join("Programs").join("localsend_app").join("devices.json"));
            candidates.push(base.join("localsend_app").join("devices.json"));
        }
    }

    // Current working directory.
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("devices.json"));
    }

    candidates.into_iter().find(|path| path.is_file())
}

/// Reads the GUI device snapshot and resolves an alias to its latest
/// confirmed channel.
///
/// Returns `Ok(None)` when no snapshot exists (the GUI is not running in
/// portable mode or has never discovered anything) or the alias is unknown;
/// returns `Err` only when a snapshot exists but cannot be parsed.
pub fn resolve_alias(
    explicit: Option<&Path>,
    alias: &str,
) -> anyhow::Result<Option<GuiResolvedTarget>> {
    let Some(snapshot_path) = locate_snapshot(explicit) else {
        return Ok(None);
    };

    let text = std::fs::read_to_string(&snapshot_path)
        .with_context(|| format!("Could not read {}", snapshot_path.display()))?;
    let snapshot: Snapshot = serde_json::from_str(&text)
        .with_context(|| format!("Invalid device snapshot {}", snapshot_path.display()))?;

    if snapshot.version > SNAPSHOT_VERSION {
        anyhow::bail!(
            "Unsupported device snapshot version {} (this build supports up to {})",
            snapshot.version,
            SNAPSHOT_VERSION
        );
    }

    let mut matches: Vec<&GuiDevice> = snapshot
        .devices
        .iter()
        .filter(|device| device.alias == alias)
        .collect();

    if matches.is_empty() {
        return Ok(None);
    }

    // Prefer devices with a confirmed channel; the GUI always writes at
    // least one, but be defensive.
    matches.retain(|device| !device.channels.is_empty());
    if matches.is_empty() {
        return Ok(None);
    }

    // An alias can be ambiguous when two devices share it. The GUI keeps one
    // entry per fingerprint, so a duplicate alias means two distinct devices.
    if matches.len() > 1 {
        anyhow::bail!(
            "Alias {alias:?} is ambiguous in the GUI device snapshot ({} devices); use an IP address",
            matches.len()
        );
    }

    let device = matches[0];
    Ok(Some(GuiResolvedTarget {
        alias: device.alias.clone(),
        fingerprint: device.fingerprint.clone(),
        channel: device.channels[0].clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_snapshot(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("devices.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(text.as_bytes()).unwrap();
        path
    }

    const SNAPSHOT: &str = r#"{
      "version": 1,
      "devices": [
        {
          "alias": "Phone",
          "version": "1.18.2",
          "deviceModel": "Pixel",
          "deviceType": "mobile",
          "fingerprint": "fp-phone",
          "download": false,
          "channels": [
            { "host": "192.168.1.4", "port": 53317, "protocol": "https" }
          ]
        },
        {
          "alias": "NAS",
          "version": "1.18.2",
          "deviceModel": null,
          "deviceType": "server",
          "fingerprint": "fp-nas",
          "download": true,
          "channels": [
            { "host": "192.168.1.41", "port": 53317, "protocol": "https" }
          ]
        }
      ]
    }"#;

    #[test]
    fn resolves_an_alias_to_its_channel() {
        let dir = std::env::temp_dir().join("localsend-cli-gui-devices-test-ok");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_snapshot(&dir, SNAPSHOT);

        let resolved = resolve_alias(Some(&path), "Phone").unwrap().unwrap();
        assert_eq!(resolved.alias, "Phone");
        assert_eq!(resolved.fingerprint, "fp-phone");
        assert_eq!(resolved.channel.host, "192.168.1.4");
        assert_eq!(resolved.channel.port, 53317);
        assert_eq!(resolved.channel.protocol, "https");
    }

    #[test]
    fn returns_none_for_unknown_alias() {
        let dir = std::env::temp_dir().join("localsend-cli-gui-devices-test-missing");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_snapshot(&dir, SNAPSHOT);

        assert!(resolve_alias(Some(&path), "Ghost").unwrap().is_none());
    }

    #[test]
    fn returns_none_when_no_snapshot_exists() {
        let dir = std::env::temp_dir().join("localsend-cli-gui-devices-test-none");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(resolve_alias(Some(&dir.join("devices.json")), "Phone").unwrap().is_none());
    }

    #[test]
    fn rejects_an_ambiguous_alias() {
        let dir = std::env::temp_dir().join("localsend-cli-gui-devices-test-ambig");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ambiguous = r#"{
          "version": 1,
          "devices": [
            {
              "alias": "Phone", "version": "1", "fingerprint": "a",
              "download": false,
              "channels": [{ "host": "1.1.1.1", "port": 53317, "protocol": "https" }]
            },
            {
              "alias": "Phone", "version": "1", "fingerprint": "b",
              "download": false,
              "channels": [{ "host": "2.2.2.2", "port": 53317, "protocol": "https" }]
            }
          ]
        }"#;
        let path = write_snapshot(&dir, ambiguous);

        let err = resolve_alias(Some(&path), "Phone").unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_unsupported_snapshot_version() {
        let dir = std::env::temp_dir().join("localsend-cli-gui-devices-test-version");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_snapshot(&dir, r#"{"version": 99, "devices": []}"#);

        let err = resolve_alias(Some(&path), "Phone").unwrap_err();
        assert!(err.to_string().contains("Unsupported"), "unexpected error: {err}");
    }
}