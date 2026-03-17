use anyhow::Result;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tokio_tungstenite::connect_async;
use tracing::{error, info, warn};

/// Threat events we care about from the EVE Frontier world API.
/// These match the event names emitted by the game server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub event_type: String,   // e.g. "ShieldAlert", "StructureShieldDepleted"
    pub ssu_id: String,       // the SSU object ID under attack
    pub timestamp_ms: u64,
}

/// Real WebSocket listener — connects to EVE Frontier world API.
/// Parses incoming JSON events and forwards threat events to the channel.
pub async fn listen_real(ws_url: &str, ssu_id: &str, tx: Sender<ThreatEvent>) -> Result<()> {
    info!("Connecting to EVE Frontier WebSocket: {}", ws_url);

    // Auto-reconnect loop
    loop {
        match connect_async(ws_url).await {
            Ok((mut ws, _)) => {
                info!("WebSocket connected");

                while let Some(msg) = ws.next().await {
                    match msg {
                        Ok(m) if m.is_text() => {
                            let text = m.into_text().unwrap_or_default();
                            if let Ok(event) = serde_json::from_str::<serde_json::Value>(&text) {
                                if let Some(threat) = parse_threat_event(&event, ssu_id) {
                                    info!("⚠️  Threat detected: {:?}", threat);
                                    if tx.send(threat).await.is_err() {
                                        return Ok(()); // receiver dropped, shut down
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("WebSocket error: {e}, reconnecting...");
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                error!("WebSocket connection failed: {e}, retrying in 5s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
}

/// Mock event emitter — fires a ShieldAlert every 30 seconds.
/// Use this while waiting for Utopia access. Swap eve_ws_url to the
/// real URL in .env and restart — no code changes needed.
pub async fn listen_mock(ssu_id: &str, tx: Sender<ThreatEvent>) -> Result<()> {
    info!("🧪 Mock mode: emitting ShieldAlert every 30s for SSU {}", ssu_id);
    let mut counter = 0u64;
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        counter += 1;
        let event = ThreatEvent {
            event_type: "ShieldAlert".into(),
            ssu_id: ssu_id.to_string(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        info!("🚨 Mock threat #{counter}: {:?}", event);
        if tx.send(event).await.is_err() {
            return Ok(());
        }
    }
}

/// Parse a raw JSON event from the EVE Frontier WebSocket into a ThreatEvent.
/// The actual field names depend on the EVE Frontier world API schema.
/// Adjust these field names once you have Utopia access and can inspect real events.
fn parse_threat_event(value: &serde_json::Value, target_ssu_id: &str) -> Option<ThreatEvent> {
    let event_type = value.get("eventType")?.as_str()?.to_string();

    // Only act on shield/attack events
    let is_threat = matches!(
        event_type.as_str(),
        "ShieldAlert" | "StructureShieldDepleted" | "StructureUnderAttack"
    );
    if !is_threat {
        return None;
    }

    // Only act on events targeting our SSU
    let ssu_id = value
        .get("assemblyId")
        .or_else(|| value.get("ssuId"))
        .or_else(|| value.get("structureId"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if ssu_id != target_ssu_id {
        return None;
    }

    let timestamp_ms = value
        .get("timestamp")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Some(ThreatEvent { event_type, ssu_id: ssu_id.to_string(), timestamp_ms })
}