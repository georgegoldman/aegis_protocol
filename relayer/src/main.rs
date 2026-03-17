mod config;
mod eve_listener;
mod key_manager;
mod tx_builder;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use config::Config;
use eve_listener::ThreatEvent;

#[tokio::main]
async fn main() -> Result<()> {
    // Init logging — set RUST_LOG=info or aegis_relayer=debug
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("aegis_relayer=info".parse()?))
        .init();

    let config = Config::from_env()?;
    info!("🛡️  Aegis Protocol Relayer starting...");
    info!("   Vault:    {}", config.vault_state_id);
    info!("   Lockdown: {}", config.lockdown_state_id);
    info!("   Switch:   {}", config.switch_state_id);
    info!("   SSU:      {}", config.ssu_object_id);

    // Channel: EVE listener → lockdown executor
    let (threat_tx, mut threat_rx) = mpsc::channel::<ThreatEvent>(32);

    // Spawn the appropriate listener based on config
    let ssu_id = config.ssu_object_id.clone();
    let ws_url = config.eve_ws_url.clone();
    let tx_clone = threat_tx.clone();

    tokio::spawn(async move {
        let result = if ws_url == "mock" {
            eve_listener::listen_mock(&ssu_id, tx_clone).await
        } else {
            eve_listener::listen_real(&ws_url, &ssu_id, tx_clone).await
        };
        if let Err(e) = result {
            error!("EVE listener died: {e}");
        }
    });

    // Spawn the inactivity monitor (Dead Man's Switch)
    // Polls vault state every 60 seconds
    let config_clone = config.clone();
    tokio::spawn(async move {
        monitor_inactivity(config_clone).await;
    });

    // Main loop: process threat events as they arrive
    info!("👂 Listening for threat events...");
    while let Some(threat) = threat_rx.recv().await {
        info!("🚨 Processing threat: {} on SSU {}", threat.event_type, threat.ssu_id);

        match tx_builder::execute_lockdown(&config, &threat).await {
            Ok(_) => info!("✅ Lockdown executed successfully"),
            Err(e) => error!("❌ Lockdown failed: {e}"),
        }
    }

    Ok(())
}

/// Polls the VaultState object on Sui every 60 seconds.
/// If last_active_ms + inactivity_limit_ms < now → fires Dead Man's Switch.
async fn monitor_inactivity(config: Config) {
    use sui_sdk::SuiClientBuilder;

    let poll_interval = tokio::time::Duration::from_secs(60);

    loop {
        tokio::time::sleep(poll_interval).await;

        let client = match SuiClientBuilder::default().build(&config.sui_rpc_url).await {
            Ok(c) => c,
            Err(e) => { error!("Failed to connect to Sui RPC: {e}"); continue; }
        };

        match check_inactivity(&client, &config).await {
            Ok(Some(elapsed_ms)) => {
                info!(
                    "⏳ Dead Man's Switch: elapsed {}s / limit {}s — FIRING",
                    elapsed_ms / 1000,
                    elapsed_ms / 1000 // limit will be logged properly below
                );
                // NOTE: you need to supply the leader_cap_id here
                // Store it in .env as LEADER_CAP_ID
                let leader_cap_id = std::env::var("LEADER_CAP_ID").unwrap_or_default();
                if let Err(e) = tx_builder::trigger_dead_man_switch(&config, &leader_cap_id).await {
                    error!("❌ Dead Man's Switch TX failed: {e}");
                }
            }
            Ok(None) => {
                // Not yet triggerable — normal
            }
            Err(e) => error!("Inactivity check failed: {e}"),
        }
    }
}

/// Returns Some(elapsed_ms) if the vault is past its inactivity threshold, None otherwise.
async fn check_inactivity(
    client: &sui_sdk::SuiClient,
    config: &Config,
) -> Result<Option<u64>> {
    use sui_sdk::types::base_types::ObjectID;

    let vault_id = config.vault_state_id.parse::<ObjectID>()?;
    let obj = client
        .read_api()
        .get_object_with_options(
            vault_id,
            sui_sdk::rpc_types::SuiObjectDataOptions::new().with_content(),
        )
        .await?;

    let content = obj.data
        .and_then(|d| d.content)
        .ok_or_else(|| anyhow::anyhow!("No content for vault object"))?;

    // Parse the Move object fields from JSON
    if let sui_sdk::rpc_types::SuiParsedData::MoveObject(mo) = content {
        let fields = &mo.fields;
        let last_active_ms: u64 = fields["last_active_ms"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let inactivity_limit_ms: u64 = fields["inactivity_limit_ms"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX);
        let is_locked: bool = fields["is_locked"].as_bool().unwrap_or(false);

        if is_locked {
            return Ok(None); // already locked, don't double-fire
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64;

        let elapsed = now_ms.saturating_sub(last_active_ms);
        if elapsed >= inactivity_limit_ms {
            return Ok(Some(elapsed));
        }
    }

    Ok(None)
}