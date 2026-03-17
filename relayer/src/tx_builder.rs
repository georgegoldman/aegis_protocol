use anyhow::Result;
use sui_sdk::{
    SuiClientBuilder,
    rpc_types::SuiTransactionBlockResponseOptions,
    types::{
        base_types::ObjectID,
        transaction::Transaction,
    },
};
use shared_crypto::intent::Intent;
use sui_sdk::types::quorum_driver_types::ExecuteTransactionRequestType;
use tracing::info;

use crate::config::Config;
use crate::eve_listener::ThreatEvent;
use crate::key_manager::load_keypair;

/// Builds and submits a PTB calling lockdown::execute_lockdown on the vault.
/// This is what fires when the relayer detects a ShieldAlert.
pub async fn execute_lockdown(config: &Config, threat: &ThreatEvent) -> Result<()> {
    info!("Building lockdown PTB for threat: {:?}", threat.event_type);

    let client = SuiClientBuilder::default()
        .build(&config.sui_rpc_url)
        .await?;

    let keypair = load_keypair(&config.relayer_private_key)?;
    let sender = sui_sdk::types::base_types::SuiAddress::from(&keypair.public());

    // Get latest gas coin
    let coins = client
        .coin_read_api()
        .get_coins(sender, None, None, None)
        .await?;
    let gas_coin = coins.data.into_iter().next()
        .ok_or_else(|| anyhow::anyhow!("Relayer wallet has no gas coins"))?;

    // Build the PTB
    let mut ptb = sui_sdk::types::programmable_transaction_builder::ProgrammableTransactionBuilder::new();

    let package = config.package_id.parse::<ObjectID>()?;
    let vault_obj = ptb.obj(sui_sdk::types::transaction::ObjectArg::SharedObject {
        id: config.vault_state_id.parse::<ObjectID>()?,
        initial_shared_version: get_initial_version(&client, &config.vault_state_id).await?,
        mutable: true,
    })?;
    let lockdown_obj = ptb.obj(sui_sdk::types::transaction::ObjectArg::SharedObject {
        id: config.lockdown_state_id.parse::<ObjectID>()?,
        initial_shared_version: get_initial_version(&client, &config.lockdown_state_id).await?,
        mutable: true,
    })?;
    let clock_obj = ptb.obj(sui_sdk::types::transaction::ObjectArg::SharedObject {
        id: config.clock_id.parse::<ObjectID>()?,
        initial_shared_version: 1u64.into(),
        mutable: false,
    })?;

    // threat_type as vector<u8>
    let threat_bytes = ptb.pure(threat.event_type.as_bytes().to_vec())?;

    // Call aegis_contract::lockdown::execute_lockdown
    ptb.programmable_move_call(
        package,
        sui_sdk::types::Identifier::new("lockdown")?,
        sui_sdk::types::Identifier::new("execute_lockdown")?,
        vec![],
        vec![vault_obj, lockdown_obj, threat_bytes, clock_obj],
    );

    let pt = ptb.finish();

    // Get reference gas price
    let gas_price = client.read_api().get_reference_gas_price().await?;

    let tx_data = sui_sdk::types::transaction::TransactionData::new_programmable(
        sender,
        vec![gas_coin.object_ref()],
        pt,
        10_000_000, // gas budget
        gas_price,
    );

    // Sign and submit
    let signature = keypair.sign_transaction(&tx_data);
    let response = client
        .quorum_driver_api()
        .execute_transaction_block(
            Transaction::from_data(tx_data, vec![signature]),
            SuiTransactionBlockResponseOptions::new().with_effects().with_events(),
            Some(ExecuteTransactionRequestType::WaitForLocalExecution),
        )
        .await?;

    info!("✅ Lockdown TX submitted: {}", response.digest);
    if let Some(effects) = response.effects {
        if effects.status().is_ok() {
            info!("✅ Lockdown confirmed on-chain");
        } else {
            anyhow::bail!("Lockdown TX failed: {:?}", effects.status());
        }
    }

    Ok(())
}

/// Builds and submits a PTB calling dead_man_switch::trigger.
/// Called by the relayer when it detects the vault has been inactive
/// longer than inactivity_limit_ms.
pub async fn trigger_dead_man_switch(
    config: &Config,
    leader_cap_id: &str,
) -> Result<()> {
    info!("Building Dead Man's Switch PTB...");

    let client = SuiClientBuilder::default()
        .build(&config.sui_rpc_url)
        .await?;

    let keypair = load_keypair(&config.relayer_private_key)?;
    let sender = sui_sdk::types::base_types::SuiAddress::from(&keypair.public());

    let coins = client
        .coin_read_api()
        .get_coins(sender, None, None, None)
        .await?;
    let gas_coin = coins.data.into_iter().next()
        .ok_or_else(|| anyhow::anyhow!("No gas coins"))?;

    let mut ptb = sui_sdk::types::programmable_transaction_builder::ProgrammableTransactionBuilder::new();

    let package = config.package_id.parse::<ObjectID>()?;

    let switch_obj = ptb.obj(sui_sdk::types::transaction::ObjectArg::SharedObject {
        id: config.switch_state_id.parse::<ObjectID>()?,
        initial_shared_version: get_initial_version(&client, &config.switch_state_id).await?,
        mutable: true,
    })?;
    let vault_obj = ptb.obj(sui_sdk::types::transaction::ObjectArg::SharedObject {
        id: config.vault_state_id.parse::<ObjectID>()?,
        initial_shared_version: get_initial_version(&client, &config.vault_state_id).await?,
        mutable: false, // read-only for switch check
    })?;
    // LeaderCap is an owned object — pass by value (the relayer must own it)
    let leader_cap_obj = ptb.obj(sui_sdk::types::transaction::ObjectArg::ImmOrOwnedObject(
        get_object_ref(&client, leader_cap_id).await?,
    ))?;
    let clock_obj = ptb.obj(sui_sdk::types::transaction::ObjectArg::SharedObject {
        id: config.clock_id.parse::<ObjectID>()?,
        initial_shared_version: 1u64.into(),
        mutable: false,
    })?;

    ptb.programmable_move_call(
        package,
        sui_sdk::types::Identifier::new("dead_man_switch")?,
        sui_sdk::types::Identifier::new("trigger")?,
        vec![],
        vec![switch_obj, vault_obj, leader_cap_obj, clock_obj],
    );

    let pt = ptb.finish();
    let gas_price = client.read_api().get_reference_gas_price().await?;
    let tx_data = sui_sdk::types::transaction::TransactionData::new_programmable(
        sender,
        vec![gas_coin.object_ref()],
        pt,
        10_000_000,
        gas_price,
    );

    let signature = keypair.sign_transaction(&tx_data);
    let response = client
        .quorum_driver_api()
        .execute_transaction_block(
            Transaction::from_data(tx_data, vec![signature]),
            SuiTransactionBlockResponseOptions::new().with_effects(),
            Some(ExecuteTransactionRequestType::WaitForLocalExecution),
        )
        .await?;

    info!("✅ Dead Man's Switch TX: {}", response.digest);
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────

async fn get_initial_version(
    client: &sui_sdk::SuiClient,
    object_id: &str,
) -> Result<sui_sdk::types::base_types::SequenceNumber> {
    let obj = client
        .read_api()
        .get_object_with_options(
            object_id.parse::<ObjectID>()?,
            sui_sdk::rpc_types::SuiObjectDataOptions::new().with_owner(),
        )
        .await?;
    let owner = obj.data
        .ok_or_else(|| anyhow::anyhow!("Object not found: {object_id}"))?
        .owner
        .ok_or_else(|| anyhow::anyhow!("No owner for object: {object_id}"))?;
    match owner {
        sui_sdk::rpc_types::SuiObjectOwner::Shared { initial_shared_version } => {
            Ok(initial_shared_version)
        }
        _ => anyhow::bail!("Object {object_id} is not a shared object"),
    }
}

async fn get_object_ref(
    client: &sui_sdk::SuiClient,
    object_id: &str,
) -> Result<sui_sdk::types::base_types::ObjectRef> {
    let obj = client
        .read_api()
        .get_object_with_options(
            object_id.parse::<ObjectID>()?,
            sui_sdk::rpc_types::SuiObjectDataOptions::new(),
        )
        .await?;
    Ok(obj.data
        .ok_or_else(|| anyhow::anyhow!("Object not found: {object_id}"))?
        .object_ref())
}