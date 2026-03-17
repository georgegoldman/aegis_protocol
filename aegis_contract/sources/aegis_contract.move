module aegis_contract::aegis_protocol;

use sui::object::{Self, UID, ID};
use sui::tx_context::{Self, TxContext};
use sui::transfer;
use sui::clock::{Self, Clock};

// Import the necessary EVE Frontier Assemblies and Primitives
// (You will need to ensure these paths match your Move.toml dependency)
use world::storage_unit::{Self, StorageUnit};
use world::inventory;
use world::in_game_id::InGameId;
use world::inventory::withdraw_item;

const E_VAULT_IS_LOCKED: u64 = 0;
const E_NOT_AUTHORIZED: u64 = 1;
const E_NOT_ABANDONED: u64 = 2;

public struct AegisVault has key {
    id: UID,
    // The specific Smart Storage Unit (SSU) this protocol protects
    target_ssu_id: ID, 
    owner: address,
    is_locked: bool,
    last_active_timestamp: u64,
    recovery_address: address, // E.g., Ayoola's wallet address for the COO fallback
    recovery_threshold_ms: u64,
}

/// The initialization function for the extension.
/// It links your custom Aegis Vault to a specific EVE Storage Unit.
public entry fun attach_aegis_to_ssu(
    target_ssu_id: ID,
    recovery_address: address,
    recovery_threshold_ms: u64,
    clock: &Clock,
    ctx: &mut TxContext
) {
    let vault = AegisVault {
        id: object::new(ctx),
        target_ssu_id,
        owner: tx_context::sender(ctx),
        is_locked: false,
        last_active_timestamp: clock::timestamp_ms(clock),
        recovery_address,
        recovery_threshold_ms,
    };
    
    transfer::transfer(vault, tx_context::sender(ctx));
}

/// The heartbeat function remains the same. The CEO/Leader calls this.
public entry fun heartbeat(
    vault: &mut AegisVault,
    clock: &Clock,
    ctx: &mut TxContext
) {
    assert!(tx_context::sender(ctx) == vault.owner, E_NOT_AUTHORIZED);
    vault.last_active_timestamp = clock::timestamp_ms(clock);
}

/// Extension-wrapped withdrawal passing all required EVE context.
public fun secure_withdraw(
    vault: &AegisVault,
    // The core EVE inventory object/system reference
    inventory_obj: &mut inventory::Inventory, 
    assembly_id: ID, 
    assembly_key: ID, // Check EVE primitives: this might be a specific Key struct or u64
    character: ID,    // The ID of the in-game character making the request
    type_id: u64,     // The item type identifier
    quantity: u64,    // How much to withdraw
    location_hash: u64, // The specific storage slot/hash
    ctx: &mut TxContext
) {
    // 1. AEGIS SECURITY CHECKS
    assert!(!vault.is_locked, E_VAULT_IS_LOCKED);
    assert!(tx_context::sender(ctx) == vault.owner, E_NOT_AUTHORIZED);
    
    // CRITICAL: Ensure the assembly they are trying to withdraw from 
    // is actually the one this specific Aegis Vault is protecting.
    assert!(assembly_id == vault.target_ssu_id, E_NOT_AUTHORIZED);

    // 2. EXECUTE CORE EVE FUNCTION
    // If the Aegis vault is safe, pass all arguments down to the Layer 1 inventory system.
    inventory::withdraw_item(
        inventory_obj, 
        assembly_id, 
        assembly_key, 
        character, 
        type_id, 
        quantity, 
        location_hash, 
        ctx
    ); 
}

/// The Dead Man's Switch execution
public entry fun check_and_recover(
    vault: &mut AegisVault,
    clock: &Clock,
    _ctx: &mut TxContext
) {
    let current_time = clock::timestamp_ms(clock);
    
    assert!(
        current_time > vault.last_active_timestamp + vault.recovery_threshold_ms, 
        E_NOT_ABANDONED
    );
    
    // Option A implementation: Transfer control of the Aegis extension 
    // to the COO's recovery address.
    vault.owner = vault.recovery_address;
    vault.last_active_timestamp = current_time;
    vault.is_locked = false; 
}