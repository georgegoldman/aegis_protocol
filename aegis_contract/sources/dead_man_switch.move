/// dead_man_switch.move
/// Aegis Protocol — Dead Man's Switch
///
/// Monitors vault inactivity. If the leader and officers are silent for
/// longer than vault.inactivity_limit_ms, anyone can call `trigger` to
/// transfer the LeaderCap to the pre-configured recovery address.
///
/// This module is purely read/transfer logic — it does NOT touch the SSU
/// inventory directly. Inventory is still protected by the world contract.
/// What transfers is governance: the LeaderCap that controls vault ACL.
module aegis_contract::dead_man_switch;

use sui::{clock::{Self, Clock}, event, object::{Self, ID}, transfer, tx_context::{Self, TxContext}};
use aegis_contract::vault::{Self, VaultState, LeaderCap};

// =====================================================================
// ERRORS
// =====================================================================
const ENotYetInactive: u64 = 100;
const EAlreadyTriggered: u64 = 101;

// =====================================================================
// STATE — one per vault, tracks switch history
// =====================================================================
public struct SwitchState has key {
    id: sui::object::UID,
    /// The vault this switch monitors
    vault_id: ID,
    /// Whether the switch has already fired (prevents replay)
    has_triggered: bool,
    /// Timestamp when it fired (0 if not yet triggered)
    triggered_at_ms: u64,
    /// Who pulled the trigger
    triggered_by: address,
}

// =====================================================================
// EVENTS
// =====================================================================
public struct SwitchArmed has copy, drop {
    switch_id: ID,
    vault_id: ID,
    inactivity_limit_ms: u64,
}

public struct SwitchTriggered has copy, drop {
    switch_id: ID,
    vault_id: ID,
    triggered_by: address,
    recovery_address: address,
    elapsed_ms: u64,
}

public struct SwitchReset has copy, drop {
    switch_id: ID,
    vault_id: ID,
}

// =====================================================================
// SETUP
// =====================================================================

/// Creates and shares a SwitchState for a given vault.
/// Call once after create_vault. The returned object is shared so
/// the off-chain relayer can monitor it via RPC.
public fun arm(
    vault: &VaultState,
    ctx: &mut TxContext,
) {
    let vault_id = object::id(vault);

    let state = SwitchState {
        id: object::new(ctx),
        vault_id,
        has_triggered: false,
        triggered_at_ms: 0,
        triggered_by: @0x0,
    };

    let switch_id = object::id(&state);

    event::emit(SwitchArmed {
        switch_id,
        vault_id,
        inactivity_limit_ms: vault::inactivity_limit_ms(vault),
    });

    transfer::share_object(state);
}

// =====================================================================
// TRIGGER — callable by anyone once threshold is exceeded
// =====================================================================

/// Anyone can call this once the vault has been inactive for long enough.
///
/// What happens:
///   - Verifies elapsed time >= inactivity_limit_ms using the on-chain Clock
///   - Transfers the LeaderCap to vault.recovery_address
///   - Marks the SwitchState as triggered (one-time only)
///
/// The LeaderCap must be passed in by the caller (e.g. the relayer wallet
/// holds it or it is stored in a recoverable location). In the full flow,
/// the leader stores their LeaderCap in a way that the relayer can include
/// it in the PTB when the switch fires.
///
/// The recovery_address (e.g. an alliance multi-sig) then holds the
/// LeaderCap and can call vault::add_member, vault::lift_lockdown, etc.
public fun trigger(
    state: &mut SwitchState,
    vault: &VaultState,
    leader_cap: LeaderCap,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(!state.has_triggered, EAlreadyTriggered);
    assert!(state.vault_id == object::id(vault), ENotYetInactive); // vault mismatch

    let now_ms = clock::timestamp_ms(clock);
    let last_active = vault::last_active_ms(vault);
    let limit = vault::inactivity_limit_ms(vault);
    let elapsed = now_ms - last_active;

    assert!(elapsed >= limit, ENotYetInactive);

    let recovery = vault::recovery_address(vault);
    let triggered_by = tx_context::sender(ctx);

    state.has_triggered = true;
    state.triggered_at_ms = now_ms;
    state.triggered_by = triggered_by;

    event::emit(SwitchTriggered {
        switch_id: object::id(state),
        vault_id: object::id(vault),
        triggered_by,
        recovery_address: recovery,
        elapsed_ms: elapsed,
    });

    // Transfer governance to the recovery address (multi-sig or officer wallet)
    transfer::public_transfer(leader_cap, recovery);
}

// =====================================================================
// READ HELPERS — used by the off-chain relayer to decide when to fire
// =====================================================================

/// Returns true if the inactivity threshold has been exceeded.
public fun is_triggerable(vault: &VaultState, clock: &Clock): bool {
    if (vault::is_locked(vault)) return false;
    let elapsed = elapsed_ms(vault, clock);
    elapsed >= vault::inactivity_limit_ms(vault)
}

/// Milliseconds since the last recorded leader/officer action.
public fun elapsed_ms(vault: &VaultState, clock: &Clock): u64 {
    let now_ms = clock::timestamp_ms(clock);
    let last = vault::last_active_ms(vault);
    if (now_ms >= last) { now_ms - last } else { 0 }
}

/// Milliseconds remaining before the switch can fire. Returns 0 if past threshold.
public fun remaining_ms(vault: &VaultState, clock: &Clock): u64 {
    let limit = vault::inactivity_limit_ms(vault);
    let elapsed = elapsed_ms(vault, clock);
    if (elapsed >= limit) { 0 } else { limit - elapsed }
}

public fun has_triggered(state: &SwitchState): bool { state.has_triggered }

public fun triggered_at_ms(state: &SwitchState): u64 { state.triggered_at_ms }