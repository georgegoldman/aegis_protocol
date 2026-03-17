/// lockdown.move
/// Aegis Protocol — Emergency Lockdown
///
/// The Rust relayer listens for EVE Frontier threat events via WebSocket
/// (ShieldAlert, StructureShieldDepleted). On detection it builds a PTB
/// calling execute_lockdown here.
///
/// What lockdown actually does in the world contract context:
///   - Sets vault.is_locked = true (via vault::set_locked)
///   - While locked, vault::member_deposit and vault::officer_withdraw
///     both abort with EVaultLocked BEFORE constructing AegisAuth {}
///   - This means the SSU extension is still registered, but our gating
///     layer prevents any calls reaching the world contract
///   - Assets in the SSU are safe: no Auth witness = no movement
module aegis_contract::lockdown;

use sui::{clock::{Self, Clock}, event};
use aegis_contract::vault::{Self, VaultState, LeaderCap};

// =====================================================================
// ERRORS
// =====================================================================
const EAlreadyLocked: u64  = 200;
const ENotLocked: u64      = 201;
const ECooldownActive: u64 = 202;
const EVaultMismatch: u64  = 203;

// 5 minutes between lockdown triggers (prevents relayer spam)
const LOCKDOWN_COOLDOWN_MS: u64 = 300_000;

// =====================================================================
// STATE — tracks lockdown history, shared object
// =====================================================================
public struct LockdownState has key {
    id: sui::object::UID,
    vault_id: ID,
    total_lockdowns: u64,
    last_trigger_ms: u64,
    last_threat_type: std::string::String,
}

// =====================================================================
// EVENTS
// =====================================================================
public struct LockdownExecuted has copy, drop {
    vault_id: ID,
    threat_type: std::string::String,
    triggered_by: address,
    timestamp_ms: u64,
    total_lockdowns: u64,
}

public struct LockdownLifted has copy, drop {
    vault_id: ID,
    lifted_by: address,
    timestamp_ms: u64,
}

public struct ThreatLogged has copy, drop {
    vault_id: ID,
    threat_type: std::string::String,
    timestamp_ms: u64,
}

// =====================================================================
// SETUP
// =====================================================================

/// Creates and shares the LockdownState tracker for a vault.
/// Call once after create_vault and arm().
public fun create_lockdown_state(
    vault: &VaultState,
    ctx: &mut TxContext,
) {
    let state = LockdownState {
        id: object::new(ctx),
        vault_id: object::id(vault),
        total_lockdowns: 0,
        last_trigger_ms: 0,
        last_threat_type: std::string::utf8(b"none"),
    };
    sui::transfer::share_object(state);
}

// =====================================================================
// EXECUTE LOCKDOWN — called by Rust relayer PTB
// =====================================================================

/// Called by the relayer's programmatic wallet when a threat event is detected.
///
/// PTB sequence the relayer builds:
///   1. lockdown::execute_lockdown(vault, lockdown_state, b"ShieldAlert", clock)
///
/// This sets vault.is_locked = true. All subsequent calls to
/// vault::member_deposit and vault::officer_withdraw will abort.
/// The world SSU's actual inventory is untouched — items stay put.
///
/// `threat_type` should be the raw EVE Frontier event name as bytes,
/// e.g. b"ShieldAlert" or b"StructureShieldDepleted".
public fun execute_lockdown(
    vault: &mut VaultState,
    state: &mut LockdownState,
    threat_type: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(state.vault_id == object::id(vault), EVaultMismatch);
    assert!(!vault::is_locked(vault), EAlreadyLocked);

    let now_ms = clock::timestamp_ms(clock);

    // Cooldown check — prevents rapid re-triggering from noisy relayers
    assert!(
        state.last_trigger_ms == 0
            || (now_ms - state.last_trigger_ms) >= LOCKDOWN_COOLDOWN_MS,
        ECooldownActive,
    );

    let threat_str = std::string::utf8(threat_type);

    event::emit(ThreatLogged {
        vault_id: object::id(vault),
        threat_type: threat_str,
        timestamp_ms: now_ms,
    });

    // Lock the vault — withholds AegisAuth from being constructed
    // by any vault:: functions until lifted
    vault::set_locked(vault, true);

    state.last_trigger_ms = now_ms;
    state.total_lockdowns = state.total_lockdowns + 1;
    state.last_threat_type = threat_str;

    event::emit(LockdownExecuted {
        vault_id: object::id(vault),
        threat_type: state.last_threat_type,
        triggered_by: tx_context::sender(ctx),
        timestamp_ms: now_ms,
        total_lockdowns: state.total_lockdowns,
    });
}

// =====================================================================
// LIFT LOCKDOWN — Leader restores access post-siege
// =====================================================================

/// Only the LeaderCap holder can lift the lockdown.
/// This re-enables AegisAuth construction in vault functions.
public fun lift_lockdown(
    vault: &mut VaultState,
    cap: &LeaderCap,
    state: &LockdownState,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(state.vault_id == object::id(vault), EVaultMismatch);
    assert!(vault::is_locked(vault), ENotLocked);

    vault::lift_lockdown(vault, cap);

    event::emit(LockdownLifted {
        vault_id: object::id(vault),
        lifted_by: tx_context::sender(ctx),
        timestamp_ms: clock::timestamp_ms(clock),
    });
}

// =====================================================================
// READ HELPERS
// =====================================================================

public fun total_lockdowns(state: &LockdownState): u64 { state.total_lockdowns }

public fun last_trigger_ms(state: &LockdownState): u64 { state.last_trigger_ms }

public fun is_in_cooldown(state: &LockdownState, clock: &Clock): bool {
    if (state.last_trigger_ms == 0) return false;
    (clock::timestamp_ms(clock) - state.last_trigger_ms) < LOCKDOWN_COOLDOWN_MS
}

public fun cooldown_remaining_ms(state: &LockdownState, clock: &Clock): u64 {
    if (!is_in_cooldown(state, clock)) return 0;
    let elapsed = clock::timestamp_ms(clock) - state.last_trigger_ms;
    LOCKDOWN_COOLDOWN_MS - elapsed
}