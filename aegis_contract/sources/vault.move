/// vault.move
/// Aegis Protocol — Alliance Vault Extension for EVE Frontier SSUs
///
/// This module registers itself as an extension on a real world::storage_unit::StorageUnit.
/// It enforces role-based access control (Leader / Officer / Member) on top of the SSU's
/// native deposit/withdraw functions. It does NOT shadow the inventory — it gates access
/// to the real one.
///
/// Integration flow:
///   1. Deploy this package → get package ID
///   2. Call vault::register_extension(storage_unit, owner_cap) → SSU now has AegisAuth
///   3. Alliance members call vault::member_withdraw / vault::member_deposit
///      which check roles then call storage_unit::withdraw_item<AegisAuth> etc.
module aegis_contract::vault;

use std::string::{Self, String};
use sui::{clock::{Self, Clock}, event};
use world::{
    access::OwnerCap,
    character::Character,
    inventory::Item,
    storage_unit::{Self, StorageUnit},
};

// =====================================================================
// ERRORS
// =====================================================================
const ENotLeader: u64         = 0;
const ENotOfficerOrAbove: u64 = 1;
const ENotMember: u64         = 2;
const EVaultLocked: u64       = 3;
const EAlreadyMember: u64     = 4;
const EInvalidRole: u64       = 5;
const ESSUMustBeOnline: u64   = 6;

// =====================================================================
// ROLE CONSTANTS
// =====================================================================
const ROLE_LEADER: u8  = 0;
const ROLE_OFFICER: u8 = 1;
const ROLE_MEMBER: u8  = 2;

// =====================================================================
// WITNESS — typed extension auth for the world SSU
// =====================================================================
/// This is the Auth witness registered on the SSU via
/// storage_unit::authorize_extension<AegisAuth>.
/// Only functions in THIS module can construct it, so only
/// this module's logic can call deposit_item / withdraw_item on the SSU.
public struct AegisAuth has drop {}

// =====================================================================
// VAULT STATE — a separate shared object tracking ACL + lockdown
// =====================================================================

public struct RoleEntry has store, copy, drop {
    member: address,
    role: u8,
}

/// The VaultState is shared alongside the SSU.
/// It holds the alliance ACL, inactivity timestamp, and lockdown flag.
/// The SSU itself holds the actual inventory (via dynamic fields in world contract).
public struct VaultState has key {
    id: UID,
    /// ID of the StorageUnit this vault wraps
    ssu_id: ID,
    /// Human-readable alliance name
    alliance_name: String,
    /// Role-based access control matrix
    access_matrix: vector<RoleEntry>,
    /// Timestamp of last leader/officer action (ms). Used by Dead Man's Switch.
    last_active_ms: u64,
    /// How long before inactivity triggers recovery (ms). Default: 30 days.
    inactivity_limit_ms: u64,
    /// Address that receives the LeaderCap if Dead Man's Switch fires.
    recovery_address: address,
    /// Walrus/IPFS blob CID for encrypted alliance intel, anchored on-chain.
    storage_cid: String,
    /// When true, the AegisAuth witness is withheld — no deposits or withdrawals
    /// can be processed through this extension until lifted.
    is_locked: bool,
}

// LeaderCap — minted once, held by the vault creator.
// Scoped to a specific VaultState by vault_id.
public struct LeaderCap has key, store {
    id: UID,
    vault_id: ID,
}

// =====================================================================
// EVENTS
// =====================================================================
public struct VaultCreated has copy, drop {
    vault_id: ID,
    ssu_id: ID,
    alliance_name: String,
    leader: address,
}

public struct ExtensionRegistered has copy, drop {
    ssu_id: ID,
    vault_id: ID,
}

public struct MemberAdded has copy, drop {
    vault_id: ID,
    member: address,
    role: u8,
}

public struct MemberRemoved has copy, drop {
    vault_id: ID,
    member: address,
}

public struct RoleUpdated has copy, drop {
    vault_id: ID,
    member: address,
    new_role: u8,
}

public struct StorageCidAnchored has copy, drop {
    vault_id: ID,
    cid: String,
}

public struct LockdownStateChanged has copy, drop {
    vault_id: ID,
    is_locked: bool,
}

// =====================================================================
// SETUP — create vault + register extension on real SSU
// =====================================================================

/// Step 1: Create the VaultState and get back a LeaderCap.
/// The caller becomes the Leader.
/// `ssu_id` is the object ID of the StorageUnit you own.
public fun create_vault(
    ssu: &StorageUnit,
    alliance_name: vector<u8>,
    inactivity_limit_ms: u64,
    recovery_address: address,
    clock: &Clock,
    ctx: &mut TxContext,
): LeaderCap {
    let leader_addr = tx_context::sender(ctx);
    let ssu_id = object::id(ssu);

    let mut matrix = vector::empty<RoleEntry>();
    vector::push_back(&mut matrix, RoleEntry {
        member: leader_addr,
        role: ROLE_LEADER,
    });

    let vault = VaultState {
        id: object::new(ctx),
        ssu_id,
        alliance_name: string::utf8(alliance_name),
        access_matrix: matrix,
        last_active_ms: clock::timestamp_ms(clock),
        inactivity_limit_ms,
        recovery_address,
        storage_cid: string::utf8(b""),
        is_locked: false,
    };

    let vault_id = object::id(&vault);

    event::emit(VaultCreated {
        vault_id,
        ssu_id,
        alliance_name: vault.alliance_name,
        leader: leader_addr,
    });

    transfer::share_object(vault);

    LeaderCap {
        id: object::new(ctx),
        vault_id,
    }
}

/// Step 2: Register AegisAuth as the extension on the SSU.
/// Must be called by the Leader (holder of OwnerCap<StorageUnit>).
/// After this, only functions in this module that construct AegisAuth {}
/// can call storage_unit::deposit_item / withdraw_item on this SSU.
public fun register_extension(
    ssu: &mut StorageUnit,
    owner_cap: &OwnerCap<StorageUnit>,
    vault: &VaultState,
    cap: &LeaderCap,
) {
    assert_leader_cap(vault, cap);
    storage_unit::authorize_extension<AegisAuth>(ssu, owner_cap);

    event::emit(ExtensionRegistered {
        ssu_id: object::id(ssu),
        vault_id: object::id(vault),
    });
}

// =====================================================================
// ACCESS CONTROL MATRIX — management
// =====================================================================

public fun add_member(
    vault: &mut VaultState,
    cap: &LeaderCap,
    member: address,
    role: u8,
    clock: &Clock,
) {
    assert_leader_cap(vault, cap);
    assert!(!vault.is_locked, EVaultLocked);
    assert!(role <= ROLE_MEMBER, EInvalidRole);
    assert!(!is_member_internal(vault, member), EAlreadyMember);

    vector::push_back(&mut vault.access_matrix, RoleEntry { member, role });
    vault.last_active_ms = clock::timestamp_ms(clock);

    event::emit(MemberAdded {
        vault_id: object::id(vault),
        member,
        role,
    });
}

public fun remove_member(
    vault: &mut VaultState,
    cap: &LeaderCap,
    member: address,
    clock: &Clock,
) {
    assert_leader_cap(vault, cap);
    assert!(!vault.is_locked, EVaultLocked);

    let mut i = 0;
    let len = vector::length(&vault.access_matrix);
    while (i < len) {
        let entry = vector::borrow(&vault.access_matrix, i);
        if (entry.member == member) {
            vector::remove(&mut vault.access_matrix, i);
            vault.last_active_ms = clock::timestamp_ms(clock);
            event::emit(MemberRemoved { vault_id: object::id(vault), member });
            return
        };
        i = i + 1;
    };
}

public fun update_role(
    vault: &mut VaultState,
    cap: &LeaderCap,
    member: address,
    new_role: u8,
    clock: &Clock,
) {
    assert_leader_cap(vault, cap);
    assert!(!vault.is_locked, EVaultLocked);
    assert!(new_role <= ROLE_MEMBER, EInvalidRole);

    let mut i = 0;
    let len = vector::length(&vault.access_matrix);
    while (i < len) {
        let entry = vector::borrow_mut(&mut vault.access_matrix, i);
        if (entry.member == member) {
            entry.role = new_role;
            vault.last_active_ms = clock::timestamp_ms(clock);
            event::emit(RoleUpdated {
                vault_id: object::id(vault),
                member,
                new_role,
            });
            return
        };
        i = i + 1;
    };
    abort ENotMember
}

// =====================================================================
// ITEM OPERATIONS — wrapping real SSU inventory calls
// =====================================================================

/// Any alliance member can deposit an Item into the SSU's main inventory.
/// The Item must have already been withdrawn from chain by the character
/// (i.e. it is a live world::inventory::Item object in the PTB).
public fun member_deposit(
    vault: &VaultState,
    ssu: &mut StorageUnit,
    character: &Character,
    item: Item,
    caller: address,
    ctx: &mut TxContext,
) {
    assert!(!vault.is_locked, EVaultLocked);
    assert!(is_member_internal(vault, caller), ENotMember);
    assert!(vault.ssu_id == object::id(ssu), ESSUMustBeOnline);

    // Delegate to world contract — AegisAuth proves this call is authorized
    storage_unit::deposit_item<AegisAuth>(ssu, character, item, AegisAuth {}, ctx);
}

/// Officers and above can withdraw items from the SSU main inventory.
/// Members cannot withdraw — they can only deposit.
/// (Adjust this to taste for your alliance rules.)
public fun officer_withdraw(
    vault: &VaultState,
    ssu: &mut StorageUnit,
    character: &Character,
    type_id: u64,
    quantity: u32,
    caller: address,
    ctx: &mut TxContext,
): Item {
    assert!(!vault.is_locked, EVaultLocked);
    let role = get_role(vault, caller);
    assert!(role <= ROLE_OFFICER, ENotOfficerOrAbove);
    assert!(vault.ssu_id == object::id(ssu), ESSUMustBeOnline);

    storage_unit::withdraw_item<AegisAuth>(ssu, character, AegisAuth {}, type_id, quantity, ctx)
}

/// Push an item directly into a specific character's owned inventory slot.
/// Useful for distributing loot, rewards, or recovered assets after a siege.
/// Officers and above only.
public fun distribute_to_member(
    vault: &VaultState,
    ssu: &mut StorageUnit,
    recipient: &Character,
    item: Item,
    caller: address,
    ctx: &mut TxContext,
) {
    assert!(!vault.is_locked, EVaultLocked);
    let role = get_role(vault, caller);
    assert!(role <= ROLE_OFFICER, ENotOfficerOrAbove);
    // Recipient must be in the alliance
    assert!(is_member_internal(vault, recipient.character_address()), ENotMember);
    assert!(vault.ssu_id == object::id(ssu), ESSUMustBeOnline);

    // Uses deposit_to_owned — recipient does NOT need to be the tx sender
    storage_unit::deposit_to_owned<AegisAuth>(ssu, recipient, item, AegisAuth {}, ctx);
}

// =====================================================================
// ACTIVITY PING — resets Dead Man's Switch timer
// =====================================================================

/// Leader or Officer pings to prove they are still active.
/// Must be called at least once every `inactivity_limit_ms` milliseconds
/// to prevent the Dead Man's Switch from firing.
public fun ping(
    vault: &mut VaultState,
    caller: address,
    clock: &Clock,
) {
    let role = get_role(vault, caller);
    assert!(role <= ROLE_OFFICER, ENotOfficerOrAbove);
    vault.last_active_ms = clock::timestamp_ms(clock);
}

// =====================================================================
// VERIFIABLE STORAGE — anchor Walrus CID on-chain
// =====================================================================

/// Officers and above anchor an encrypted intel blob's CID on-chain.
/// The actual blob lives on Walrus/IPFS; only the hash is stored here.
/// Members can read the CID via get_storage_cid to retrieve + decrypt.
public fun anchor_storage_cid(
    vault: &mut VaultState,
    caller: address,
    cid: vector<u8>,
    clock: &Clock,
) {
    assert!(!vault.is_locked, EVaultLocked);
    let role = get_role(vault, caller);
    assert!(role <= ROLE_OFFICER, ENotOfficerOrAbove);

    vault.storage_cid = string::utf8(cid);
    vault.last_active_ms = clock::timestamp_ms(clock);

    event::emit(StorageCidAnchored {
        vault_id: object::id(vault),
        cid: vault.storage_cid,
    });
}

/// Returns the Walrus CID — only alliance members can call this.
public fun get_storage_cid(vault: &VaultState, caller: address): String {
    assert!(is_member_internal(vault, caller), ENotMember);
    vault.storage_cid
}

// =====================================================================
// LOCKDOWN — managed by lockdown.move, exposed here for lift
// =====================================================================

/// Internal: set lockdown state. Called by lockdown::execute_lockdown.
/// Package-internal — only modules in aegis_contract can call this.
public(package) fun set_locked(vault: &mut VaultState, locked: bool) {
    vault.is_locked = locked;
    event::emit(LockdownStateChanged {
        vault_id: object::id(vault),
        is_locked: locked,
    });
}

/// Leader lifts a lockdown after a siege ends.
public fun lift_lockdown(vault: &mut VaultState, cap: &LeaderCap) {
    assert_leader_cap(vault, cap);
    set_locked(vault, false);
}

// =====================================================================
// READ-ONLY HELPERS
// =====================================================================

public fun is_locked(vault: &VaultState): bool { vault.is_locked }

public fun last_active_ms(vault: &VaultState): u64 { vault.last_active_ms }

public fun inactivity_limit_ms(vault: &VaultState): u64 { vault.inactivity_limit_ms }

public fun recovery_address(vault: &VaultState): address { vault.recovery_address }

public fun ssu_id(vault: &VaultState): ID { vault.ssu_id }

public fun get_role(vault: &VaultState, addr: address): u8 {
    let mut i = 0;
    let len = vector::length(&vault.access_matrix);
    while (i < len) {
        let entry = vector::borrow(&vault.access_matrix, i);
        if (entry.member == addr) return entry.role;
        i = i + 1;
    };
    255u8 // not a member
}

public fun is_member(vault: &VaultState, addr: address): bool {
    is_member_internal(vault, addr)
}

// =====================================================================
// INTERNAL
// =====================================================================

fun is_member_internal(vault: &VaultState, addr: address): bool {
    let mut i = 0;
    let len = vector::length(&vault.access_matrix);
    while (i < len) {
        let entry = vector::borrow(&vault.access_matrix, i);
        if (entry.member == addr) return true;
        i = i + 1;
    };
    false
}

fun assert_leader_cap(vault: &VaultState, cap: &LeaderCap) {
    assert!(cap.vault_id == object::id(vault), ENotLeader);
}