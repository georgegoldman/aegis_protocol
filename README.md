# Aegis Protocol: Verifiable Alliance Vaults

**EVE Frontier** is a lawless, hardcore space survival universe where players must build and protect their own civilizations
. Reigniting this civilization relies on player-made infrastructure, specifically S**mart Assemblies** like Smart Storage Units (SSUs)
.
The **Aegis Protocol** is a programmable security layer designed to protect these assets from the inherent risks of the Frontier.

## The Problem

In EVE Frontier, player organizations (Alliances) store massive amounts of value and critical intelligence inside Smart Storage Units (SSUs)
. Because the universe is player-driven and features real consequences
, these assets are highly vulnerable:
Leader Abandonment: If an Alliance leader goes offline permanently, the assets locked inside the SSU become inaccessible.
Theft and Sieges: If an SSU is attacked and destroyed by hostile players, all stored assets and intel are permanently lost or stolen.

## The Solution

The Aegis Protocol turns a static storage box into a smart, self-defending escrow vault. By bridging in-game events with the Sui blockchain
, it introduces a "Dead Man's Switch," multi-sig emergency recovery, and an automated threat response mechanism.


## System Architectural Design

The architecture takes advantage of Sui's object-centric model and sub-second transaction finality to bridge the on-chain and in-client experiences
. It is divided into three distinct layers:

1. **On-Chain Layer (Sui Move)**
This layer utilizes **the Move programming language** to enforce the "Digital Laws" of the vault safely and concurrently

- Vault Object: A Move smart contract that wraps the standard SSU permissions, treating the SSU as a persistent, programmable object
- **Access Control Matrix:** Defines deposit/withdraw privileges based on organizational roles (e.g., Leader, Officer, Member).
- **Time-Locked Recovery (Dead Man's Switch):** A function that tracks the last_active_timestamp. If inactivity exceeds a predetermined limit (e.g., 30 days), ownership of the vault object automatically transfers to a predefined multi-sig address.
- **Emergency Lockdown:** A function that instantly revokes all standard withdrawal permissions when triggered, securing the assets during a siege.

2. **Off-Chain Relayer Engine (Rust)**
Hosted on an Ubuntu environment, this high-performance engine acts as the nervous system between the EVE Frontier game servers and the Sui blockchain.

- **WebSocket Listener:** A Rust service that continuously monitors the EVE Frontier API for specific threat events (e.g., StructureShieldDepleted, PlayerPodded).
- **Transaction Builder:** Upon detecting a threat, the relayer constructs a transaction to call the "Emergency Lockdown" function on the Sui network.
- **Key Manager:** Securely holds the programmatic wallet keys required to sign and execute emergency transactions with near-zero latency.

3. **Verifiable Storage Layer**
Designed for data too large or sensitive to store directly on the Sui chain (e.g., encrypted alliance intel, supply chain coordinates).

- **Encrypted Payloads:** Alliance data is encrypted locally.
- **Decentralized Blob Storage:** Encrypted payloads are pushed to a decentralized storage network.
- **On-Chain Anchoring:** The resulting storage hash (CID) is anchored inside the Sui Vault Object. Only players with the correct on-chain access matrix permissions can retrieve the hash and decrypt the data.


## System Data Flow: Threat Response Scenario

The following sequence triggers when an Alliance SSU falls under enemy attack:

| Step | Action                         | Component                     | Output / State Change                                      |
|------|--------------------------------|-------------------------------|------------------------------------------------------------|
| 1    | Enemy attacks Alliance SSU     | EVE Frontier Server           | Emits ShieldAlert event via API                            |
| 2    | Detects ShieldAlert event      | Rust Relayer (Off-Chain)      | Parses event data and verifies the target                  |
| 3    | Constructs lockdown transaction| Rust Relayer (Off-Chain)      | Signs transaction via the programmatic Key Manager wallet  |
| 4    | Executes LockdownVault         | Sui Network (On-Chain)        | Vault Object permissions updated instantly via Move contract |
| 5    | Vault locked to all users      | EVE Frontier SSU              | Assets secured against theft during the active siege       |