/// Loaded from .env at startup. All object IDs come from your deploy script output.
#[derive(Debug, Clone)]
pub struct Config {
    // Sui
    pub sui_rpc_url: String,
    pub relayer_private_key: String,   // base64 encoded keypair (sui keytool export)

    // Deployed contract
    pub package_id: String,
    pub vault_state_id: String,
    pub lockdown_state_id: String,
    pub switch_state_id: String,
    pub clock_id: String,              // always 0x6 on Sui

    // EVE Frontier
    /// Real: wss://world-api-utopia.uat.pub.evefrontier.com/ws
    /// Mock: set to "mock" to use the built-in mock emitter
    pub eve_ws_url: String,

    /// The SSU object ID in the EVE world (from game after anchoring)
    pub ssu_object_id: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenv::dotenv().ok();
        Ok(Config {
            sui_rpc_url: std::env::var("SUI_RPC_URL")
                .unwrap_or("https://fullnode.testnet.sui.io:443".into()),
            relayer_private_key: std::env::var("RELAYER_PRIVATE_KEY")?,
            package_id: std::env::var("PACKAGE_ID")?,
            vault_state_id: std::env::var("VAULT_STATE_ID")?,
            lockdown_state_id: std::env::var("LOCKDOWN_STATE_ID")?,
            switch_state_id: std::env::var("SWITCH_STATE_ID")?,
            clock_id: "0x0000000000000000000000000000000000000000000000000000000000000006".into(),
            eve_ws_url: std::env::var("EVE_WS_URL")
                .unwrap_or("mock".into()),
            ssu_object_id: std::env::var("SSU_OBJECT_ID")?,
        })
    }
}