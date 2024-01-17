use libecvrf::{KeyPair, ECVRF};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::postgres_sql::Postgres;

/// Node context
pub struct NodeContext {
    ecvrf: ECVRF<'static>,
    is_testnet: bool,
    postgres: Postgres,
    key_id: i64,
    keypair: KeyPair,
    // Single lock will be the botle neck when we have more user
    // I'm prefer to use [HashMap] to mapping from receiver_id -> lock
    pub sync: Mutex<bool>,
}

impl NodeContext {
    /// Create a new instance of node context
    pub fn new(key_id: i64, keypair: KeyPair, is_testnet: bool, postgres: Postgres) -> Arc<Self> {
        let ecvrf = ECVRF::new(keypair.secret_key);
        Arc::new(Self {
            key_id,
            ecvrf,
            is_testnet,
            postgres,
            keypair,
            sync: Mutex::new(false),
        })
    }

    /// Get key ID
    pub fn key_id(&self) -> i64 {
        self.key_id
    }

    /// Get keypair
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Get ECVRF instance
    pub fn ecvrf(&self) -> &ECVRF<'static> {
        &self.ecvrf
    }

    /// Check if node is running on testnet
    pub fn is_testnet(&self) -> bool {
        self.is_testnet
    }

    /// Get Postgres database
    pub fn postgres(&self) -> &Postgres {
        &self.postgres
    }
}
