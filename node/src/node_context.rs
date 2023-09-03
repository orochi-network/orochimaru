use crate::sqlite::SQLiteDB;
use libecvrf::{KeyPair, ECVRF};
use std::sync::Arc;

/// Node context
pub struct NodeContext {
    ecvrf: ECVRF<'static>,
    is_testnet: bool,
    sqlite: SQLiteDB,
    key_id: u32,
    keypair: KeyPair,
}

impl NodeContext {
    /// Create a new instance of node context
    pub fn new(key_id: u32, keypair: KeyPair, is_testnet: bool, sqlite: SQLiteDB) -> Arc<Self> {
        let ecvrf = ECVRF::new(keypair.secret_key);
        Arc::new(Self {
            key_id,
            ecvrf,
            is_testnet,
            sqlite,
            keypair,
        })
    }

    /// Get key ID
    pub fn key_id(&self) -> u32 {
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

    /// Get SQLite database
    pub fn sqlite(&self) -> &SQLiteDB {
        &self.sqlite
    }
}
