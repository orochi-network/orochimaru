use sea_orm::{Database, DatabaseConnection};

use super::table::{KeyringTable, RandomnessTable, ReceiverTable};

/// SQL Lite Database
pub struct SQLiteDB {
    connection: DatabaseConnection,
}

impl SQLiteDB {
    /// Create a new instance of SQLite database
    pub async fn new(database_url: String) -> Self {
        Self {
            connection: Database::connect(database_url)
                .await
                .expect("Can not connect to database"),
        }
    }

    /// Get table receiver
    pub fn table_receiver(&self) -> ReceiverTable<'_> {
        ReceiverTable::new(&self.connection)
    }

    /// Get table randomness
    pub fn table_randomness(&self) -> RandomnessTable<'_> {
        RandomnessTable::new(&self.connection)
    }

    /// Get table keyring
    pub fn table_keyring(&self) -> KeyringTable<'_> {
        KeyringTable::new(&self.connection)
    }
}
