use sea_orm::{Database, DatabaseConnection};

use super::table::{KeyringTable, RandomnessTable, ReceiverTable};

pub struct SQLiteDB {
    connection: DatabaseConnection,
}

impl SQLiteDB {
    // Create a new instance of SQLite database
    pub async fn new(database_url: String) -> Self {
        Self {
            connection: Database::connect(database_url)
                .await
                .expect("Can not connect to database"),
        }
    }

    pub fn table_receiver(&self) -> ReceiverTable {
        ReceiverTable::new(&self.connection)
    }

    pub fn table_randomness(&self) -> RandomnessTable {
        RandomnessTable::new(&self.connection)
    }

    pub fn table_keyring(&self) -> KeyringTable {
        KeyringTable::new(&self.connection)
    }
}
