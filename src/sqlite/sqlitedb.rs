use std::{borrow::BorrowMut, sync::Arc};

pub struct SqliteDB {
    pub connection: SqliteConnection,
}

impl SqliteDB {
    pub fn new(database_url: String) -> Self {
        let conn = SqliteConnection::establish(&database_url)
            .unwrap_or_else(|_| panic!("Error connecting to {}", database_url));
        Self { connection: conn }
    }

    pub fn keyring_new_record(
        &mut self,
        val_network: i32,
        val_secret_key: String,
        val_public_key: String,
    ) -> QueryResult<usize> {
        diesel::insert_into(keyring::table)
            .values(NewKeyringRecord {
                network: val_network,
                secret_key: val_secret_key,
                public_key: val_public_key,
            })
            .execute(self.connection.borrow_mut())
    }

    pub fn keyring_get_records(&mut self) -> QueryResult<Vec<Keyring>> {
        use super::schema::keyring::dsl::*;
        keyring.load::<Keyring>(self.connection.borrow_mut())
    }
}
