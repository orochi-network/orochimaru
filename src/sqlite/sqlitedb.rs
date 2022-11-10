use super::{
    keyring::{
        ActiveModel as AModelKeyring, Column as ColumnKeyring, Entity as Keyring,
        Model as ModelKeyring,
    },
    randomness::{
        ActiveModel as AModelRandomness, Column as ColumnRandomness, Entity as Randomness,
        Model as ModelRandomness,
    },
};

use hmac::digest::Key;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, DbErr, EntityTrait, InsertResult,
    QueryFilter,
};

pub struct KeyringTable<'a> {
    connection: &'a DatabaseConnection,
}

impl<'a> KeyringTable<'a> {
    pub async fn new(conn: &'a DatabaseConnection) -> KeyringTable {
        Self { connection: conn }
    }

    pub async fn find_by_id(&self, id: u32) -> Result<Option<ModelKeyring>, DbErr> {
        Keyring::find_by_id(id).one(self.connection).await
    }

    pub async fn find_by_name(&self, name: String) -> Result<Option<ModelKeyring>, DbErr> {
        Keyring::find()
            .filter(ColumnKeyring::Username.eq(name))
            .one(self.connection)
            .await
    }

    // Get all keys in keyring table
    pub async fn find_all(&self) -> Result<Vec<ModelKeyring>, DbErr> {
        Keyring::find().all(self.connection).await
    }

    // Insert data to keyring table
    pub async fn insert(
        &self,
        json_record: serde_json::Value,
    ) -> Result<InsertResult<AModelKeyring>, DbErr> {
        let new_record = AModelKeyring::from_json(json_record)?;
        Keyring::insert(new_record).exec(self.connection).await
    }
}

pub struct RandomnessTable<'a> {
    connection: &'a DatabaseConnection,
}

impl<'a> RandomnessTable<'a> {
    pub async fn new(conn: &'a DatabaseConnection) -> RandomnessTable {
        Self { connection: conn }
    }

    pub async fn find_by_epoch(&self, epoch: i32) -> Result<Vec<ModelRandomness>, DbErr> {
        Randomness::find()
            .filter(ColumnRandomness::Epoch.eq(epoch))
            .all(self.connection)
            .await
    }

    pub async fn insert(
        &self,
        json_record: serde_json::Value,
    ) -> Result<InsertResult<AModelRandomness>, DbErr> {
        let new_record = AModelRandomness::from_json(json_record)?;
        Randomness::insert(new_record).exec(self.connection).await
    }
}

pub struct SqliteDB {
    connection: DatabaseConnection,
}

impl SqliteDB {
    // Create a new instance of SQLite database
    pub async fn new(database_url: String) -> Self {
        Self {
            connection: Database::connect(database_url)
                .await
                .expect("Can not connect to database"),
        }
    }

    pub async fn table_randomness(&self) -> RandomnessTable {
        RandomnessTable::new(&self.connection).await
    }

    pub async fn table_keyring(&self) -> KeyringTable {
        KeyringTable::new(&self.connection).await
    }
}
