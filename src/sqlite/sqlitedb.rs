use super::{
    keyring::{ActiveModel as AModelKeyring, Entity as Keyring, Model as ModelKeyring},
    randomness::{
        ActiveModel as AModelRandomness, Column as ColumnRandomness, Entity as Randomness,
        Model as ModelRandomness,
    },
};

use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, DbErr, EntityTrait, InsertResult,
    QueryFilter,
};

pub struct SqliteDB {
    pub connection: DatabaseConnection,
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

    // Get all keys in keyring table
    pub async fn keyring_find_all(&self) -> Result<Vec<ModelKeyring>, DbErr> {
        Keyring::find().all(&self.connection).await
    }

    // Insert data to keyring table
    pub async fn keyring_insert(
        &self,
        json_record: serde_json::Value,
    ) -> Result<InsertResult<AModelKeyring>, DbErr> {
        let new_record = AModelKeyring::from_json(json_record)?;
        Keyring::insert(new_record).exec(&self.connection).await
    }

    pub async fn randomness_find_by_epoch(
        &self,
        epoch: i32,
    ) -> Result<Vec<ModelRandomness>, DbErr> {
        Randomness::find()
            .filter(ColumnRandomness::Epoch.eq(epoch))
            .all(&self.connection)
            .await
    }

    pub async fn randomness_insert(
        &self,
        json_record: serde_json::Value,
    ) -> Result<InsertResult<AModelRandomness>, DbErr> {
        let new_record = AModelRandomness::from_json(json_record)?;
        Randomness::insert(new_record).exec(&self.connection).await
    }
}
