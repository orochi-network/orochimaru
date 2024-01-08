use crate::receiver::{ActiveModel, Column, Entity, Model};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, QueryFilter,
};

/// Receiver table
pub struct ReceiverTable<'a> {
    connection: &'a DatabaseConnection,
}

impl<'a> ReceiverTable<'a> {
    /// Create new instance of receiver table
    pub fn new(connection: &'a DatabaseConnection) -> Self {
        Self { connection }
    }

    /// Find receiver record by its network and address
    pub async fn find_by_id(&self, id: u32) -> Result<Option<Model>, DbErr> {
        Entity::find_by_id(id).one(self.connection).await
    }

    /// Find receiver record by its network and address
    pub async fn update(&self, record: ActiveModel) -> Result<Model, DbErr> {
        record.update(self.connection).await
    }

    /// Find receiver record by its network and address
    pub async fn find_one(&self, network: u32, address: &str) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(
                Condition::all()
                    .add(Column::Address.eq(address.to_owned()))
                    .add(Column::Network.eq(network)),
            )
            .one(self.connection)
            .await
    }

    /// Insert data to receiver table
    pub async fn insert(&self, json_record: serde_json::Value) -> Result<Model, DbErr> {
        let new_record = ActiveModel::from_json(json_record)?;
        Entity::insert(new_record)
            .exec_with_returning(self.connection)
            .await
    }
}
