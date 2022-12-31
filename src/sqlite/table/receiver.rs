use crate::receiver::{ActiveModel, Column, Entity, Model};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait,
    InsertResult, QueryFilter, QueryOrder, QuerySelect,
};
use uuid::Uuid;

pub struct ReceiverTable<'a> {
    connection: &'a DatabaseConnection,
}

impl<'a> ReceiverTable<'a> {
    // Create new instance of receiver table
    pub fn new(connection: &'a DatabaseConnection) -> Self {
        Self { connection }
    }

    pub async fn find_by_id(&self, id: u32) -> Result<Option<Model>, DbErr> {
        Entity::find_by_id(id).one(self.connection).await
    }

    // Find receiver record by its network and address
    pub async fn update(&self, network: u32, address: String) -> Result<Option<Model>, DbErr> {
        let receiver = Entity::find()
            .filter(
                Condition::all()
                    .add(Column::Address.eq(address.clone()))
                    .add(Column::Network.eq(network)),
            )
            .one(self.connection)
            .await
            .expect("Unable to read receiver data from database");

        match receiver {
            Some(r) => {
                Entity::update(ActiveModel {
                    id: ActiveValue::NotSet,
                    name: ActiveValue::NotSet,
                    network: ActiveValue::Set(network),
                    address: ActiveValue::Set(address),
                    nonce: ActiveValue::Set(r.nonce + 1),
                    created_date: ActiveValue::default(),
                })
                .exec(self.connection)
                .await
                .expect("Unable to update record");
                self.find_by_id(r.id).await
            }
            None => {
                let returning_receiver = Entity::insert(ActiveModel {
                    id: ActiveValue::NotSet,
                    name: ActiveValue::Set(Uuid::new_v4().to_string()),
                    network: ActiveValue::Set(network),
                    address: ActiveValue::Set(address),
                    nonce: ActiveValue::Set(0),
                    created_date: ActiveValue::default(),
                })
                .exec_with_returning(self.connection)
                .await
                .expect("Unable to insert new receiver record");
                Ok(Some(returning_receiver))
            }
        }
    }

    pub async fn get_latest_record(
        &self,
        network: u32,
        address: String,
    ) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(
                Condition::all()
                    .add(Column::Network.eq(network))
                    .add(Column::Address.eq(address)),
            )
            .order_by_desc(Column::Nonce)
            .limit(1)
            .one(self.connection)
            .await
    }

    // Insert data to receiver table
    pub async fn insert(
        &self,
        json_record: serde_json::Value,
    ) -> Result<InsertResult<ActiveModel>, DbErr> {
        let new_record = ActiveModel::from_json(json_record)?;
        Entity::insert(new_record).exec(self.connection).await
    }

    // Insert data to receiver table
    pub async fn insert_returning(&self, json_record: serde_json::Value) -> Result<Model, DbErr> {
        let new_record = ActiveModel::from_json(json_record)?;
        Entity::insert(new_record)
            .exec_with_returning(self.connection)
            .await
    }
}
