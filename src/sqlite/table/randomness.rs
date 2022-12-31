use crate::{
    randomness::{ActiveModel, Column, Entity, Model},
    receiver,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, InsertResult,
    Order, QueryFilter, QueryOrder,
};

use super::ReceiverTable;

pub struct RandomnessTable<'a> {
    pub connection: &'a DatabaseConnection,
}

impl<'a> RandomnessTable<'a> {
    // Create new instance of randomness
    pub fn new(connection: &'a DatabaseConnection) -> Self {
        Self { connection }
    }

    pub async fn find_recent_epoch(
        &self,
        network: u32,
        address: String,
        epoch: u32,
    ) -> Result<Vec<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .get_latest_record(network, address)
            .await
            .expect("Unable to query receiver from database");
        match receiver {
            Some(receiver_record) => {
                Entity::find()
                    .filter(
                        Condition::all()
                            .add(Column::ReceiverId.eq(receiver_record.id))
                            .add(Column::Epoch.gte(epoch)),
                    )
                    .order_by(Column::Epoch, Order::Desc)
                    .all(self.connection)
                    .await
            }
            None => Ok(vec![]),
        }
    }

    pub async fn find_latest_epoch(
        &self,
        network: u32,
        address: String,
    ) -> Result<Option<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .get_latest_record(network, address)
            .await
            .expect("Unable to query receiver from database");
        match receiver {
            Some(receiver_record) => {
                Entity::find()
                    .filter(Column::ReceiverId.eq(receiver_record.id))
                    .order_by(Column::Epoch, Order::Desc)
                    .one(self.connection)
                    .await
            }
            None => Ok(None),
        }
    }

    pub async fn insert(
        &self,
        json_record: serde_json::Value,
    ) -> Result<InsertResult<ActiveModel>, DbErr> {
        let new_record = ActiveModel::from_json(json_record)?;
        Entity::insert(new_record).exec(self.connection).await
    }

    pub async fn insert_returning(&self, json_record: serde_json::Value) -> Result<Model, DbErr> {
        let new_record = ActiveModel::from_json(json_record)?;
        Entity::insert(new_record)
            .exec_with_returning(self.connection)
            .await
    }
}
