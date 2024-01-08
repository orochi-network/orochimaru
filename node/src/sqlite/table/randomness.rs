use crate::randomness::{ActiveModel, Column, Entity, Model};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, Order,
    QueryFilter, QueryOrder, QuerySelect,
};

use super::ReceiverTable;

/// Randomness table
pub struct RandomnessTable<'a> {
    /// Database connection
    pub connection: &'a DatabaseConnection,
}

/// Randomness related columns
impl<'a> RandomnessTable<'a> {
    /// Create new instance of randomness
    pub fn new(connection: &'a DatabaseConnection) -> Self {
        Self { connection }
    }

    /// Find randomness record by its network and address
    pub async fn find_recent_epoch(
        &self,
        network: u32,
        address: &str,
        epoch: u32,
    ) -> Result<Vec<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .find_one(network, address)
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
                    // 20 is the limit of number of records
                    .limit(20)
                    .order_by(Column::Epoch, Order::Asc)
                    .all(self.connection)
                    .await
            }
            None => Ok(vec![]),
        }
    }

    /// Find randomness record by its network and address
    pub async fn find_latest_epoch(
        &self,
        network: u32,
        address: &str,
    ) -> Result<Option<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .find_one(network, address)
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

    /// Find randomness record by its network, address and epoch_id
    pub async fn find_given_epoch(
        &self,
        network: u32,
        address: &str,
        epoch_id: u32,
    ) -> Result<Option<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .find_one(network, address)
            .await
            .expect("Unable to query receiver from database");
        match receiver {
            Some(receiver_record) => {
                Entity::find()
                    .filter(
                        Condition::all()
                            .add(Column::ReceiverId.eq(receiver_record.id))
                            .add(Column::Epoch.eq(epoch_id)),
                    )
                    .order_by(Column::Epoch, Order::Desc)
                    .one(self.connection)
                    .await
            }
            None => Ok(None),
        }
    }

    /// Find randomness record by its network and address
    pub async fn insert(&self, json_record: serde_json::Value) -> Result<Model, DbErr> {
        let new_record = ActiveModel::from_json(json_record)?;

        Entity::insert(new_record)
            .exec_with_returning(self.connection)
            .await
    }

    /// Find randomness record by its network and address
    pub async fn update(&self, active_model: ActiveModel) -> Result<Model, DbErr> {
        active_model.update(self.connection).await
    }
}
