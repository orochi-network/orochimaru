use crate::receiver::{ActiveModel, Column, Entity, Model};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait,
    QueryFilter,
};

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
    pub async fn update(
        &self,
        record: &Model,
        network: u32,
        address: &String,
    ) -> Result<Option<Model>, DbErr> {
        Entity::update(ActiveModel {
            id: ActiveValue::set(record.id),
            name: ActiveValue::set(record.name.clone()),
            network: ActiveValue::set(network),
            address: ActiveValue::set(address.clone()),
            nonce: ActiveValue::set(record.nonce + 1),
            created_date: ActiveValue::default(),
        })
        .exec(self.connection)
        .await
        .expect("Unable to update receiver");
        self.find_by_id(record.id).await

        /*
        match receiver {
            Some(r) => {
                Entity::update(ActiveModel {
                    id: ActiveValue::set(r.id),
                    name: ActiveValue::set(r.name),
                    network: ActiveValue::set(network),
                    address: ActiveValue::set(address.clone()),
                    nonce: ActiveValue::set(r.nonce + 1),
                    created_date: ActiveValue::default(),
                })
                .exec(self.connection)
                .await
                .expect("Unable to update receiver");
                self.find_by_id(r.id).await
            }
            None => Err(DbErr::Custom("Unable to insert new record".to_string())),
        }
        {
            let returning_receiver = Entity::insert(ActiveModel {
                id: ActiveValue::not_set(),
                name: ActiveValue::set(Uuid::new_v4().to_string()),
                network: ActiveValue::set(network),
                address: ActiveValue::set(address.clone()),
                nonce: ActiveValue::set(0),
                created_date: ActiveValue::default(),
            })
            .exec_with_returning(self.connection)
            .await
            .expect("Unable to insert new receiver record");
            Ok(Some(returning_receiver))
        }*/
    }

    pub async fn find_one(&self, network: u32, address: &String) -> Result<Option<Model>, DbErr> {
        Entity::find()
            .filter(
                Condition::all()
                    .add(Column::Address.eq(address.clone()))
                    .add(Column::Network.eq(network)),
            )
            .one(self.connection)
            .await
    }

    // Insert data to receiver table
    pub async fn insert(&self, json_record: serde_json::Value) -> Result<Model, DbErr> {
        let new_record = ActiveModel::from_json(json_record)?;
        Entity::insert(new_record)
            .exec_with_returning(self.connection)
            .await
    }
}
