//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.11

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Receiver data
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "receiver")]
pub struct Model {
    /// Receiver Id
    #[serde(skip_deserializing)]
    #[sea_orm(primary_key)]
    pub id: i64,
    /// Keyring Id
    #[serde(skip_serializing)]
    pub keyring_id: i64,
    /// Receiver name
    #[sea_orm(unique)]
    pub name: String,
    /// Receiver address
    pub address: String,
    /// Network chain Id
    pub network: i64,
    /// Receiver nonce
    pub nonce: i64,
    /// Created date
    #[serde(skip_deserializing)]
    pub created_date: DateTime,
}

/// Relationship to randomness
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Linked to keyring
    #[sea_orm(
        belongs_to = "super::keyring::Entity",
        from = "Column::KeyringId",
        to = "super::keyring::Column::Id",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Keyring,
    /// Linked to randomness
    #[sea_orm(has_many = "super::randomness::Entity")]
    Randomness,
}

impl Related<super::keyring::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Keyring.def()
    }
}

impl Related<super::randomness::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Randomness.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
