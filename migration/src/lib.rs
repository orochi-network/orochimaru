pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table_keyring;
mod m20221105_172637_create_table_randomness;
mod m20221229_005309_create_table_receiver;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table_keyring::Migration),
            Box::new(m20221105_172637_create_table_randomness::Migration),
            Box::new(m20221229_005309_create_table_receiver::Migration),
        ]
    }
}
