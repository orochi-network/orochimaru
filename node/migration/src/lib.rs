pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table_keyring;
mod m20221229_005309_create_table_receiver;
mod m20230115_172637_create_table_randomness;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table_keyring::Migration),
            Box::new(m20221229_005309_create_table_receiver::Migration),
            Box::new(m20230115_172637_create_table_randomness::Migration),
        ]
    }
}
