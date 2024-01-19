use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Keyring::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Keyring::Id)
                            .big_integer()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Keyring::Username).string().not_null())
                    .col(ColumnDef::new(Keyring::HMACSecret).string().not_null())
                    .col(
                        ColumnDef::new(Keyring::PublicKey)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Keyring::SecretKey)
                            .string()
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Keyring::CreatedDate)
                            .timestamp()
                            .not_null()
                            .extra("DEFAULT CURRENT_TIMESTAMP".to_string()),
                    )
                    .index(
                        Index::create()
                            .name("index_username")
                            .unique()
                            .col(Keyring::Username),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Keyring::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum Keyring {
    Table,
    Id,
    Username,
    HMACSecret,
    PublicKey,
    SecretKey,
    CreatedDate,
}
