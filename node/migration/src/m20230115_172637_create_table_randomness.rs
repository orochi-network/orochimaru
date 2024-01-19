use crate::m20220101_000001_create_table_keyring::Keyring;
use crate::m20221229_005309_create_table_receiver::Receiver;
use sea_orm_migration::prelude::*;
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Randomness::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Randomness::Id)
                            .big_integer()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Randomness::KeyringId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Randomness::ReceiverId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Randomness::Epoch).big_integer().not_null())
                    .col(ColumnDef::new(Randomness::Alpha).string().not_null())
                    .col(ColumnDef::new(Randomness::Gamma).string().not_null())
                    .col(ColumnDef::new(Randomness::C).string().not_null())
                    .col(ColumnDef::new(Randomness::S).string().not_null())
                    .col(ColumnDef::new(Randomness::Y).string().not_null())
                    .col(
                        ColumnDef::new(Randomness::WitnessAddress)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Randomness::WitnessGamma).string().not_null())
                    .col(ColumnDef::new(Randomness::WitnessHash).string().not_null())
                    .col(ColumnDef::new(Randomness::InverseZ).string().not_null())
                    // Signature should be unique, according to uniqueness of ECDSA
                    .col(
                        ColumnDef::new(Randomness::SignatureProof)
                            .unique_key()
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Randomness::CreatedDate)
                            .timestamp()
                            .extra("DEFAULT CURRENT_TIMESTAMP".to_string())
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("link_randomness_to_keyring")
                            .from_tbl(Randomness::Table)
                            .from_col(Randomness::KeyringId)
                            .to_tbl(Keyring::Table)
                            .to_col(Keyring::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("link_randomness_to_receiver")
                            .from_tbl(Randomness::Table)
                            .from_col(Randomness::ReceiverId)
                            .to_tbl(Receiver::Table)
                            .to_col(Receiver::Id),
                    )
                    .index(
                        Index::create()
                            .name("index_alpha")
                            .unique()
                            .col(Randomness::Alpha),
                    )
                    .index(Index::create().name("index_y").unique().col(Randomness::Y))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Randomness::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum Randomness {
    Table,
    Id,
    KeyringId,
    ReceiverId,
    Epoch,
    Alpha,
    Gamma,
    C,
    S,
    Y,
    WitnessAddress,
    WitnessGamma,
    WitnessHash,
    InverseZ,
    SignatureProof,
    CreatedDate,
}
