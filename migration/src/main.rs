use dotenv::dotenv;
use sea_orm_migration::prelude::*;
use std::{fs, path::Path};

#[async_std::main]
async fn main() {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");
    let file = database_url.replace("sqlite://", "./");
    if !Path::new(&file).exists() {
        fs::write(file, "").unwrap();
    }
    cli::run_cli(migration::Migrator).await;
}
