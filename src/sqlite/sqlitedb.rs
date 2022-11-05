use std::{borrow::BorrowMut, sync::Arc};

use sea_orm::DatabaseConnection;

pub struct SqliteDB {
    pub connection: DatabaseConnection,
}

impl SqliteDB {}
