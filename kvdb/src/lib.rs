use rocksdb::{BoundColumnFamily, Options, DB};
use std::sync::Arc;
use std::{iter::IntoIterator, path::Path, str};

// Key Value Partition
// it's alternative to Column Family in rocksdb
pub trait KVPartition<K, V> {
    fn put(&self, key: K, value: V) -> bool;

    fn get(&self, key: K) -> Option<Vec<u8>>;

    fn del(&self, key: K) -> bool;

    fn close(&self) -> bool;
}

// Key Value persist storage
pub trait KVStorage {
    fn new<P, I, N>(path: P, family_columns: I) -> Self
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = N>,
        N: AsRef<str>;
}

// RocksDB is a KVStorage
pub struct RocksDB {
    connection: Arc<DB>,
}

// RocksDBColumnFamily is a KVPartition
pub struct RocksDBColumnFamily<'a> {
    connection: Arc<DB>,
    partition: &'a str,
}

impl<'a> RocksDBColumnFamily<'a> {
    fn cf(&'a self) -> Arc<BoundColumnFamily<'a>> {
        self.connection
            .cf_handle(self.partition)
            .expect("Unable to create column handler")
    }
}

impl<'a, K: AsRef<[u8]>, V: AsRef<[u8]>> KVPartition<K, V> for RocksDBColumnFamily<'a> {
    fn put(&self, key: K, value: V) -> bool {
        match self.connection.put_cf(&self.cf().clone(), key, value) {
            Ok(_) => true,
            _ => false,
        }
    }

    fn get(&self, key: K) -> Option<Vec<u8>> {
        match self.connection.get_cf(&self.cf().clone(), key) {
            Ok(v) => v,
            _ => None,
        }
    }

    fn del(&self, key: K) -> bool {
        match self.connection.delete_cf(&self.cf().clone(), key) {
            Ok(_) => true,
            _ => false,
        }
    }

    fn close(&self) -> bool {
        true
    }
}

impl KVStorage for RocksDB {
    fn new<P, I, N>(path: P, family_columns: I) -> Self
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = N>,
        N: AsRef<str>,
    {
        let mut db_opts = Options::default();
        db_opts.create_missing_column_families(true);
        db_opts.create_if_missing(true);
        db_opts.set_max_write_buffer_number(16);
        RocksDB {
            connection: Arc::new(
                DB::open_cf(&db_opts, path, family_columns).expect("Unable to open database"),
            ),
        }
    }
}

impl<'a> RocksDB {
    pub fn get_partition(&'a self, partition: &'a str) -> RocksDBColumnFamily<'a> {
        RocksDBColumnFamily {
            connection: self.connection.clone(),
            partition,
        }
    }
}

impl<K: AsRef<[u8]>, V: AsRef<[u8]>> KVPartition<K, V> for RocksDB {
    fn put(&self, key: K, value: V) -> bool {
        let conn = self.connection.clone();
        match conn.put(key, value) {
            Ok(_) => true,
            _ => false,
        }
    }

    fn get(&self, key: K) -> Option<Vec<u8>> {
        let conn = self.connection.clone();
        match conn.get(key) {
            Ok(v) => v,
            _ => None,
        }
    }

    fn del(&self, key: K) -> bool {
        let conn = self.connection.clone();
        match conn.delete(key) {
            Ok(_) => true,
            _ => false,
        }
    }

    fn close(&self) -> bool {
        true
    }
}
