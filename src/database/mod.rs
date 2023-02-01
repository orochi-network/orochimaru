use crate::protos::storage::StorageKeyring;
use crate::storage::{StorageRandomness, StorageReceiver};
use ecvrf::helper::{generate_raw_keypair, random_bytes, recover_raw_keypair};
use kvdb::{KVPartition, RocksDB, RocksDBColumnFamily};
use protobuf::Message;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, sync::Arc};
use uuid::Uuid;

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn keyring_load(connection: Arc<RocksDB>) -> Result<StorageKeyring, protobuf::Error> {
    let db = connection.clone();
    let metadata = db.get_partition("metadata");
    match <RocksDBColumnFamily<'_> as KVPartition<&str, &str>>::get(&metadata, "keyring_active_key")
    {
        // If the record is exist then get take it
        Some(keyring_record_in_bytes) => StorageKeyring::parse_from_bytes(&keyring_record_in_bytes),
        // Otherwise we create a new one then take it
        None => {
            let keyring = db.get_partition("keyring");
            // Generate new key if the given key wasn't existed
            let new_keypair = match env::var("SECRET_KEY") {
                // Get secret from .env file
                Ok(r) => recover_raw_keypair(
                    hex::decode(r.trim())
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap(),
                ),
                // Generate new secret
                Err(_) => generate_raw_keypair(),
            };
            let mut keyring_record = StorageKeyring::new();
            // Random the HMAC key
            let mut buf = [0u8; 32];
            random_bytes(&mut buf);
            // Fill the record
            keyring_record.uuid = Uuid::new_v4().to_string();
            keyring_record.username = "hide_in_the_bush".to_string();
            keyring_record.hmac_secret = buf.to_vec();
            keyring_record.public_key = new_keypair.public_key.to_vec();
            keyring_record.secret_key = new_keypair.secret_key.to_vec();
            keyring_record.timestamp = current_timestamp();
            metadata.put("keyring_active_key", keyring_record.uuid.clone());
            keyring.put(
                keyring_record.uuid.clone(),
                keyring_record
                    .write_to_bytes()
                    .expect("Unable to serialized data"),
            );
            Ok(keyring_record.clone())
        }
    }
}

pub fn keyring_get(connection: Arc<RocksDB>) -> Result<StorageKeyring, protobuf::Error> {
    let db = connection.clone();
    let metadata = db.get_partition("metadata");
    let keyring_data =
        <RocksDBColumnFamily<'_> as KVPartition<&str, &str>>::get(&metadata, "keyring_active_key")
            .expect("Unable to get key from keyring");
    StorageKeyring::parse_from_bytes(&keyring_data)
}

pub fn receiver_increase_nonce(
    connection: Arc<RocksDB>,
    network: u64,
    address: &String,
) -> Result<StorageReceiver, protobuf::Error> {
    let db = connection.clone();
    let metadata = db.get_partition("receiver");
    match <RocksDBColumnFamily<'_> as KVPartition<&str, &str>>::get(
        &metadata,
        format!("receiver_of_{}_{}", network, address).as_str(),
    ) {
        Some(receiver_in_bytes) => match StorageReceiver::parse_from_bytes(&receiver_in_bytes) {
            Ok(mut receiver_record) => {
                receiver_record.nonce += 1;
                receiver_record.timestamp = current_timestamp();
                Ok(receiver_record.clone())
            }
            Err(e) => Err(e),
        },
        None => {
            let mut receiver_record = StorageReceiver::new();
            receiver_record.uuid = Uuid::new_v4().to_string();
            receiver_record.network = network;
            receiver_record.nonce = 0;
            receiver_record.address = address.clone();
            receiver_record.timestamp = current_timestamp();
            Ok(receiver_record.clone())
        }
    }
}

pub fn randomness_add_new_epoch(
    connection: Arc<RocksDB>,
    network: u64,
    address: &String,
    new_epoch: &mut StorageRandomness,
) -> Result<StorageRandomness, protobuf::Error> {
    let db = connection.clone();
    let randomness = db.get_partition("randomness");
    // Check for the existing of current epoch
    match <RocksDBColumnFamily<'_> as KVPartition<&str, &str>>::get(
        &randomness,
        format!("randomness_of_{}_{}", network, address).as_str(),
    ) {
        Some(epoch_in_bytes) => {
            // We need to add new epoch
            match StorageRandomness::parse_from_bytes(&epoch_in_bytes) {
                Ok(current_epoch) => {
                    receiver_increase_nonce(connection, network, address)
                        .expect("Unable to increase nonce");
                    new_epoch.uuid = Uuid::new_v4().to_string();
                    new_epoch.epoch = current_epoch.epoch + 1;
                    new_epoch.previous_uuid = current_epoch.uuid;
                    new_epoch.keyring_uuid = current_epoch.keyring_uuid;
                    new_epoch.receiver_uuid = current_epoch.receiver_uuid;
                    new_epoch.timestamp = current_timestamp();
                    let new_epoch_in_bytes = new_epoch
                        .write_to_bytes()
                        .expect("Unable to serialized new epoch");
                    randomness.put(new_epoch.uuid.clone(), &new_epoch_in_bytes);
                    randomness.put(
                        format!("randomness_of_{}_{}", network, address).as_str(),
                        &new_epoch_in_bytes,
                    );
                    Ok(new_epoch.clone())
                }
                Err(e) => Err(e),
            }
        }
        None => {
            let receiver_record = receiver_increase_nonce(connection, network, address)
                .expect("Unable to increase nonce");
            if new_epoch.keyring_uuid.is_empty() {
                panic!("Rick, something is wong!. I don't know Rick, you're better check the keyring uuid");
            }
            let mut new_epoch = StorageRandomness::new();
            new_epoch.uuid = Uuid::new_v4().to_string();
            new_epoch.epoch = 0;
            new_epoch.previous_uuid = "00000000-0000-0000-0000-000000000000".to_string();
            new_epoch.receiver_uuid = receiver_record.uuid;
            new_epoch.timestamp = current_timestamp();
            Ok(new_epoch.clone())
        }
    }
}
