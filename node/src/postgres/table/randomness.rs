use std::sync::Arc;

use crate::{
    ethereum::{compose_operator_proof, ecvrf_proof_digest, sign_ethereum_message},
    evm::evm_verify,
    randomness::{ActiveModel, Column, Entity, Model},
    receiver, NodeContext,
};
use libecvrf::{
    extends::{AffineExtend, ScalarExtend},
    secp256k1::curve::Scalar,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait,
    Order, QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use serde_json::json;
use uuid::Uuid;

use super::ReceiverTable;

/// Randomness table
pub struct RandomnessTable<'a> {
    /// Database connection
    pub connection: &'a DatabaseConnection,
}

/// Randomness related columns
impl<'a> RandomnessTable<'a> {
    /// Create new instance of randomness
    pub fn new(connection: &'a DatabaseConnection) -> Self {
        Self { connection }
    }

    /// Find randomness record by its network and address
    pub async fn find_recent_epoch(
        &self,
        network: i64,
        address: &str,
    ) -> Result<Vec<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .find_one(network, address)
            .await
            .expect("Unable to query receiver from database");
        match receiver {
            Some(receiver_record) => {
                Entity::find()
                    .filter(Condition::all().add(Column::ReceiverId.eq(receiver_record.id)))
                    // 20 is the limit of number of records
                    .limit(20)
                    .order_by(Column::Epoch, Order::Desc)
                    .all(self.connection)
                    .await
            }
            None => Ok(vec![]),
        }
    }

    /// Find randomness record by its network and address
    pub async fn find_closure_epoch(
        &self,
        network: i64,
        address: &str,
        epoch: i64,
    ) -> Result<Vec<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .find_one(network, address)
            .await
            .expect("Unable to query receiver from database");
        match receiver {
            Some(receiver_record) => {
                Entity::find()
                    .filter(
                        Condition::all()
                            .add(Column::ReceiverId.eq(receiver_record.id))
                            .add(Column::Epoch.lte(epoch)),
                    )
                    // 20 is the limit of number of records
                    .limit(20)
                    .order_by(Column::Epoch, Order::Desc)
                    .all(self.connection)
                    .await
            }
            None => Ok(vec![]),
        }
    }

    /// Find randomness record by its network and address
    pub async fn find_latest_epoch(
        &self,
        network: i64,
        address: &str,
    ) -> Result<Option<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .find_one(network, address)
            .await
            .expect("Unable to query receiver from database");
        match receiver {
            Some(receiver_record) => {
                Entity::find()
                    .filter(Column::ReceiverId.eq(receiver_record.id))
                    .order_by(Column::Epoch, Order::Desc)
                    .one(self.connection)
                    .await
            }
            None => Ok(None),
        }
    }

    /// Find randomness record by its network, address and epoch_id
    pub async fn find_given_epoch(
        &self,
        network: i64,
        address: &str,
        epoch_id: i64,
    ) -> Result<Option<Model>, DbErr> {
        let receiver = ReceiverTable::new(self.connection)
            .find_one(network, address)
            .await
            .expect("Unable to query receiver from database");
        match receiver {
            Some(receiver_record) => {
                Entity::find()
                    .filter(
                        Condition::all()
                            .add(Column::ReceiverId.eq(receiver_record.id))
                            .add(Column::Epoch.eq(epoch_id)),
                    )
                    .order_by(Column::Epoch, Order::Desc)
                    .one(self.connection)
                    .await
            }
            None => Ok(None),
        }
    }

    /// Find randomness record by its network and address
    pub async fn safe_insert(
        &self,
        context: Arc<NodeContext>,
        network: i64,
        address: String,
    ) -> Result<Model, DbErr> {
        let _lock = context.sync.lock().await;
        let ecvrf = context.ecvrf();
        let txn = self.connection.begin().await?;

        // Lookup the receiver record by address and network from database
        let receiver_record = match receiver::Entity::find()
            .filter(
                Condition::all()
                    .add(receiver::Column::Address.eq(address.to_owned()))
                    .add(receiver::Column::Network.eq(network)),
            )
            .one(&txn)
            .await
        {
            Ok(option_receiver) => match option_receiver {
                Some(model_receiver) => model_receiver,
                None => {
                    // Insert new receiver record if we're on testnet
                    if context.is_testnet() {
                        match receiver::ActiveModel::from_json(json!({
                            "name": Uuid::new_v4(),
                            "network": network,
                            "address": address.clone(),
                            "nonce": 0
                        })) {
                            Ok(active_model) => {
                                match receiver::Entity::insert(active_model)
                                    .exec_with_returning(&txn)
                                    .await
                                {
                                    Ok(receiver_model) => receiver_model,
                                    Err(e) => return Err(e),
                                }
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        return Err(DbErr::RecordNotFound(
                            "Receiver record not found".to_string(),
                        ));
                    }
                }
            },
            Err(e) => return Err(e),
        };

        // Read alpha from latest epoch
        let alpha = match Entity::find()
            .filter(Column::ReceiverId.eq(receiver_record.id))
            .order_by(Column::Epoch, Order::Desc)
            .one(&txn)
            .await
        {
            Ok(randomness_exec_result) => match randomness_exec_result {
                Some(latest_epoch) => {
                    let mut buf = [0u8; 32];
                    hex::decode_to_slice(latest_epoch.y, &mut buf)
                        .expect("Unable to decode previous result");

                    Scalar::from_bytes(&buf)
                }
                None => Scalar::randomize(),
            },
            Err(e) => return Err(e),
        };

        let contract_proof = match ecvrf.prove_contract(&alpha) {
            Ok(r) => r,
            Err(_) => {
                return Err(DbErr::Exec(sea_orm::RuntimeErr::Internal(
                    "Unable to prove contract".to_string(),
                )))
            }
        };

        if !evm_verify(&contract_proof) {
            return Err(DbErr::Exec(sea_orm::RuntimeErr::Internal(
                "EVM unable to verify".to_string(),
            )));
        }

        let receiver_nonce = receiver_record.nonce;
        let mut bytes_address = [0u8; 20];
        hex::decode_to_slice(
            address.replace("0x", "").replace("0X", ""),
            &mut bytes_address,
        )
        .expect("Unable to decode address");

        let raw_proof = compose_operator_proof(
            receiver_nonce,
            &bytes_address,
            &ecvrf_proof_digest(&contract_proof),
        );
        let ecdsa_proof = sign_ethereum_message(&context.keypair().secret_key, &raw_proof);

        // Construct active model from JSON
        let new_randomness_record = match ActiveModel::from_json(json!({
            "keyring_id": context.key_id(),
            "receiver_id": receiver_record.id,
            "epoch": receiver_record.nonce,
            "alpha":hex::encode(alpha
                .b32()),
            "gamma": contract_proof.gamma.to_hex_string(),
            "c":hex::encode(contract_proof.c.b32()),
            "s":hex::encode(contract_proof.s.b32()),
            "y":hex::encode(contract_proof.y.b32()),
            "witness_address": hex::encode(contract_proof.witness_address.b32())[0..40],
            "witness_gamma": contract_proof.witness_gamma.to_hex_string(),
            "witness_hash": contract_proof.witness_hash.to_hex_string(),
            "inverse_z": hex::encode(contract_proof.inverse_z.b32()),
            "signature_proof": hex::encode(&ecdsa_proof),
        })) {
            Ok(rr) => rr,
            Err(e) => return Err(e),
        };

        let mut receiver_active_model = receiver::ActiveModel::from(receiver_record);
        receiver_active_model.nonce = ActiveValue::Set(receiver_nonce + 1);
        // Update database receiver record
        receiver_active_model.save(&txn).await?;

        let result = Entity::insert(new_randomness_record)
            .exec_with_returning(&txn)
            .await;

        match txn.commit().await {
            Ok(_) => result,
            Err(e) => Err(e),
        }
    }

    /// Find randomness record by its network and address
    pub async fn update(&self, active_model: ActiveModel) -> Result<Model, DbErr> {
        active_model.update(self.connection).await
    }
}
