// use crate::common::sign::TxSignature;
// use crate::exchange::signature_message::ExchangeTransfer;
// use crate::exchange::OrderBase;
// use crate::output::program_output::PerpetualOutput;
// use crate::perpetual::definitions::general_config::GeneralConfig;
// use crate::perpetual::definitions::PerpError;
// use crate::perpetual::order::validate_order_and_update_fulfillment;
// use crate::position::update_position::update_position_in_dict;
// use crate::state::CarriedState;
// use crate::transactions::block_config::BlockConfig;
// use crate::Engine;
// use franklin_crypto::eddsa::PrivateKey;
// use num_bigint::BigInt;
// use num_traits::Zero;
// use serde::{Deserialize, Serialize};
// use std::ops::Neg;
// use types::common::defined_types::{AssetIdType, PositionId};
// use types::common::defined_types::{HashType, SignatureType};
// use types::common::packed_public_key::PublicKeyType;
// use types::common::params::{AMOUNT_UPPER_BOUND, NO_SYNTHETIC_DELTA_ASSET_ID};
// use utils::{BigIntSerdeAsRadix10String, BigIntSerdeAsRadix16Prefix0xString, U64SerdeAsString};
// use zksync_crypto::{franklin_crypto::eddsa::PrivateKey, Engine};
//
// #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub struct Transfer {
//     #[serde(flatten)]
//     pub base: OrderBase,
//     #[serde(rename = "sender_position_id", with = "U64SerdeAsString")]
//     pub sender_position_id: PositionId,
//     #[serde(rename = "receiver_public_key")]
//     pub receiver_public_key: PublicKeyType,
//     #[serde(rename = "receiver_position_id", with = "U64SerdeAsString")]
//     pub receiver_position_id: PositionId,
//     #[serde(rename = "amount", with = "BigIntSerdeAsRadix10String")]
//     pub amount: BigInt,
//     #[serde(rename = "asset_id", with = "BigIntSerdeAsRadix16Prefix0xString")]
//     pub asset_id: AssetIdType,
// }
//
// impl Transfer {
//     pub fn sign(&self, pk: &PrivateKey<Engine>) -> Self {
//         let message_hash = transfer_hash(&self, 0);
//         let sign_info = TxSignature::sign_musig(pk, message_hash.as_bytes());
//
//         Self {
//             base: OrderBase {
//                 nonce: self.base.nonce,
//                 public_key: PublicKeyType(sign_info.pub_key.0),
//                 expiration_timestamp: self.base.expiration_timestamp,
//                 signature: SignatureType(sign_info.signature),
//             },
//             sender_position_id: self.sender_position_id,
//             receiver_public_key: self.receiver_public_key.clone(),
//             receiver_position_id: self.receiver_position_id,
//             amount: self.amount.clone(),
//             asset_id: self.asset_id.clone(),
//         }
//     }
// }
//
// pub fn transfer_hash(transfer: &Transfer, condition: u64) -> HashType {
//     let mut exchange_transfer = ExchangeTransfer::default();
//     exchange_transfer.base = transfer.base.clone();
//     exchange_transfer.sender_vault_id = transfer.sender_position_id.clone();
//     exchange_transfer.receiver_public_key = transfer.receiver_public_key.clone();
//     exchange_transfer.receiver_vault_id = transfer.receiver_position_id.clone();
//     exchange_transfer.amount = transfer.amount.clone();
//     exchange_transfer.asset_id = transfer.asset_id.clone();
//     exchange_transfer.src_fee_vault_id = transfer.sender_position_id.clone();
//     exchange_transfer.asset_id_fee = BigInt::zero();
//     exchange_transfer.max_amount_fee = BigInt::zero();
//
//     return ExchangeTransfer::hash(exchange_transfer, condition);
// }
//
// pub fn execute_transfer(
//     carried_state: &mut CarriedState,
//     block_config: &BlockConfig,
//     tx: &Transfer,
// ) -> Result<PerpetualOutput, PerpError> {
//     if tx.sender_position_id == tx.receiver_position_id {
//         return Err(PerpError::SamePositionID);
//     }
//     if !(BigInt::zero() <= tx.amount && tx.amount <= AMOUNT_UPPER_BOUND.clone() - 1) {
//         return Err(PerpError::OutOfRangeAmount);
//     }
//     let general_config: &GeneralConfig = &block_config.general_config;
//     if tx.asset_id != general_config.collateral_asset_info.asset_id {
//         return Err(PerpError::InvalidCollateralAssetID);
//     }
//
//     let message_hash: HashType = transfer_hash(tx, 0);
//     validate_order_and_update_fulfillment(
//         &mut carried_state.orders_dict,
//         &message_hash,
//         &tx.base,
//         &block_config.min_expiration_timestamp,
//         tx.amount.clone(),
//         tx.amount.clone(),
//     )?;
//
//     // Update the sender's position.
//     update_position_in_dict(
//         &mut carried_state.positions_dict,
//         &tx.sender_position_id,
//         &tx.base.public_key,
//         tx.amount.clone().neg(),
//         &NO_SYNTHETIC_DELTA_ASSET_ID,
//         BigInt::zero(),
//         &carried_state.global_funding_indices,
//         &carried_state.oracle_prices,
//         general_config,
//     )?;
//
//     // Update the receiver's position.
//     update_position_in_dict(
//         &mut carried_state.positions_dict,
//         &tx.receiver_position_id,
//         &tx.receiver_public_key,
//         tx.amount.clone(),
//         &NO_SYNTHETIC_DELTA_ASSET_ID,
//         BigInt::zero(),
//         &carried_state.global_funding_indices,
//         &carried_state.oracle_prices,
//         general_config,
//     )?;
//     Ok(PerpetualOutput::empty())
// }
