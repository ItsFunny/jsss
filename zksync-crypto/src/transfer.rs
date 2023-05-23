// use crate::{privkey_to_pubkey_internal, Fr};
// use franklin_crypto::bellman::bn256::Bn256;
// use franklin_crypto::bellman::{Field, PrimeField};
// use franklin_crypto::eddsa::PublicKey;
// use num::{BigInt, Zero};
// use num_bigint::BigInt;
// use std::str::FromStr;
// use wasm_bindgen::JsValue;
//
// pub struct TransferRequest {
//     pub asset_id: BigInt,
//     pub asset_id_fee: BigInt,
//     pub receiver_public_key: String,
//     pub sender_vault_id: i64,
//     pub receiver_vault_id: i64,
// }
//
// impl TransferRequest {}
//
// pub fn sign_transfer(
//     transfer: TransferRequest,
//     private_key: &[u8],
//     condition: i64,
// ) -> Result<Vec<u8>, JsValue> {
//     let pubkey = privkey_to_pubkey_internal(private_key)?;
//     let msg = rescue_hash_two_element(
//         fr_from_bigint(&transfer.asset_id),
//         fr_from_bigint(&transfer.asset_id_fee),
//     );
//     let msg = if condition != 0 {
//         rescue_hash_two_element(msg, fr_from_bigint(&BigInt::from(condition)))
//     } else {
//         rescue_hash_two_element(msg, pub_key_to_fr(&pubkey))
//     };
//     todo!()
// }
//
// fn pub_key_to_fr(pubkey: &PublicKey<Bn256>) -> Fr {
//     let (x, y) = pubkey.0.into_xy();
//     return rescue_hash_two_element(x, y);
// }
//
// pub fn rescue_hash_two_element(a: Fr, b: Fr) -> Fr {
//     let hasher = &zksync_crypto::params::RESCUE_HASHER as &BabyRescueHasher;
//     return hasher.hash_elements([a, b]);
// }
//
// pub fn fr_from_bigint(num: &BigInt) -> Fr {
//     if num > &BigInt::zero() {
//         Fr::from_str(&num.to_string()).unwrap()
//     } else {
//         let mut num = Fr::from_str(&(-num).to_string()).unwrap();
//         num.negate();
//         num
//     }
// }
