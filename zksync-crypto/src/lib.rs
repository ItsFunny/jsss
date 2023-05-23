//! Utils for signing zksync transactions.
//! This crate is compiled into wasm to be used in `zksync.js`.
mod models;
mod transfer;
mod utils;

const PACKED_POINT_SIZE: usize = 32;
const PACKED_SIGNATURE_SIZE: usize = 64;

pub use franklin_crypto::bellman::pairing::bn256::{Bn256 as Engine, Fr};
use franklin_crypto::rescue::bn256::Bn256RescueParams;
use serde::{Deserialize, Serialize};

pub type Fs = <Engine as JubjubEngine>::Fs;

thread_local! {
    pub static JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
    pub static RESCUE_PARAMS: Bn256RescueParams = Bn256RescueParams::new_checked_2_into_1();
}

use wasm_bindgen::prelude::*;

use franklin_crypto::{
    alt_babyjubjub::{edwards, fs::FsRepr, AltJubjubBn256, FixedGenerators},
    bellman::pairing::ff::{PrimeField, PrimeFieldRepr},
    eddsa::{PrivateKey, PublicKey, Seed, Signature as EddsaSignature},
    jubjub::JubjubEngine,
};
use num_bigint::BigInt;

pub type Signature = EddsaSignature<Engine>;

use crate::utils::set_panic_hook;
use sha2::{Digest, Sha256};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(start)]
/// This method initializes params for current thread, otherwise they will be initialized when signing
/// first message.
pub fn zksync_crypto_init() {
    JUBJUB_PARAMS.with(|_| {});
    RESCUE_PARAMS.with(|_| {});
    set_panic_hook();
}

#[wasm_bindgen(js_name = privateKeyFromSeed)]
pub fn private_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    if seed.len() < 32 {
        return Err(JsValue::from_str("Seed is too short"));
    };

    let sha256_bytes = |input: &[u8]| -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(input);
        hasher.result().to_vec()
    };

    let mut effective_seed = sha256_bytes(seed);

    loop {
        let raw_priv_key = sha256_bytes(&effective_seed);
        let mut fs_repr = FsRepr::default();
        fs_repr
            .read_be(&raw_priv_key[..])
            .expect("failed to read raw_priv_key");
        if Fs::from_repr(fs_repr).is_ok() {
            return Ok(raw_priv_key);
        } else {
            effective_seed = raw_priv_key;
        }
    }
}

fn read_signing_key(private_key: &[u8]) -> Result<PrivateKey<Engine>, JsValue> {
    let mut fs_repr = FsRepr::default();
    fs_repr
        .read_be(private_key)
        .map_err(|_| JsValue::from_str("couldn't read private key repr"))?;
    Ok(PrivateKey::<Engine>(
        Fs::from_repr(fs_repr).expect("couldn't read private key from repr"),
    ))
}

fn privkey_to_pubkey_internal(private_key: &[u8]) -> Result<PublicKey<Engine>, JsValue> {
    let p_g = FixedGenerators::SpendingKeyGenerator;

    let sk = read_signing_key(private_key)?;

    Ok(JUBJUB_PARAMS.with(|params| PublicKey::from_private(&sk, p_g, params)))
}

#[wasm_bindgen(js_name = pubKeyHash)]
pub fn pub_key_hash(pubkey: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pubkey = JUBJUB_PARAMS
        .with(|params| PublicKey::read(pubkey, params))
        .map_err(|_| JsValue::from_str("couldn't read public key"))?;
    Ok(utils::pub_key_hash(&pubkey))
}

#[wasm_bindgen]
pub fn private_key_to_pubkey_hash(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(utils::pub_key_hash(&privkey_to_pubkey_internal(
        private_key,
    )?))
}

#[derive(Debug, Deserialize, Serialize)]
struct A {
    field1: String,
    field2: u64,
}

#[wasm_bindgen]
pub fn printA(jsonBytes: &str) -> u64 {
    let a: A = serde_json::from_str(jsonBytes).unwrap();
    a.field2 + a.field2 + a.field2
}

#[wasm_bindgen]
pub fn private_key_to_pubkey(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut pubkey_buf = Vec::with_capacity(PACKED_POINT_SIZE);

    let pubkey = privkey_to_pubkey_internal(private_key)?;
    pubkey
        .write(&mut pubkey_buf)
        .expect("failed to write pubkey to buffer");

    Ok(pubkey_buf)
}
#[wasm_bindgen]
pub fn private_key_to_pubkey_with_xy(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut pubkey_buf = Vec::with_capacity(PACKED_POINT_SIZE + PACKED_POINT_SIZE);
    let pubkey = privkey_to_pubkey_internal(private_key)?;
    let (a, b) = pubkey.0.into_xy();
    a.into_repr()
        .write_be(&mut pubkey_buf)
        .expect("failed to write a to buffer");
    b.into_repr()
        .write_be(&mut pubkey_buf)
        .expect("failed to write b to buffer");
    Ok(pubkey_buf)
}

// pub fn sign_transfer(json: String, private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
//     let transfer: Transfer =
//         serde_json::from_str(json.as_str()).map_err(|_| JsValue::from_str("json parse error"))?;
//
//     let private_key: PrivateKey<Engine> = read_signing_key(private_key)?;
//
//     let transfer = transfer.sign(&private_key);
//
//     let signature = transfer.base.signature;
//
//     Ok(signature
//         .serialize_packed()
//         .map_err(|_| JsValue::from_str("serialize error"))?)
// }

// pub fn sign_withdraw(json: String, asset_id: i64, private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
//     let data: Withdrawal =
//         serde_json::from_str(json.as_str()).map_err(|_| JsValue::from_str("json parse error"))?;
//     let asset_id = BigInt::from(asset_id);
//
//     let private_key: PrivateKey<Engine> = read_signing_key(private_key)?;
//
//     let data = data.sign(&private_key, asset_id);
//
//     let signature = data.base.signature;
//
//     Ok(signature
//         .serialize_packed()
//         .map_err(|_| JsValue::from_str("serialize error"))?)
// }

// pub fn sign_exchange_limit_order(
//     json: String,
//     asset_id: i64,
//     private_key: &[u8],
// ) -> Result<Vec<u8>, JsValue> {
//     let data: ExchangeLimitOrder =
//         serde_json::from_str(json.as_str()).map_err(|_| JsValue::from_str("json parse error"))?;
//     let asset_id = BigInt::from(asset_id);
//
//     let private_key: PrivateKey<Engine> = read_signing_key(private_key)?;
//
//     // let data = data.sign(&private_key, asset_id);
//
//     let signature = data.base.signature;
//
//     Ok(signature
//         .serialize_packed()
//         .map_err(|_| JsValue::from_str("serialize error"))?)
// }

#[wasm_bindgen(js_name = "rescueHash")]
pub fn rescue_hash_tx_msg(msg: &[u8]) -> Vec<u8> {
    utils::rescue_hash_tx_msg(msg)
}

/// `msg` should be represented by 2 concatenated
/// serialized orders of the swap transaction
#[wasm_bindgen(js_name = "rescueHashOrders")]
pub fn rescue_hash_orders(msg: &[u8]) -> Vec<u8> {
    utils::rescue_hash_orders(msg)
}

#[wasm_bindgen]
/// We use musig Schnorr signature scheme.
/// It is impossible to restore signer for signature, that is why we provide public key of the signer
/// along with signature.
/// [0..32] - packed public key of signer.
/// [32..64] - packed r point of the signature.
/// [64..96] - s poing of the signature.
pub fn sign_musig_without_hash_msg(private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut packed_full_signature = Vec::with_capacity(PACKED_POINT_SIZE + PACKED_SIGNATURE_SIZE);
    let p_g = FixedGenerators::SpendingKeyGenerator;
    let private_key = read_signing_key(private_key)?;

    {
        let public_key =
            JUBJUB_PARAMS.with(|params| PublicKey::from_private(&private_key, p_g, params));
        public_key
            .write(&mut packed_full_signature)
            .expect("failed to write pubkey to packed_point");
    };

    let signature = JUBJUB_PARAMS.with(|jubjub_params| {
        RESCUE_PARAMS.with(|rescue_params| {
            let seed = Seed::deterministic_seed(&private_key, &msg);
            private_key.musig_rescue_sign(&msg, &seed, p_g, rescue_params, jubjub_params)
        })
    });

    signature
        .r
        .write(&mut packed_full_signature)
        .expect("failed to write signature");
    signature
        .s
        .into_repr()
        .write_le(&mut packed_full_signature)
        .expect("failed to write signature repr");

    assert_eq!(
        packed_full_signature.len(),
        PACKED_POINT_SIZE + PACKED_SIGNATURE_SIZE,
        "incorrect signature size when signing"
    );

    Ok(packed_full_signature)
}

#[wasm_bindgen]
/// We use musig Schnorr signature scheme.
/// It is impossible to restore signer for signature, that is why we provide public key of the signer
/// along with signature.
/// [0..32] - packed public key of signer.
/// [32..64] - packed r point of the signature.
/// [64..96] - s poing of the signature.
pub fn sign_musig(private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut packed_full_signature = Vec::with_capacity(PACKED_POINT_SIZE + PACKED_SIGNATURE_SIZE);
    let p_g = FixedGenerators::SpendingKeyGenerator;
    let private_key = read_signing_key(private_key)?;

    {
        let public_key =
            JUBJUB_PARAMS.with(|params| PublicKey::from_private(&private_key, p_g, params));
        public_key
            .write(&mut packed_full_signature)
            .expect("failed to write pubkey to packed_point");
    };

    let signature = JUBJUB_PARAMS.with(|jubjub_params| {
        RESCUE_PARAMS.with(|rescue_params| {
            let hashed_msg = utils::rescue_hash_tx_msg(msg);
            let seed = Seed::deterministic_seed(&private_key, &hashed_msg);
            private_key.musig_rescue_sign(&hashed_msg, &seed, p_g, rescue_params, jubjub_params)
        })
    });

    signature
        .r
        .write(&mut packed_full_signature)
        .expect("failed to write signature");
    signature
        .s
        .into_repr()
        .write_le(&mut packed_full_signature)
        .expect("failed to write signature repr");

    assert_eq!(
        packed_full_signature.len(),
        PACKED_POINT_SIZE + PACKED_SIGNATURE_SIZE,
        "incorrect signature size when signing"
    );

    Ok(packed_full_signature)
}

#[wasm_bindgen]
pub fn verify_musig(msg: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    if signature.len() != PACKED_POINT_SIZE + PACKED_SIGNATURE_SIZE {
        return Err(JsValue::from_str("Signature length is not 96 bytes. Make sure it contains both the public key and the signature itself."));
    }

    let pubkey = &signature[..PACKED_POINT_SIZE];
    let pubkey = JUBJUB_PARAMS
        .with(|params| edwards::Point::read(&*pubkey, params).map(PublicKey))
        .map_err(|_| JsValue::from_str("couldn't read public key"))?;

    let signature = deserialize_signature(&signature[PACKED_POINT_SIZE..])?;

    let msg = utils::rescue_hash_tx_msg(msg);
    let value = JUBJUB_PARAMS.with(|jubjub_params| {
        RESCUE_PARAMS.with(|rescue_params| {
            pubkey.verify_musig_rescue(
                &msg,
                &signature,
                FixedGenerators::SpendingKeyGenerator,
                rescue_params,
                jubjub_params,
            )
        })
    });

    Ok(value)
}

fn deserialize_signature(bytes: &[u8]) -> Result<Signature, JsValue> {
    let (r_bar, s_bar) = bytes.split_at(PACKED_POINT_SIZE);

    let r = JUBJUB_PARAMS
        .with(|params| edwards::Point::read(r_bar, params))
        .map_err(|_| JsValue::from_str("Failed to parse signature"))?;

    let mut s_repr = FsRepr::default();
    s_repr
        .read_le(s_bar)
        .map_err(|_| JsValue::from_str("Failed to parse signature"))?;

    let s = <Engine as JubjubEngine>::Fs::from_repr(s_repr)
        .map_err(|_| JsValue::from_str("Failed to parse signature"))?;

    Ok(Signature { r, s })
}

#[test]
pub fn asd() {}
