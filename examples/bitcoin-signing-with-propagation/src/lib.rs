use near_sdk::serde::Serialize;
use near_sdk::{ext_contract, Promise};
use near_sdk::{near, Gas, NearToken};

use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::EcdsaSighashType;

const MPC_CONTRACT_ACCOUNT_ID: &str = "v1.signer-prod.testnet";
const ONE_YOCTO: NearToken = NearToken::from_yoctonear(100000000000000000000000);
const GAS: Gas = Gas::from_tgas(250);
const PATH: &str = "bitcoin-1";
const KEY_VERSION: u32 = 0;

#[derive(Debug, Serialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[allow(dead_code)]
#[ext_contract(mpc_contract)]
trait MPCContract {
    fn sign(&self, request: SignRequest);
}

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    pub fn generate_sighash_p2pkh(&self, bitcoin_tx: BitcoinTransaction) -> Vec<u8> {
        bitcoin_tx.build_for_signing_legacy(EcdsaSighashType::All)
    }

    pub fn sign_sighash_p2pkh(&self, sighash_p2pkh: String) -> Promise {
        // Decode the hex string back to bytes
        let payload_vec = hex::decode(sighash_p2pkh).expect("Invalid hex string");

        // Ensure the payload is exactly 32 bytes
        let payload: [u8; 32] = payload_vec
            .try_into()
            .expect("Payload must be 32 bytes long");

        let request: SignRequest = SignRequest {
            payload,
            path: PATH.to_string(),
            key_version: KEY_VERSION,
        };

        mpc_contract::ext(MPC_CONTRACT_ACCOUNT_ID.parse().unwrap())
            .with_static_gas(GAS)
            .with_attached_deposit(ONE_YOCTO)
            .sign(request)
    }
}

pub fn vec_to_fixed<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}
