use near_sdk::serde::Serialize;
use near_sdk::{ext_contract, Promise};
use near_sdk::{near, Gas, NearToken};

use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::EcdsaSighashType;
use omni_transaction::bitcoin::types::ScriptBuf;

const MPC_CONTRACT_ACCOUNT_ID: &str = "v1.signer-prod.testnet";
const GAS: Gas = Gas::from_tgas(50);
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
    fn experimental_signature_deposit(&self) -> NearToken;
}

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    pub fn generate_sighash_p2wpkh(
        &self,
        bitcoin_tx: BitcoinTransaction,
        input_index: usize,
        script_code: &ScriptBuf,
        value: u64,
    ) -> Vec<u8> {
        bitcoin_tx.build_for_signing_segwit(EcdsaSighashType::All, input_index, script_code, value)
    }

    pub fn sign_sighash_p2wpkh(
        &self,
        sighash_p2wpkh: String,
        attached_deposit: NearToken,
    ) -> Promise {
        // Decode the hex string back to bytes
        let payload_vec = hex::decode(sighash_p2wpkh).expect("Invalid hex string");

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
            .with_attached_deposit(attached_deposit)
            .sign(request)
    }
}
