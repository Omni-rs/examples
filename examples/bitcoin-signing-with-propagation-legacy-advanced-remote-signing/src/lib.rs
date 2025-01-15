use near_sdk::env::{self, sha256};
use near_sdk::Promise;
use near_sdk::{near, Gas, NearToken, PromiseError};

use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{EcdsaSighashType, ScriptBuf, TransactionType};
use omni_transaction::bitcoin::utils::{build_script_sig, serialize_ecdsa_signature_from_str};
use omni_transaction::signer::types::{mpc_contract, SignRequest, SignatureResponse};
pub mod external;

use external::this_contract;

const MPC_CONTRACT_ACCOUNT_ID: &str = "v1.signer-prod.testnet";
const GAS: Gas = Gas::from_tgas(50);
const PATH: &str = "bitcoin-1";
const KEY_VERSION: u32 = 0;
const CALLBACK_GAS: Gas = Gas::from_tgas(200);

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    pub fn create_sighash_and_sign_p2pkh(
        &self,
        bitcoin_tx: BitcoinTransaction,
        bitcoin_pubkey: Vec<u8>,
        attached_deposit: NearToken,
    ) -> Promise {
        // Build the encoded transaction for sighash
        let encoded_tx = bitcoin_tx.build_for_signing_legacy(EcdsaSighashType::All);

        // Hash the encoded transaction (sighash)
        let sighash = sha256(&sha256(&encoded_tx));

        // Ensure the payload is exactly 32 bytes
        let payload: [u8; 32] = sighash.try_into().expect("Payload must be 32 bytes long");

        let request: SignRequest = SignRequest {
            payload,
            path: PATH.to_string(),
            key_version: KEY_VERSION,
        };

        let promise = mpc_contract::ext(MPC_CONTRACT_ACCOUNT_ID.parse().unwrap())
            .with_static_gas(GAS)
            .with_attached_deposit(attached_deposit)
            .sign(request);

        promise.then(
            this_contract::ext(env::current_account_id())
                .with_static_gas(CALLBACK_GAS)
                .callback(bitcoin_tx, bitcoin_pubkey),
        )
    }

    #[private]
    pub fn callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        bitcoin_tx: BitcoinTransaction,
        bitcoin_pubkey: Vec<u8>,
    ) -> String {
        match call_result {
            Ok(signature_response) => {
                env::log_str(&format!(
                    "Successfully received signature: big_r = {:?}, s = {:?}, recovery_id = {}",
                    signature_response.big_r, signature_response.s, signature_response.recovery_id
                ));

                let signature = serialize_ecdsa_signature_from_str(
                    &signature_response.big_r.affine_point,
                    &signature_response.s.scalar,
                );

                let script_sig = build_script_sig(&signature, bitcoin_pubkey.as_slice());

                let mut bitcoin_tx = bitcoin_tx;

                // Update the transaction with the script_sig
                let updated_tx = bitcoin_tx.build_with_script_sig(
                    0,
                    ScriptBuf(script_sig),
                    TransactionType::P2PKH,
                );

                // Serialise the updated transaction
                hex::encode(updated_tx)
            }
            Err(error) => {
                env::log_str(&format!("Callback failed with error: {:?}", error));
                "Callback failed".to_string()
            }
        }
    }
}
