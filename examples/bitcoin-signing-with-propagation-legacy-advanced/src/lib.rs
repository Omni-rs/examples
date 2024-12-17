use near_sdk::env::{self, sha256};
use near_sdk::Promise;
use near_sdk::{near, Gas, NearToken, PromiseError};

use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{EcdsaSighashType, ScriptBuf, TransactionType};

pub mod external;
pub mod signature;
pub mod types;

use external::{mpc_contract, this_contract};
use types::{SignRequest, SignatureResponse};

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

                // 🔥 Extrae r y s desde los campos de SignatureResponse
                let big_r_bytes = hex::decode(signature_response.big_r.affine_point)
                    .expect("Error al decodificar Big R en formato hexadecimal");
                let s_bytes = hex::decode(signature_response.s.scalar)
                    .expect("Error al decodificar S en formato hexadecimal");

                // Construye la firma completa (64 bytes) combinando r (32) y s (32)
                let mut signature_bytes = vec![];
                signature_bytes.extend_from_slice(&big_r_bytes[1..]); // Remove first byte (indicator)
                signature_bytes.extend_from_slice(&s_bytes);

                // Function 1: encode_signature_as_der
                // Function 2: build_script_sig

                // 🚀 Construye el script sig
                let script_sig = signature::build_script_sig(&signature_bytes, &bitcoin_pubkey);
                env::log_str(&format!("ScriptSig: {:?}", script_sig));

                let mut bitcoin_tx = bitcoin_tx;

                // 🔧 Actualiza la transacción con el script_sig
                let updated_tx = bitcoin_tx.build_with_script_sig(
                    0,
                    ScriptBuf(script_sig),
                    TransactionType::P2PKH,
                );
                env::log_str(&format!(
                    "Bitcoin transaction after script_sig: {:?}",
                    updated_tx
                ));

                // 🚀 Serializar la transacción completa a hexadecimal
                let raw_hex_tx = hex::encode(updated_tx);

                env::log_str(&format!(
                    "Updated Bitcoin transaction as HEX: {}",
                    raw_hex_tx
                ));

                // Devolver la transacción en formato hexadecimal
                raw_hex_tx
            }
            Err(error) => {
                env::log_str(&format!("Callback failed with error: {:?}", error));
                "Callback failed".to_string()
            }
        }
    }
}
