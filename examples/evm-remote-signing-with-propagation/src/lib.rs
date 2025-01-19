use near_sdk::{env, near, Gas, NearToken, Promise, PromiseError};
use omni_transaction::evm::evm_transaction::EVMTransaction;
use omni_transaction::evm::types::Signature;
use omni_transaction::signer::types::{mpc_contract, SignRequest, SignatureResponse};

pub mod external;

use external::this_contract;

const MPC_CONTRACT_ACCOUNT_ID: &str = "v1.signer-prod.testnet";
const GAS: Gas = Gas::from_tgas(50);
const PATH: &str = "ethereum-1";
const KEY_VERSION: u32 = 0;
const CALLBACK_GAS: Gas = Gas::from_tgas(200);

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    pub fn hash_and_sign_transaction(
        &self,
        evm_tx_params: EVMTransaction,
        attached_deposit: NearToken,
    ) -> Promise {
        let encoded_data = evm_tx_params.build_for_signing();

        let tx_hash = env::keccak256(&encoded_data);

        // Ensure the payload is exactly 32 bytes
        let payload: [u8; 32] = tx_hash.try_into().expect("Payload must be 32 bytes long");

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
                .callback(evm_tx_params),
        )
    }

    #[private]
    pub fn callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        ethereum_tx: EVMTransaction,
    ) -> String {
        match call_result {
            Ok(signature_response) => {
                env::log_str(&format!(
                    "Successfully received signature: big_r = {:?}, s = {:?}, recovery_id = {}",
                    signature_response.big_r, signature_response.s, signature_response.recovery_id
                ));

                // Extract r and s from the signature response
                let affine_point_bytes = hex::decode(signature_response.big_r.affine_point)
                    .expect("Failed to decode affine_point to bytes");

                env::log_str(&format!(
                    "Decoded affine_point bytes (length: {}): {:?}",
                    affine_point_bytes.len(),
                    hex::encode(&affine_point_bytes)
                ));

                // Extract r from the affine_point_bytes
                let r_bytes = affine_point_bytes[1..33].to_vec();
                assert_eq!(r_bytes.len(), 32, "r must be 32 bytes");

                env::log_str(&format!(
                    "Extracted r (32 bytes): {:?}",
                    hex::encode(&r_bytes)
                ));

                let s_bytes = hex::decode(signature_response.s.scalar)
                    .expect("Failed to decode scalar to bytes");

                assert_eq!(s_bytes.len(), 32, "s must be 32 bytes");

                env::log_str(&format!(
                    "Decoded s (32 bytes): {:?}",
                    hex::encode(&s_bytes)
                ));

                // decode the address from the signature response

                // Calculate v
                let v = signature_response.recovery_id as u64;
                env::log_str(&format!("Calculated v: {}", v));

                let signature_omni = Signature {
                    v,
                    r: r_bytes,
                    s: s_bytes,
                };
                let omni_evm_tx_encoded_with_signature =
                    ethereum_tx.build_with_signature(&signature_omni);

                env::log_str(&format!(
                    "Successfully signed transaction: {:?}",
                    omni_evm_tx_encoded_with_signature
                ));

                // Serialise the updated transaction
                hex::encode(omni_evm_tx_encoded_with_signature)
            }
            Err(error) => {
                env::log_str(&format!("Callback failed with error: {:?}", error));
                "Callback failed".to_string()
            }
        }
    }
}
