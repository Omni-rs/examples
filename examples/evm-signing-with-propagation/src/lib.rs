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
    pub fn get_transaction_encoded_data(&self, evm_tx_params: EVMTransaction) -> Vec<u8> {
        evm_tx_params.build_for_signing()
    }

    pub fn get_transaction_hash(&self, evm_tx_params: EVMTransaction) -> Vec<u8> {
        let encoded_data = self.get_transaction_encoded_data(evm_tx_params);
        env::keccak256(&encoded_data)
    }

    // pub fn sign_transaction(&self, tx_hash: Vec<u8>, attached_deposit: NearToken) -> Promise {
    //     // Ensure the payload is exactly 32 bytes
    //     let payload: [u8; 32] = tx_hash
    //         .clone()
    //         .try_into()
    //         .expect("Payload must be 32 bytes long");

    //     let request: SignRequest = SignRequest {
    //         payload,
    //         path: PATH.to_string(),
    //         key_version: KEY_VERSION,
    //     };

    //     let promise = mpc_contract::ext(MPC_CONTRACT_ACCOUNT_ID.parse().unwrap())
    //         .with_static_gas(GAS)
    //         .with_attached_deposit(attached_deposit)
    //         .sign(request);

    //     promise.then(
    //         this_contract::ext(env::current_account_id())
    //             .with_static_gas(CALLBACK_GAS)
    //             .callback(tx_hash),
    //     )
    // }

    // #[private]
    // pub fn callback(
    //     &mut self,
    //     #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
    //     ethereum_tx: Vec<u8>,
    //     // TODO: Pasar todo typado
    //     // omni_evm_tx: EVMTransaction,
    // ) -> String {
    //     match call_result {
    //         Ok(signature_response) => {
    //             env::log_str(&format!(
    //                 "Successfully received signature: big_r = {:?}, s = {:?}, recovery_id = {}",
    //                 signature_response.big_r, signature_response.s, signature_response.recovery_id
    //             ));

    //             // TODO: Encodear la response bien
    //             let signature_omni: Signature = Signature {
    //                 v: signature.v().to_u64(),
    //                 r: signature.r().to_be_bytes::<32>().to_vec(),
    //                 s: signature.s().to_be_bytes::<32>().to_vec(),
    //             };

    //             let omni_evm_tx_encoded_with_signature =
    //                 ethereum_tx.build_with_signature(&signature_omni);

    //             // let signature = serialize_ecdsa_signature_from_str(
    //             //     &signature_response.big_r.affine_point,
    //             //     &signature_response.s.scalar,
    //             // );

    //             // let script_sig = build_script_sig(&signature, bitcoin_pubkey.as_slice());

    //             // let mut bitcoin_tx = bitcoin_tx;

    //             // // Update the transaction with the script_sig
    //             // let updated_tx = bitcoin_tx.build_with_script_sig(
    //             //     0,
    //             //     ScriptBuf(script_sig),
    //             //     TransactionType::P2PKH,
    //             // );

    //             // Serialise the updated transaction
    //             // hex::encode(updated_tx)
    //             "".to_string()
    //         }
    //         Err(error) => {
    //             env::log_str(&format!("Callback failed with error: {:?}", error));
    //             "Callback failed".to_string()
    //         }
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_transaction::evm::evm_transaction::EVMTransaction;
    use omni_transaction::evm::utils::parse_eth_address;

    #[test]
    fn test_get_transaction_encoded_when_passing_tx() {
        let contract = Contract::default();

        let to_address_str = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let to_address = parse_eth_address(to_address_str);
        let max_fee_per_gas: u128 = 20_000_000_000;
        let max_priority_fee_per_gas: u128 = 1_000_000_000;
        let gas_limit: u128 = 21_000;
        let chain_id: u64 = 1;
        let nonce: u64 = 0;
        let input: Vec<u8> = vec![];
        let value: u128 = 10000000000000000; // 0.01 ETH

        let tx = EVMTransaction {
            nonce,
            to: Some(to_address),
            value,
            input,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            chain_id,
            access_list: vec![],
        };

        let encoded_data = contract.get_transaction_encoded_data(tx);

        let expected_data = vec![
            2, 239, 1, 128, 132, 59, 154, 202, 0, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 216,
            218, 107, 242, 105, 100, 175, 157, 126, 237, 158, 3, 229, 52, 21, 211, 122, 169, 96,
            69, 135, 35, 134, 242, 111, 193, 0, 0, 128, 192,
        ];

        assert!(!encoded_data.is_empty());
        assert_eq!(encoded_data, expected_data);
    }
}
