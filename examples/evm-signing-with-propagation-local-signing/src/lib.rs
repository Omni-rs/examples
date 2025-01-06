use near_sdk::{env, near};
use omni_transaction::evm::evm_transaction::EVMTransaction;

pub mod external;

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    pub fn hash_transaction(&self, evm_tx_params: EVMTransaction) -> [u8; 32] {
        let encoded_data = evm_tx_params.build_for_signing();

        let tx_hash = env::keccak256(&encoded_data);

        // Ensure the payload is exactly 32 bytes
        let payload: [u8; 32] = tx_hash.try_into().expect("Payload must be 32 bytes long");

        payload
    }
}
