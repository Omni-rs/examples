use near_sdk::near;
use omni_transaction::near::types::{Action, PublicKey, TransferAction};
use omni_transaction::transaction_builder::TransactionBuilder;
use omni_transaction::transaction_builder::TxBuilder;
use omni_transaction::types::NEAR;

#[near(contract_state)]
pub struct Contract {}

impl Default for Contract {
    fn default() -> Self {
        Self {}
    }
}

#[near]
impl Contract {
    pub fn get_transaction_encoded_data(&self) -> Vec<u8> {
        let signer_id = "alice.near";
        let signer_public_key = [0u8; 64];
        let nonce = 0;
        let receiver_id = "bob.near";
        let block_hash = [0u8; 32];
        let transfer_action = Action::Transfer(TransferAction { deposit: 1u128 });
        let actions = vec![transfer_action];

        let near_tx = TransactionBuilder::new::<NEAR>()
            .signer_id(signer_id.to_string())
            .signer_public_key(PublicKey::SECP256K1(signer_public_key.into()))
            .nonce(nonce)
            .receiver_id(receiver_id.to_string())
            .block_hash(block_hash)
            .actions(actions)
            .build();

        near_tx.build_for_signing()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_transaction_encoded_data() {
        let contract = Contract::default();

        let encoded_data = contract.get_transaction_encoded_data();

        let expected_data = vec![
            10, 0, 0, 0, 97, 108, 105, 99, 101, 46, 110, 101, 97, 114, 1, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 98, 111, 98, 46, 110, 101, 97, 114, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        assert!(encoded_data.len() > 0);
        assert_eq!(encoded_data, expected_data);
    }
}
