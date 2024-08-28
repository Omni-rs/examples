use near_sdk::near;
use omni_transaction::near::near_transaction::NearTransaction;

#[near(contract_state)]
pub struct Contract {}

impl Default for Contract {
    fn default() -> Self {
        Self {}
    }
}

#[near]
impl Contract {
    pub fn get_transaction_encoded_data(&self, near_tx_params: NearTransaction) -> Vec<u8> {
        near_tx_params.build_for_signing()
    }
}

#[cfg(test)]
mod tests {
    use omni_transaction::{
        near::types::{
            AccessKey, AccessKeyPermission, Action, AddKeyAction, ED25519PublicKey, PublicKey,
            TransferAction,
        },
        transaction_builder::{TransactionBuilder, TxBuilder},
        types::NEAR,
    };

    use super::*;

    #[test]
    fn test_get_transaction_encoded_data() {
        let contract = Contract::default();

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

        let encoded_data = contract.get_transaction_encoded_data(near_tx);

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

    #[test]
    fn test_get_transaction_encoded_data_2() {
        let contract = Contract::default();

        let signer_id = "forgetful-parent.testnet";
        let signer_public_key = "6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"; // ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp
        let signer_public_key_as_bytes: [u8; 32] = bs58::decode(signer_public_key)
            .into_vec()
            .expect("Decoding failed")
            .try_into()
            .expect("Invalid length, expected 32 bytes");

        let nonce = 1;
        let receiver_id = "forgetful-parent.testnet";
        let block_hash = "4reLvkAWfqk5fsqio1KLudk46cqRz9erQdaHkWZKMJDZ";
        let block_hash_as_bytes = bs58::decode(block_hash)
            .into_vec()
            .expect("Decoding failed")
            .try_into()
            .expect("Invalid length, expected 32 bytes");

        let transfer_action = Action::Transfer(TransferAction { deposit: 1u128 });
        let add_key_action = Action::AddKey(Box::new(AddKeyAction {
            public_key: PublicKey::ED25519(ED25519PublicKey(signer_public_key_as_bytes)),
            access_key: AccessKey {
                nonce: 0,
                permission: AccessKeyPermission::FullAccess,
            },
        }));

        let actions = vec![transfer_action, add_key_action];

        let near_tx = TransactionBuilder::new::<NEAR>()
            .signer_id(signer_id.to_string())
            .signer_public_key(PublicKey::ED25519(ED25519PublicKey(
                signer_public_key_as_bytes,
            )))
            .nonce(nonce)
            .receiver_id(receiver_id.to_string())
            .block_hash(block_hash_as_bytes)
            .actions(actions)
            .build();

        let encoded_data = contract.get_transaction_encoded_data(near_tx);

        let expected_data = vec![
            24, 0, 0, 0, 102, 111, 114, 103, 101, 116, 102, 117, 108, 45, 112, 97, 114, 101, 110,
            116, 46, 116, 101, 115, 116, 110, 101, 116, 0, 77, 167, 224, 244, 9, 106, 175, 44, 229,
            94, 55, 22, 87, 205, 48, 137, 186, 30, 159, 89, 244, 214, 226, 123, 208, 46, 71, 42,
            22, 166, 29, 193, 1, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 102, 111, 114, 103, 101, 116,
            102, 117, 108, 45, 112, 97, 114, 101, 110, 116, 46, 116, 101, 115, 116, 110, 101, 116,
            57, 74, 190, 179, 94, 112, 118, 9, 222, 143, 115, 182, 61, 67, 189, 26, 55, 111, 254,
            103, 147, 92, 170, 104, 147, 125, 210, 155, 192, 78, 103, 60, 2, 0, 0, 0, 3, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 77, 167, 224, 244, 9, 106, 175, 44, 229,
            94, 55, 22, 87, 205, 48, 137, 186, 30, 159, 89, 244, 214, 226, 123, 208, 46, 71, 42,
            22, 166, 29, 193, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];

        println!("Encoded data {:?}", encoded_data);
        println!("Expected data {:?}", expected_data);
        assert!(encoded_data.len() > 0);
        assert!(encoded_data == expected_data);
    }
}
