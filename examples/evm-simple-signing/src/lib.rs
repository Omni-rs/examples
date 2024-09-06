use near_sdk::near;
use omni_transaction::evm::evm_transaction::EVMTransaction;
use omni_transaction::evm::types::Signature;
use omni_transaction::transaction_builder::TransactionBuilder;
use omni_transaction::transaction_builder::TxBuilder;
use omni_transaction::types::EVM;

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    pub fn get_transaction_encoded_data_with_signature(
        &self,
        evm_tx_params: EVMTransaction,
        signature: Signature,
    ) -> Vec<u8> {
        let evm_tx = TransactionBuilder::new::<EVM>()
            .nonce(evm_tx_params.nonce)
            .to(evm_tx_params.to.expect("to address is required"))
            .value(evm_tx_params.value)
            .input(evm_tx_params.input)
            .max_priority_fee_per_gas(evm_tx_params.max_priority_fee_per_gas)
            .max_fee_per_gas(evm_tx_params.max_fee_per_gas)
            .gas_limit(evm_tx_params.gas_limit)
            .chain_id(evm_tx_params.chain_id)
            .build();

        evm_tx.build_with_signature(&signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_transaction::evm::evm_transaction::EVMTransaction;
    use omni_transaction::evm::types::Signature;
    use omni_transaction::evm::utils::parse_eth_address;

    #[test]
    fn test_signing_with_mpc_signer() {
        let contract = Contract::default();

        let chain_id: u64 = 1;
        let nonce: u64 = 0x42;
        let gas_limit = 44386;
        let max_fee_per_gas = 0x4a817c800;
        let max_priority_fee_per_gas = 0x3b9aca00;
        let to_address_str = "6069a6c32cf691f5982febae4faf8a6f3ab2f0f6";
        let to_address = parse_eth_address(to_address_str);
        let value: u128 = 0;
        let input_str = "a22cb4650000000000000000000000005eee75727d804a2b13038928d36f8b188945a57a0000000000000000000000000000000000000000000000000000000000000000";
        let input_vec: Vec<u8> = hex::decode(input_str).expect("Decoding failed");

        let tx = EVMTransaction {
            nonce,
            to: Some(to_address),
            value,
            input: input_vec,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            chain_id,
            access_list: vec![],
        };

        let signature: Signature = Signature {
            v: 0u64,
            r: vec![
                132, 12, 252, 87, 40, 69, 245, 120, 110, 112, 41, 132, 194, 165, 130, 82, 140, 173,
                75, 73, 178, 161, 11, 157, 177, 190, 127, 202, 144, 5, 133, 101,
            ],
            s: vec![
                37, 231, 16, 156, 235, 152, 22, 141, 149, 176, 155, 24, 187, 246, 182, 133, 19, 14,
                5, 98, 242, 51, 135, 125, 73, 43, 148, 238, 224, 197, 182, 209,
            ],
        };

        let encoded_data = contract.get_transaction_encoded_data_with_signature(tx, signature);

        let expected_data = vec![
            2, 248, 176, 1, 66, 132, 59, 154, 202, 0, 133, 4, 168, 23, 200, 0, 130, 173, 98, 148,
            96, 105, 166, 195, 44, 246, 145, 245, 152, 47, 235, 174, 79, 175, 138, 111, 58, 178,
            240, 246, 128, 184, 68, 162, 44, 180, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 94, 238,
            117, 114, 125, 128, 74, 43, 19, 3, 137, 40, 211, 111, 139, 24, 137, 69, 165, 122, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 192, 128, 160, 132, 12, 252, 87, 40, 69, 245, 120, 110, 112, 41, 132, 194, 165, 130,
            82, 140, 173, 75, 73, 178, 161, 11, 157, 177, 190, 127, 202, 144, 5, 133, 101, 160, 37,
            231, 16, 156, 235, 152, 22, 141, 149, 176, 155, 24, 187, 246, 182, 133, 19, 14, 5, 98,
            242, 51, 135, 125, 73, 43, 148, 238, 224, 197, 182, 209,
        ];

        assert!(!encoded_data.is_empty());
        assert_eq!(encoded_data, expected_data);
    }
}
