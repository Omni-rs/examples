use near_sdk::near;
use omni_transaction::evm::utils::parse_eth_address;
use omni_transaction::transaction_builder::TransactionBuilder;
use omni_transaction::transaction_builder::TxBuilder;
use omni_transaction::types::EVM;

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    pub fn get_transaction_encoded_data(&self) -> Vec<u8> {
        let to_address_str = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let to_address = parse_eth_address(to_address_str);
        let max_gas_fee: u128 = 20_000_000_000;
        let max_priority_fee_per_gas: u128 = 1_000_000_000;
        let gas_limit: u128 = 21_000;
        let chain_id: u64 = 1;
        let nonce: u64 = 0;
        let data: Vec<u8> = vec![];
        let value: u128 = 10000000000000000; // 0.01 ETH

        let evm_tx = TransactionBuilder::new::<EVM>()
            .nonce(nonce)
            .to(to_address)
            .value(value)
            .input(data)
            .max_priority_fee_per_gas(max_priority_fee_per_gas)
            .max_fee_per_gas(max_gas_fee)
            .gas_limit(gas_limit)
            .chain_id(chain_id)
            .build();

        evm_tx.build_for_signing()
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
            2, 239, 1, 128, 132, 59, 154, 202, 0, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 216,
            218, 107, 242, 105, 100, 175, 157, 126, 237, 158, 3, 229, 52, 21, 211, 122, 169, 96,
            69, 135, 35, 134, 242, 111, 193, 0, 0, 128, 192,
        ];

        assert!(!encoded_data.is_empty());
        assert_eq!(encoded_data, expected_data);
    }
}
