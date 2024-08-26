use near_sdk::near;
// use omni_transaction::transaction_builder::TransactionBuilder;
// use omni_transaction::transaction_builder::TxBuilder;
// use omni_transaction::types::EVM;

#[near(contract_state)]
pub struct Contract {}

impl Default for Contract {
    fn default() -> Self {
        Self {}
    }
}

#[near]
impl Contract {
    pub fn get_transaction_encoded_data(&self) -> String {
        // let tx = TransactionBuilder::new::<EVM>().nonce(1).build();
        // .nonce(1)
        // .(1)
        // .set_gas_limit(1)
        // .set_to("0x")
        // .build();

        // tx.build_for_signing()
        "Hello World!".to_string()
    }
}

// #[cfg(test)]
// mod tests {
//     use near_sdk::log;

//     use super::*;

//     #[test]
//     fn test_get_transaction_encoded_data() {
//         let contract = Contract::default();

//         let encoded_data = contract.get_transaction_encoded_data();

//         log!("encoded_data: {:?}", encoded_data);

//         assert!(encoded_data.len() > 0);
//     }
// }
