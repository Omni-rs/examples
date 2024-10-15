use omni_transaction::evm::evm_transaction::EVMTransaction;
use omni_transaction::evm::utils::parse_eth_address;
use serde_json::json;

#[tokio::test]
async fn test_simple_encoding_with_args() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox().await?;

    // Compile the contract
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy the contract
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Prepare the transaction
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

    // Call the contract
    let view_result = contract
        .view("get_transaction_encoded_data")
        .args_json(json!({
            "evm_tx_params": tx
        }))
        .await?;

    // Deserialize the result
    let transaction_encoded_data: Vec<u8> = serde_json::from_slice(&view_result.result)?;

    let expected_data = vec![
        2, 239, 1, 128, 132, 59, 154, 202, 0, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 216, 218,
        107, 242, 105, 100, 175, 157, 126, 237, 158, 3, 229, 52, 21, 211, 122, 169, 96, 69, 135,
        35, 134, 242, 111, 193, 0, 0, 128, 192,
    ];

    assert_eq!(transaction_encoded_data, expected_data);

    Ok(())
}
