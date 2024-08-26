use omni_transaction::evm::evm_transaction::EVMTransaction;
use omni_transaction::evm::types::Signature;
use omni_transaction::evm::utils::parse_eth_address;
use serde_json::json;

#[tokio::test]
async fn test_simple_encoding_with_signature() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox().await?;

    // Compile the contract
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy the contract
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Prepare the transaction
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
            132, 12, 252, 87, 40, 69, 245, 120, 110, 112, 41, 132, 194, 165, 130, 82, 140, 173, 75,
            73, 178, 161, 11, 157, 177, 190, 127, 202, 144, 5, 133, 101,
        ],
        s: vec![
            37, 231, 16, 156, 235, 152, 22, 141, 149, 176, 155, 24, 187, 246, 182, 133, 19, 14, 5,
            98, 242, 51, 135, 125, 73, 43, 148, 238, 224, 197, 182, 209,
        ],
    };

    // Call the contract
    let view_result = contract
        .view("get_transaction_encoded_data_with_signature")
        .args_json(json!({
            "evm_tx_params": tx,
            "signature": signature
        }))
        .await?;

    // Deserialize the result
    let transaction_encoded_data: Vec<u8> = serde_json::from_slice(&view_result.result)?;

    let expected_data = vec![
        2, 248, 176, 1, 66, 132, 59, 154, 202, 0, 133, 4, 168, 23, 200, 0, 130, 173, 98, 148, 96,
        105, 166, 195, 44, 246, 145, 245, 152, 47, 235, 174, 79, 175, 138, 111, 58, 178, 240, 246,
        128, 184, 68, 162, 44, 180, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 94, 238, 117, 114,
        125, 128, 74, 43, 19, 3, 137, 40, 211, 111, 139, 24, 137, 69, 165, 122, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 128,
        160, 132, 12, 252, 87, 40, 69, 245, 120, 110, 112, 41, 132, 194, 165, 130, 82, 140, 173,
        75, 73, 178, 161, 11, 157, 177, 190, 127, 202, 144, 5, 133, 101, 160, 37, 231, 16, 156,
        235, 152, 22, 141, 149, 176, 155, 24, 187, 246, 182, 133, 19, 14, 5, 98, 242, 51, 135, 125,
        73, 43, 148, 238, 224, 197, 182, 209,
    ];

    assert_eq!(transaction_encoded_data, expected_data);

    Ok(())
}
