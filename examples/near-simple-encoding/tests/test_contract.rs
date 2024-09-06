use serde_json::json;

#[tokio::test]
async fn test_contract_is_operational() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the contract
    let sandbox = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy the contract

    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Call the contract
    let view_result = contract
        .view("get_transaction_encoded_data")
        .args_json(json!({}))
        .await?;

    // Check the result
    let transaction_encoded_data: Vec<u8> = serde_json::from_slice(&view_result.result)?;

    let expected_data = vec![
        10, 0, 0, 0, 97, 108, 105, 99, 101, 46, 110, 101, 97, 114, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 8, 0, 0, 0, 98, 111, 98, 46, 110, 101, 97, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 3, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    assert_eq!(transaction_encoded_data, expected_data);

    Ok(())
}
