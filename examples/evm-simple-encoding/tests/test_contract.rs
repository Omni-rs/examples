use serde_json::json;

#[tokio::test]
async fn test_simple_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox().await?;

    // Compile the contract
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy the contract
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Call the contract
    let view_result = contract
        .view("get_transaction_encoded_data")
        .args_json(json!({}))
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
