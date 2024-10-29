use serde_json::json;

#[tokio::test]
async fn test_sighash_p2pkh() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox().await?;

    // Compile the contract
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy the contract
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Call the contract
    let view_result = contract.view("sighash_p2pkh").args_json(json!({})).await?;

    // Deserialize the result
    let sighash_p2pkh: Vec<u8> = serde_json::from_slice(&view_result.result)?;

    let expected_data = vec![
        1, 0, 0, 0, 1, 28, 135, 153, 241, 127, 123, 70, 156, 123, 129, 155, 207, 90, 104, 88, 204,
        62, 44, 165, 48, 143, 238, 60, 97, 255, 144, 238, 31, 215, 108, 206, 46, 0, 0, 0, 0, 0,
        255, 255, 255, 255, 2, 0, 101, 205, 29, 0, 0, 0, 0, 50, 55, 54, 97, 57, 49, 52, 52, 48, 54,
        99, 102, 56, 97, 49, 56, 98, 57, 55, 97, 50, 51, 48, 100, 49, 53, 101, 100, 56, 50, 102,
        48, 100, 50, 53, 49, 53, 54, 48, 97, 48, 53, 98, 100, 97, 48, 54, 56, 56, 97, 99, 0, 225,
        245, 5, 0, 0, 0, 0, 50, 55, 54, 97, 57, 49, 52, 99, 98, 56, 97, 51, 48, 49, 56, 99, 102,
        50, 55, 57, 51, 49, 49, 98, 49, 52, 56, 99, 98, 56, 100, 49, 51, 55, 50, 56, 98, 100, 56,
        99, 98, 101, 57, 53, 98, 100, 97, 56, 56, 97, 99, 0, 0, 0, 0, 1, 0, 0, 0,
    ];

    assert_eq!(sighash_p2pkh, expected_data);

    Ok(())
}

#[tokio::test]
async fn test_sighash_p2wpkh() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox().await?;

    // Compile the contract
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy the contract
    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    // Call the contract
    let view_result = contract.view("sighash_p2wpkh").args_json(json!({})).await?;

    // Deserialize the result
    let sighash_p2pkh: Vec<u8> = serde_json::from_slice(&view_result.result)?;

    let expected_data = vec![
        2, 0, 0, 0, 190, 19, 35, 27, 24, 80, 118, 238, 28, 58, 96, 102, 217, 33, 170, 218, 166,
        161, 96, 97, 97, 101, 9, 116, 240, 177, 223, 37, 186, 193, 117, 136, 59, 177, 48, 41, 206,
        123, 31, 85, 158, 245, 231, 71, 252, 172, 67, 159, 20, 85, 162, 236, 124, 95, 9, 183, 34,
        144, 121, 94, 112, 102, 80, 68, 28, 135, 153, 241, 127, 123, 70, 156, 123, 129, 155, 207,
        90, 104, 88, 204, 62, 44, 165, 48, 143, 238, 60, 97, 255, 144, 238, 31, 215, 108, 206, 46,
        0, 0, 0, 0, 50, 55, 54, 97, 57, 49, 52, 52, 48, 54, 99, 102, 56, 97, 49, 56, 98, 57, 55,
        97, 50, 51, 48, 100, 49, 53, 101, 100, 56, 50, 102, 48, 100, 50, 53, 49, 53, 54, 48, 97,
        48, 53, 98, 100, 97, 48, 54, 56, 56, 97, 99, 0, 101, 205, 29, 0, 0, 0, 0, 255, 255, 255,
        255, 51, 246, 62, 154, 157, 45, 168, 65, 30, 226, 118, 42, 92, 251, 84, 198, 60, 11, 30,
        24, 93, 54, 136, 124, 222, 114, 103, 35, 173, 53, 186, 251, 0, 0, 0, 0, 1, 0, 0, 0,
    ];

    assert_eq!(sighash_p2pkh, expected_data);

    Ok(())
}
