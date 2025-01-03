// Near dependencies
use near_primitives::action::FunctionCallAction;
// OmniBox dependencies
use omni_box::utils::{address, signature};
use omni_box::OmniBox;
// Omni Transaction Dependencies
use omni_transaction::evm::evm_transaction::EVMTransaction;
// Other Dependencies
use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use serde_json::json;

fn vec_to_array(vec: Vec<u8>) -> Result<[u8; 20], &'static str> {
    if vec.len() == 20 {
        let mut array = [0u8; 20];
        array.copy_from_slice(&vec);
        Ok(array)
    } else {
        Err("Vec length is not 20")
    }
}

const PATH: &str = "ethereum-1";

#[tokio::test]
async fn test_simple_encoding_with_args() -> Result<(), Box<dyn std::error::Error>> {
    let omni_box = OmniBox::new().await;

    let evm_context = &omni_box.evm_context;

    // Prepare the transaction
    let to_address = &omni_box.evm_context.alice;
    let to_address = vec_to_array(to_address.default_signer().address().to_vec()).unwrap();
    let max_fee_per_gas: u128 = 20_000_000_000;
    let max_priority_fee_per_gas: u128 = 1_000_000_000;
    let gas_limit: u128 = 21_000;
    let chain_id: u64 = evm_context.anvil.chain_id();
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

    let derived_address =
        address::get_derived_address_for_evm(&omni_box.deployer_account.account_id, PATH);

    println!("derived_address: {:?}", derived_address.address);

    let attached_deposit = omni_box.get_experimental_signature_deposit().await?;

    let args = json!({
        "evm_tx_params": tx,
        "attached_deposit": attached_deposit
    });

    // Call the contract
    let signer_response = omni_box
        .friendly_near_json_rpc_client
        .send_action(FunctionCallAction {
            method_name: "hash_and_sign_transaction".to_string(),
            args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
            gas: 300000000000000,
            deposit: 1000000000000000000000000,
        })
        .await?;

    println!("signer_response: {:?}", signer_response);

    // Convert the transaction to a hexadecimal string
    let hex_omni_tx = signature::extract_signed_transaction(&signer_response).unwrap();
    println!("hex_omni_tx: {:?}", hex_omni_tx);

    // Create a provider with the wallet.
    let rpc_url = evm_context.anvil.endpoint().parse()?;
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(rpc_url);

    match provider.send_raw_transaction(&hex_omni_tx).await {
        Ok(tx_hash) => println!("Transaction sent successfully. Hash: {:?}", tx_hash),
        Err(e) => println!("Failed to send transaction: {:?}", e),
    }

    Ok(())
}
