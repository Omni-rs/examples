// Near dependencies
use near_primitives::action::FunctionCallAction;
// OmniBox dependencies
use omni_box::utils::address;
use omni_box::OmniBox;
// Omni Transaction Dependencies
use omni_transaction::evm::evm_transaction::EVMTransaction;
// Other Dependencies
use serde_json::json;
// Alloy Dependencies
use alloy_primitives::keccak256;

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
    let _near_context = &omni_box.near_context;

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

    let method_name = "get_transaction_encoded_data";
    let args = json!({
        "evm_tx_params": tx
    });

    // Call the contract
    let transaction_payload = &omni_box
        .friendly_near_json_rpc_client
        .call_contract::<Vec<u8>>(method_name, args)
        .await?;

    let attached_deposit = omni_box.get_experimental_signature_deposit().await?;
    println!("attached_deposit: {}", attached_deposit);
    println!("transaction_payload response: {:?}", transaction_payload);

    // Hash the encoded transaction
    let omni_evm_tx_hash = keccak256(&transaction_payload);
    println!("transaction_payload hash: {:?}", omni_evm_tx_hash.to_vec());

    // Compare if keccak256 is working correctly
    let method_name_2 = "get_transaction_hash";
    let args_2 = json!({
        "evm_tx_params": tx
    });

    // Call the contract
    let transaction_payload_2 = &omni_box
        .friendly_near_json_rpc_client
        .call_contract::<Vec<u8>>(method_name_2, args_2)
        .await?;

    println!(
        "transaction_payload_2 response: {:?}",
        transaction_payload_2.to_vec()
    );

    assert_eq!(omni_evm_tx_hash.to_vec(), transaction_payload_2.to_vec());

    // // Create the args for the sign_sighash_p2pkh method
    // let args = json!({
    //     "hash": hex::encode(omni_evm_tx_hash),
    //     "attached_deposit": attached_deposit.to_string()
    // });

    // let signer_response = omni_box
    //     .friendly_near_json_rpc_client
    //     .send_action(FunctionCallAction {
    //         method_name: "sign_transaction".to_string(),
    //         args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
    //         gas: 100_000_000_000_000,
    //         deposit: 1000000000000000000000000,
    //     })
    //     .await?;

    // // Propagate a EVM node
    // // Send the transaction
    // match provider
    //     .send_raw_transaction(&omni_evm_tx_encoded_with_signature)
    //     .await
    // {
    //     Ok(tx_hash) => println!("Transaction sent successfully. Hash: {:?}", tx_hash),
    //     Err(e) => println!("Failed to send transaction: {:?}", e),
    // }

    Ok(())
}
