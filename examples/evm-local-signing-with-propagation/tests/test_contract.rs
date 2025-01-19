use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use near_primitives::action::FunctionCallAction;
use omni_box::utils::signature;
use omni_box::OmniBox;
use omni_transaction::evm::evm_transaction::EVMTransaction;
use omni_transaction::evm::types::Signature;
use serde_json::json;

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

    let args = json!({
        "evm_tx_params": tx
    });

    // Call the contract
    let signer_response = omni_box
        .friendly_near_json_rpc_client
        .send_action(FunctionCallAction {
            method_name: "hash_transaction".to_string(),
            args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
            gas: 300000000000000,
            deposit: 1000000000000000000000000,
        })
        .await?;

    let omni_evm_tx_hash = signature::extract_payload(&signer_response).unwrap();
    let signer: PrivateKeySigner = evm_context.anvil.keys()[1].clone().into(); // Bob's key

    // Sign the transaction hash
    let omni_evm_tx_hash_fixed = omni_evm_tx_hash.into();
    let signature = signer.sign_hash(&omni_evm_tx_hash_fixed).await?;

    let signature_omni: Signature = Signature {
        v: if signature.v() { 1 } else { 0 },
        r: signature.r().to_be_bytes::<32>().to_vec(),
        s: signature.s().to_be_bytes::<32>().to_vec(),
    };

    let omni_evm_tx_encoded_with_signature = tx.build_with_signature(&signature_omni);

    // Send the transaction
    match evm_context
        .provider
        .send_raw_transaction(&omni_evm_tx_encoded_with_signature)
        .await
    {
        Ok(tx_hash) => println!("Transaction sent successfully. Hash: {:?}", tx_hash),
        Err(e) => println!("Failed to send transaction: {:?}", e),
    }

    Ok(())
}

fn vec_to_array(vec: Vec<u8>) -> Result<[u8; 20], &'static str> {
    if vec.len() == 20 {
        let mut array = [0u8; 20];
        array.copy_from_slice(&vec);
        Ok(array)
    } else {
        Err("Vec length is not 20")
    }
}
