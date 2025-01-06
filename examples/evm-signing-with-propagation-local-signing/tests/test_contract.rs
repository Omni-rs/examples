use alloy::network::EthereumWallet;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
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
use omni_transaction::evm::types::Signature;
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
    println!("signer_response: {:?}", signer_response);

    let omni_evm_tx_hash = signature::extract_payload(&signer_response).unwrap();
    println!("omni_evm_tx_hash: {:?}", omni_evm_tx_hash);

    let signer: PrivateKeySigner = evm_context.anvil.keys()[0].clone().into();
    let wallet = EthereumWallet::from(signer.clone());

    // Create a provider with the wallet.
    let rpc_url = evm_context.anvil.endpoint().parse()?;
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_http(rpc_url);

    // Sign the transaction hash
    let omni_evm_tx_hash_fixed = omni_evm_tx_hash.into();
    let signature = signer.sign_hash(&omni_evm_tx_hash_fixed).await?;

    println!("signature: {:?}", signature);

    let signature_omni: Signature = Signature {
        v: if signature.v() { 1 } else { 0 },
        r: signature.r().to_be_bytes::<32>().to_vec(),
        s: signature.s().to_be_bytes::<32>().to_vec(),
    };
    println!("signature omni: {:?}", signature_omni);

    let omni_evm_tx_encoded_with_signature = tx.build_with_signature(&signature_omni);
    println!(
        "omni_evm_tx_encoded_with_signature: {:?}",
        omni_evm_tx_encoded_with_signature
    );

    // Send the transaction
    match provider
        .send_raw_transaction(&omni_evm_tx_encoded_with_signature)
        .await
    {
        Ok(tx_hash) => println!("Transaction sent successfully. Hash: {:?}", tx_hash),
        Err(e) => println!("Failed to send transaction: {:?}", e),
    }

    Ok(())
}

// signature: PrimitiveSignature { y_parity: true, r: 24246092416176482321844670070653284229982656009744458523150460084931885601571, s: 12005508541870860363886469032227997305416912314428430174077896805445194279628 }
// signature omni: Signature { v: 1, r: [53, 154, 205, 79, 51, 193, 181, 72, 126, 121, 248, 19, 18, 163, 44, 117, 74, 125, 71, 50, 239, 90, 160, 141, 167, 84, 46, 49, 67, 5, 19, 35], s: [26, 138, 224, 133, 65, 161, 248, 59, 142, 207, 98, 167, 10, 105, 106, 189, 156, 53, 12, 234, 143, 76, 177, 76, 45, 223, 70, 190, 129, 68, 234, 204] }

// omni_evm_tx_hash: [209, 8, 99, 240, 65, 52, 142, 105, 146, 94, 149, 120, 24, 102, 129, 203, 99, 49, 234, 18, 2, 213, 211, 166, 65, 55, 227, 62, 17, 109, 190, 163]
// omni_evm_tx_encoded_with_signature: [2, 248, 116, 130, 122, 105, 128, 132, 59, 154, 202, 0, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 135, 35, 134, 242, 111, 193, 0, 0, 128, 192, 1, 160, 53, 154, 205, 79, 51, 193, 181, 72, 126, 121, 248, 19, 18, 163, 44, 117, 74, 125, 71, 50, 239, 90, 160, 141, 167, 84, 46, 49, 67, 5, 19, 35, 160, 26, 138, 224, 133, 65, 161, 248, 59, 142, 207, 98, 167, 10, 105, 106, 189, 156, 53, 12, 234, 143, 76, 177, 76, 45, 223, 70, 190, 129, 68, 234, 204]
// Transaction sent successfully. Hash: PendingTransactionBuilder { config: PendingTransactionConfig { tx_hash: 0x8f523ec8585057f19d39b927ff7e8c8b7086a4a4fa7e8a8e4848639af9dd0fc2, required_confirmations: 1, timeout: None }, provider: RootProvider { client: RpcClient(RpcClientInner { transport: Http { client: Client { accepts: Accepts, proxies: [Proxy(System({}), None)], referer: true, default_headers: {"accept": "*/*"} }, url: Url { scheme: "http", cannot_be_a_base: false, username: "", password: None, host: Some(Domain("localhost")), port: Some(59889), path: "/", query: None, fragment: None } }, is_local: true, id: 1, poll_interval: 250 }), .. } }

// 02f874827a6980843b9aca008504a817c80082520894f39fd6e51aad88f6f4ce6ab8827279cfffb92266872386f26fc1000080c001a0359acd4f33c1b5487e79f81312a32c754a7d4732ef5aa08da7542e3143051323a01a8ae08541a1f83b8ecf62a70a696abd9c350cea8f4cb14c2ddf46be8144eacc

// {
//     "chainId": "31337",
//     "type": "EIP-1559",
//     "valid": true,
//     "hash": "0x8f523ec8585057f19d39b927ff7e8c8b7086a4a4fa7e8a8e4848639af9dd0fc2",
//     "nonce": "0",
//     "gasLimit": "21000",
//     "maxFeePerGas": "20000000000",
//     "maxPriorityFeePerGas": "1000000000",
//     "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
//     "to": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
//     "publicKey": "0x048318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5",
//     "v": "01",
//     "r": "359acd4f33c1b5487e79f81312a32c754a7d4732ef5aa08da7542e3143051323",
//     "s": "1a8ae08541a1f83b8ecf62a70a696abd9c350cea8f4cb14c2ddf46be8144eacc",
//     "value": "10000000000000000"
//   }
