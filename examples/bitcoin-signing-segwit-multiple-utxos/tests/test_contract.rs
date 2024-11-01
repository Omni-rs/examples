// Rust Bitcoin Dependencies
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{Message, PublicKey as BitcoinSecp256k1PublicKey, Secp256k1};
use bitcoin::{ScriptBuf as BitcoinScriptBuf, WPubkeyHash};
// NEAR Dependencies
use near_crypto::InMemorySigner;
use near_jsonrpc_client::methods;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::types::{BlockReference, Finality, FunctionArgs};
use near_primitives::views::{QueryRequest, TxExecutionStatus};

use omni_testing_utilities::address::get_public_key_as_bytes;
use omni_testing_utilities::signature::{create_signature, extract_multiple_signatures};
// Omni Transaction Dependencies
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{
    Amount, Hash as OmniHash, LockTime, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Version,
    Witness,
};
use omni_transaction::transaction_builder::{TransactionBuilder, TxBuilder};
use omni_transaction::types::BITCOIN;
// Omni Testing Utilities
use omni_testing_utilities::bitcoind::AddressType;
use omni_testing_utilities::{
    address::{get_derived_address_for_segwit, get_public_key_hash},
    bitcoin::{get_bitcoin_instance, BTCTestContext},
    environment::get_user_account_info_from_file,
    near::{
        compile_and_deploy_contract, get_near_rpc_client, get_nonce_and_block_hash,
        send_transaction,
    },
};
// Other Dependencies
use futures::future::join_all;
use serde_json::json;

const OMNI_SPEND_AMOUNT: Amount = Amount::from_sat(500_000);
const PATH: &str = "bitcoin-1";
const MPC_CONTRACT_ACCOUNT: &str = "v1.signer-prod.testnet";

#[tokio::test]
async fn test_sighash_p2wpkh_btc_multiple_signing_remote() -> Result<(), Box<dyn std::error::Error>>
{
    let should_deploy = std::env::var("DEPLOY").is_ok();

    // Start Bitcoin node
    let bitcoind = get_bitcoin_instance().unwrap();
    let btc_client = &bitcoind.client;

    // Read the config
    let user_account = get_user_account_info_from_file(None).unwrap();

    // Create near signer
    let signer: InMemorySigner = InMemorySigner::from_secret_key(
        user_account.account_id.clone(),
        user_account.private_key.clone(),
    );

    // Create near json rpc client
    let near_json_rpc_client = get_near_rpc_client();

    if should_deploy {
        compile_and_deploy_contract(&user_account, &signer, &near_json_rpc_client).await?;
    }

    // Prepare the BTC Test Context
    let btc_test_context = BTCTestContext::new(btc_client).unwrap();

    // Setup Bob (the receiver)
    let bob = btc_test_context.setup_account(AddressType::Bech32).unwrap();

    // Get the derived address of the NEAR contract
    let derived_address = get_derived_address_for_segwit(&user_account.account_id, PATH);
    let public_key_hash = get_public_key_hash(&derived_address);

    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;

    // Now we need to get the UTXO of the NEAR contract, we use scantxoutset to get the first UTXO
    let unspent_utxos = btc_test_context
        .scan_utxo_for_address_with_count(&derived_address, 2)
        .unwrap();

    // Generate more blocks to avoid issues with confirmations
    btc_test_context.generate_to_derived_address(&derived_address)?;

    let mut inputs = Vec::new();
    let mut total_utxo_amount = 0;

    for unspent in &unspent_utxos {
        // Build the transaction where the sender is the derived address
        let near_contract_spending_txid_str = unspent["txid"].as_str().unwrap();
        let near_contract_spending_hash =
            OmniHash::from_hex(near_contract_spending_txid_str).unwrap();
        let near_contract_spending_txid = Txid(near_contract_spending_hash);
        let near_contract_spending_vout = unspent["vout"].as_u64().unwrap() as usize;

        // Create inputs using Omni library
        let txin: TxIn = TxIn {
            previous_output: OutPoint::new(
                near_contract_spending_txid,
                near_contract_spending_vout as u32,
            ),
            script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(), // Filled in after signing.
        };

        inputs.push(txin);

        let utxo_amount =
            Amount::from_sat((unspent["amount"].as_f64().unwrap() * 100_000_000.0) as u64);

        total_utxo_amount += utxo_amount.to_sat();
    }

    let change_amount: Amount =
        Amount::from_sat(total_utxo_amount) - OMNI_SPEND_AMOUNT - Amount::from_sat(1000); // 1000 satoshis for fee

    let near_p2wpkh = WPubkeyHash::from_slice(&public_key_hash).unwrap();

    // The change output is locked to a key controlled by us.
    let change_txout = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf(BitcoinScriptBuf::new_p2wpkh(&near_p2wpkh).into_bytes()), // TODO: Change
    };

    // The spend output is locked to a key controlled by the receiver. In this case to Alice.
    let spend_txout = TxOut {
        value: OMNI_SPEND_AMOUNT,
        script_pubkey: ScriptBuf(bob.address.script_pubkey().into_bytes()),
    };

    let near_contract_spending_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::Two)
        .lock_time(LockTime::from_height(0).unwrap())
        .inputs(inputs)
        .outputs(vec![spend_txout, change_txout])
        .build();

    let requests: Vec<methods::query::RpcQueryRequest> = unspent_utxos
        .iter()
        .enumerate()
        .map(|(i, unspent)| {
            let _utxo_amount =
                Amount::from_sat((unspent["amount"].as_f64().unwrap() * 100_000_000.0) as u64);

            // TODO: Change bob por NEAR
            let script_pub_key = BitcoinScriptBuf::new_p2wpkh(&bob.wpkh);
            let script_pubkey_bob = script_pub_key.p2wpkh_script_code().unwrap();
            let script_code = ScriptBuf(script_pubkey_bob.into_bytes());

            // Call the NEAR contract to generate the sighash
            let method_name = "generate_sighash_p2wpkh";

            let args = json!({
                "bitcoin_tx": near_contract_spending_tx,
                "input_index": i,
                "script_code":script_code,
                "value": OMNI_SPEND_AMOUNT.to_sat()
            });

            methods::query::RpcQueryRequest {
                block_reference: BlockReference::Finality(Finality::Final),
                request: QueryRequest::CallFunction {
                    account_id: user_account.account_id.clone(),
                    method_name: method_name.to_string(),
                    args: FunctionArgs::from(args.to_string().into_bytes()),
                },
            }
        })
        .collect();

    let futures = requests
        .into_iter()
        .map(|request| near_json_rpc_client.call(request));

    let responses = join_all(futures).await;

    let mut actions = Vec::new();
    let mut sighhashes_messages = Vec::new();

    for response in responses {
        match response {
            Ok(response) => {
                if let QueryResponseKind::CallResult(call_result) = response.kind {
                    if let Ok(result_str) = String::from_utf8(call_result.result.clone()) {
                        // Parse the result
                        let result_bytes: Vec<u8> = result_str
                            .trim_matches(|c| c == '[' || c == ']') // Remove brackets
                            .split(',') // Split by comma
                            .map(|s| s.trim().parse::<u8>().unwrap()) // Parse each byte
                            .collect();

                        // Calculate the sighash
                        let sighash_omni = sha256d::Hash::hash(&result_bytes);
                        let msg_omni =
                            Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();

                        sighhashes_messages.push(msg_omni);

                        // Get the deposit amount for the mpc signer
                        let request = methods::query::RpcQueryRequest {
                            block_reference: Finality::Final.into(),
                            request: QueryRequest::CallFunction {
                                account_id: MPC_CONTRACT_ACCOUNT.parse().unwrap(),
                                method_name: "experimental_signature_deposit".to_string(),
                                args: FunctionArgs::from(vec![]),
                            },
                        };

                        let response = near_json_rpc_client.call(request).await?;

                        let mut attached_deposit: u128 = 0;

                        if let QueryResponseKind::CallResult(result) = response.kind {
                            // Decode the byte array to a string
                            let result_str = String::from_utf8(result.result).unwrap();
                            attached_deposit =
                                result_str.trim_matches('"').parse::<u128>().unwrap();
                        } else {
                            println!("Error getting the attached deposit");
                        }

                        // Create the args for the sign_sighash_p2pkh method
                        let args = json!({
                            "sighash_p2wpkh": hex::encode(msg_omni.as_ref()),
                            "attached_deposit": attached_deposit.to_string()
                        });

                        // Create the action
                        let signing_action = Action::FunctionCall(Box::new(FunctionCallAction {
                            method_name: "sign_sighash_p2wpkh".to_string(),
                            args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
                            gas: 100_000_000_000_000,
                            deposit: 1000000000000000000000000,
                        }));

                        actions.push(signing_action);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
            }
        }
    }

    // Send the transaction using the actions created

    let result = get_nonce_and_block_hash(
        &near_json_rpc_client,
        user_account.account_id.clone(),
        signer.public_key(),
    )
    .await;

    let (nonce, block_hash) = result.unwrap();

    let nonce = nonce + 1;

    // Create the transaction
    let near_tx: Transaction = Transaction::V0(TransactionV0 {
        signer_id: user_account.account_id.clone(),
        public_key: signer.public_key(),
        nonce,
        receiver_id: user_account.account_id.clone(),
        block_hash,
        actions,
    });

    // Sign the transaction
    let signer = &signer.into();
    let signed_transaction = near_tx.sign(signer);

    // Send the transaction
    let request: methods::send_tx::RpcSendTransactionRequest =
        methods::send_tx::RpcSendTransactionRequest {
            signed_transaction,
            wait_until: TxExecutionStatus::Final,
        };

    let signer_response: methods::tx::RpcTransactionResponse =
        send_transaction(&near_json_rpc_client, request).await?;

    println!("Signer response: {:?}", signer_response);

    let signatures = extract_multiple_signatures(&signer_response).unwrap();

    println!("Signatures: {:?}", signatures);

    for (index, (big_r, s)) in signatures.iter().enumerate() {
        println!("Verifying signature {}", index);

        // Build the signature
        let signature_built = create_signature(&big_r, &s);

        // Verify signature
        let secp = Secp256k1::new();

        let public_key_as_bytes = get_public_key_as_bytes(&derived_address);

        let bitcoin_secp256k1_public_key =
            BitcoinSecp256k1PublicKey::from_slice(&public_key_as_bytes).unwrap();

        // Verify signature
        let is_valid = secp
            .verify_ecdsa(
                &sighhashes_messages[index],
                &signature_built.unwrap(),
                &bitcoin_secp256k1_public_key,
            )
            .is_ok();

        assert!(is_valid, "The signature should be valid");

        println!("Signature verified");
    }
    Ok(())
}
