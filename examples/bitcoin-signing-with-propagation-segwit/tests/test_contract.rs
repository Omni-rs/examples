// Rust Bitcoin Dependencies
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{Message, PublicKey as BitcoinSecp256k1PublicKey, Secp256k1};
use bitcoin::Witness as BitcoinWitness;
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
use omni_testing_utilities::signature::{create_signature, extract_big_r_and_s};
// Omni Transaction Dependencies
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{
    Amount, Hash as OmniHash, LockTime, OutPoint, ScriptBuf, Sequence, TransactionType, TxIn,
    TxOut, Txid, Version, Witness,
};
use omni_transaction::transaction_builder::{TransactionBuilder, TxBuilder};
use omni_transaction::types::BITCOIN;
// Omni Testing Utilities
use omni_testing_utilities::bitcoind::AddressType;
use omni_testing_utilities::{
    address::{get_derived_address_for_segwit, get_public_key_hash_2},
    bitcoin::{get_bitcoin_instance, BTCTestContext},
    environment::get_user_account_info_from_file,
    near::{
        compile_and_deploy_contract, get_near_rpc_client, get_nonce_and_block_hash,
        send_transaction,
    },
};
// Other Dependencies
use serde_json::json;

const OMNI_SPEND_AMOUNT: Amount = Amount::from_sat(500_000);
const PATH: &str = "bitcoin-1";

#[tokio::test]
async fn test_sighash_p2wpkh_btc_signing_remote_with_propagation(
) -> Result<(), Box<dyn std::error::Error>> {
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
    let public_key_hash = get_public_key_hash_2(&derived_address);

    println!("Derived address: {:?}", derived_address.address);
    println!(
        "Public key hash: {:?}",
        hex::encode(public_key_hash.clone())
    );

    btc_test_context.generate_to_derived_address(&derived_address)?;

    // Now we need to get the UTXO of the NEAR contract, we use scantxoutset to get the first UTXO
    let binding = btc_test_context
        .scan_utxo_for_address_with_count(&derived_address, 1)
        .unwrap();

    let first_unspent_near_contract = binding.first().unwrap();

    // Generate more blocks to avoid issues with confirmations
    btc_test_context.generate_to_derived_address(&derived_address)?;

    // Build the transaction where the sender is the derived address
    let near_contract_spending_txid_str = first_unspent_near_contract["txid"].as_str().unwrap();
    let near_contract_spending_hash = OmniHash::from_hex(near_contract_spending_txid_str).unwrap();
    let near_contract_spending_txid = Txid(near_contract_spending_hash);
    let near_contract_spending_vout =
        first_unspent_near_contract["vout"].as_u64().unwrap() as usize;

    // Create the transaction input
    let near_contract_spending_txin: TxIn = TxIn {
        previous_output: OutPoint::new(
            near_contract_spending_txid,
            near_contract_spending_vout as u32,
        ),
        script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
        witness: Witness::default(), // Filled in after signing.
    };

    let utxo_amount = Amount::from_sat(
        (first_unspent_near_contract["amount"].as_f64().unwrap() * 100_000_000.0) as u64,
    );

    let change_amount: Amount = utxo_amount - OMNI_SPEND_AMOUNT - Amount::from_sat(1000); // 1000 satoshis for fee

    println!(
        "DEBUG ITEM BOB SCRIPT PUBKEY {}",
        bob.address.clone().script_pubkey()
    );

    // Create the transaction output
    let near_contract_spending_txout = TxOut {
        value: OMNI_SPEND_AMOUNT,
        script_pubkey: ScriptBuf(bob.address.script_pubkey().into_bytes()),
    };

    let near_p2wpkh = WPubkeyHash::from_slice(&public_key_hash).unwrap();

    println!(
        "DEBUG ITEM NEAR P2WPKH {}",
        BitcoinScriptBuf::new_p2wpkh(&near_p2wpkh)
    );

    // Create the change output
    let near_contract_spending_change_txout = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf(BitcoinScriptBuf::new_p2wpkh(&near_p2wpkh).into_bytes()),
    };

    let mut near_contract_spending_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::Two)
        .lock_time(LockTime::from_height(0).unwrap())
        .inputs(vec![near_contract_spending_txin])
        .outputs(vec![
            near_contract_spending_txout,
            near_contract_spending_change_txout,
        ])
        .build();

    let script_pubkey_near_contract = BitcoinScriptBuf::new_p2wpkh(&near_p2wpkh)
        .p2wpkh_script_code()
        .unwrap();

    println!(
        "DEBUG ITEM SCRIPT PUBKEY NEAR CONTRACT {:?}",
        script_pubkey_near_contract
    );

    let near_script_code = ScriptBuf(script_pubkey_near_contract.into_bytes());
    println!("Script code: {:?}", near_script_code);

    // Call the NEAR contract to generate the sighash
    let method_name = "generate_sighash_p2wpkh";
    let args = json!({
        "bitcoin_tx": near_contract_spending_tx,
        "input_index": 0,
        "script_code":near_script_code,
        "value": OMNI_SPEND_AMOUNT.to_sat()
    });

    let request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::CallFunction {
            account_id: user_account.account_id.clone(),
            method_name: method_name.to_string(),
            args: FunctionArgs::from(args.to_string().into_bytes()),
        },
    };

    let response = near_json_rpc_client.call(request).await?;

    // Parse result
    if let QueryResponseKind::CallResult(call_result) = response.kind {
        if let Ok(result_str) = String::from_utf8(call_result.result.clone()) {
            // Parse the result
            let result_bytes: Vec<u8> = result_str
                .trim_matches(|c| c == '[' || c == ']') // Eliminar corchetes
                .split(',') // Dividir por comas
                .map(|s| s.trim().parse::<u8>().unwrap()) // Convertir cada parte a u8
                .collect();

            println!("Result bytes: {:?}", result_bytes);

            let sighash_encoded_local = near_contract_spending_tx.build_for_signing_segwit(
                omni_transaction::bitcoin::types::EcdsaSighashType::All,
                0,
                &near_script_code,
                OMNI_SPEND_AMOUNT.to_sat(),
            );

            println!("Sighash encoded local: {:?}", sighash_encoded_local);

            // Calculate the sighash
            let sighash_omni = sha256d::Hash::hash(&result_bytes);
            let msg_omni = Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();

            println!("Sighash generated");

            assert_eq!(result_bytes, sighash_encoded_local);

            // Get the deposit amount for the mpc signer
            let mpc_contract_account_id: &str = "v1.signer-prod.testnet";

            let request = methods::query::RpcQueryRequest {
                block_reference: Finality::Final.into(),
                request: QueryRequest::CallFunction {
                    account_id: mpc_contract_account_id.parse().unwrap(),
                    method_name: "experimental_signature_deposit".to_string(),
                    args: FunctionArgs::from(vec![]),
                },
            };

            let response = near_json_rpc_client.call(request).await?;

            let mut attached_deposit: u128 = 0;

            if let QueryResponseKind::CallResult(result) = response.kind {
                // Decode the byte array to a string
                let result_str = String::from_utf8(result.result).unwrap();
                attached_deposit = result_str.trim_matches('"').parse::<u128>().unwrap();
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
                actions: vec![signing_action.clone()],
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

            let signer_response = send_transaction(&near_json_rpc_client, request).await?;
            let (big_r, s) = extract_big_r_and_s(&signer_response).unwrap();
            let signature_built = create_signature(&big_r, &s);

            println!("Signature built: {:?}", signature_built);

            // Verify signature
            let secp = Secp256k1::new();

            let public_key_as_bytes = get_public_key_as_bytes(&derived_address);
            println!("Public key as bytes: {:?}", public_key_as_bytes);

            let secp_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&public_key_as_bytes)
                .expect("Invalid public key");

            println!("Secp pubkey: {:?}", secp_pubkey);

            let bitcoin_pubkey = bitcoin::PublicKey::new(secp_pubkey);

            println!("Bitcoin pubkey: {:?}", bitcoin_pubkey);

            let bitcoin_secp256k1_public_key =
                BitcoinSecp256k1PublicKey::from_slice(&public_key_as_bytes).unwrap();

            println!("Bitcoin public key: {:?}", bitcoin_secp256k1_public_key);

            let wpkh = bitcoin_pubkey.wpubkey_hash().unwrap();

            println!("Wpkh: {:?}", wpkh);

            // Verify signature
            let is_valid = secp
                .verify_ecdsa(
                    &msg_omni,
                    &signature_built.unwrap(),
                    &bitcoin_secp256k1_public_key,
                )
                .is_ok();

            assert!(is_valid, "The signature should be valid");

            println!("Signature verified");
            // ----

            // Encode the signature
            let signature = bitcoin::ecdsa::Signature {
                signature: signature_built.unwrap(),
                sighash_type: bitcoin::EcdsaSighashType::All,
            };

            println!("Signature: {:?}", signature);
            println!("Signature bytes: {:?}", signature.serialize());

            let witness_script = bitcoin::ScriptBuf::new_p2wpkh(&wpkh);
            println!("Witness script: {:?}", witness_script);
            println!("Witness script bytes: {:?}", witness_script.as_bytes());

            // Create the witness
            let witness = BitcoinWitness::p2wpkh(&signature, &secp_pubkey);

            println!("Witness: {:?}", witness);
            println!("Witness bytes: {:?}", witness);

            println!(
                "Witness antes de firmar: {:?}",
                near_contract_spending_tx.input[0].witness
            );

            let encoded_omni_tx = near_contract_spending_tx.build_with_witness(
                0,
                witness.to_vec(),
                TransactionType::P2WPKH,
            );

            println!(
                "Witness después de firmar: {:?}",
                near_contract_spending_tx.input[0].witness
            );

            println!("Encoded Omni TX: {:?}", encoded_omni_tx.clone());
            println!(
                "hex encoded omni tx {:?}",
                hex::encode(encoded_omni_tx.clone())
            );

            // Convert the transaction to a hexadecimal string
            let hex_omni_tx = hex::encode(encoded_omni_tx);
            let maxfeerate = 0.10;
            let maxburnamount = 10.00;

            // We now deploy to the bitcoin network (regtest mode)
            let raw_tx_result: serde_json::Value = btc_client
                .call(
                    "sendrawtransaction",
                    &[json!(hex_omni_tx), json!(maxfeerate), json!(maxburnamount)],
                )
                .unwrap();

            println!("raw_tx_result: {:?}", raw_tx_result);
        }
    }

    Ok(())
}
