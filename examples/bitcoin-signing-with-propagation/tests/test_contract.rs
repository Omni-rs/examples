// Rust Bitcoin Dependencies
use bitcoin::hashes::{ripemd160, sha256d, Hash};
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{self, Message};
use bitcoin::Network;
use k256::elliptic_curve::sec1::ToEncodedPoint;
// NEAR Dependencies
use near_crypto::{InMemorySigner, PublicKey, SecretKey};
use near_jsonrpc_client::methods::tx::{RpcTransactionError, TransactionInfo};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::types::{BlockReference, Finality, FunctionArgs};
use near_primitives::views::{QueryRequest, TxExecutionStatus};
use near_sdk::AccountId;
// Omni Transaction Dependencies
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{
    Amount, EcdsaSighashType, Hash as OmniHash, LockTime, OutPoint, ScriptBuf, Sequence,
    TransactionType, TxIn, TxOut, Txid, Version, Witness,
};
use omni_transaction::transaction_builder::{TransactionBuilder, TxBuilder};
use omni_transaction::types::BITCOIN;
// Other Dependencies
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::time::{Duration, Instant};

mod utils;

use utils::{
    address::get_derived_address,
    bitcoin::{get_bitcoin_instance, BTCTestContext},
    environment::get_user_account_info_from_file,
    near::compile_and_deploy_contract,
};

const OMNI_SPEND_AMOUNT: Amount = Amount::from_sat(500_000_000);

#[tokio::test]
async fn test_sighash_p2pkh_btc_signing_with_propagation() -> Result<(), Box<dyn std::error::Error>>
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

    if should_deploy {
        compile_and_deploy_contract(&signer).await?;
    }

    // Prepare the BTCTestContext
    let mut btc_test_context = BTCTestContext::new(btc_client).unwrap();

    // Setup Bob
    let bob = btc_test_context.setup_account().unwrap();
    println!("bob.script_pubkey: {:?}", bob.script_pubkey);

    // Generate 101 blocks to the address
    btc_client.generate_to_address(101, &bob.address)?;

    // List UTXOs for Bob
    let unspent_utxos_bob = btc_test_context.get_utxo_for_address(&bob.address).unwrap();

    // Get the first UTXO
    let first_unspent = unspent_utxos_bob
        .into_iter()
        .next()
        .expect("There should be at least one unspent output");

    // Build the transaction
    let txid_str = first_unspent["txid"].as_str().unwrap();
    let hash = OmniHash::from_hex(txid_str).unwrap();
    let txid = Txid(hash);
    let vout = first_unspent["vout"].as_u64().unwrap() as usize;

    let txin: TxIn = TxIn {
        previous_output: OutPoint::new(txid, vout as u32),
        script_sig: ScriptBuf::default(), // For a p2pkh script_sig is initially empty.
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    // Get the derived address
    let derived_address = get_derived_address(&account_id);
    let derived_public_key_bytes = derived_address.public_key.to_encoded_point(false); // Ensure this method exists
    let derived_public_key_bytes_array = derived_public_key_bytes.as_bytes();

    println!("btc derived_address: {:?}", derived_address.address);

    // Hash the public key using SHA-256 followed by RIPEMD-160
    let sha256_hash = sha256d::Hash::hash(&derived_public_key_bytes_array);
    let ripemd160_hash = ripemd160::Hash::hash(sha256_hash.as_byte_array());

    // The script_pubkey for the NEAR contract to be the spender
    let script_pubkey = Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(&ripemd160_hash.as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let txout = TxOut {
        value: OMNI_SPEND_AMOUNT,
        script_pubkey: ScriptBuf(script_pubkey.as_bytes().to_vec()), // Here we use the script_pubkey of the derived address as the spender
    };

    let utxo_amount =
        Amount::from_sat((first_unspent["amount"].as_f64().unwrap() * 100_000_000.0) as u64);

    let change_amount: Amount = utxo_amount - OMNI_SPEND_AMOUNT - Amount::from_sat(1000); // 1000 satoshis for fee

    let change_txout = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf(bob.script_pubkey.as_bytes().to_vec()),
    };

    let mut btc_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::One)
        .lock_time(LockTime::from_height(1).unwrap())
        .inputs(vec![txin])
        .outputs(vec![txout, change_txout])
        .build();

    // Add the script_sig to the transaction
    btc_tx.input[0].script_sig = ScriptBuf(bob.script_pubkey.as_bytes().to_vec());

    // Encode the transaction for signing
    let encoded_data = btc_tx.build_for_signing_legacy(EcdsaSighashType::All);

    // Calculate the sighash
    let sighash_omni = sha256d::Hash::hash(&encoded_data);
    let msg_omni = Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();

    // Sign the sighash and broadcast the transaction using the Omni library
    let secp = Secp256k1::new();
    let signature_omni = secp.sign_ecdsa(&msg_omni, &bob.private_key);

    // Verify signature
    let is_valid = secp
        .verify_ecdsa(&msg_omni, &signature_omni, &bob.public_key)
        .is_ok();

    assert!(is_valid, "The signature should be valid");

    println!("is valid");

    // Encode the signature
    let signature = bitcoin::ecdsa::Signature {
        signature: signature_omni,
        sighash_type: bitcoin::EcdsaSighashType::All,
    };

    // Create the script_sig
    let script_sig_new = Builder::new()
        .push_slice(signature.serialize())
        .push_key(&bob.bitcoin_public_key)
        .into_script();

    // Assign script_sig to txin
    let omni_script_sig = ScriptBuf(script_sig_new.as_bytes().to_vec());
    let encoded_omni_tx = btc_tx.build_with_script_sig(0, omni_script_sig, TransactionType::P2PKH);

    let near_contract_address = bitcoin::Address::from_str(&derived_address.address.to_string())?;
    let near_contract_address = near_contract_address
        .require_network(Network::Regtest)
        .unwrap();

    // Convert the transaction to a hexadecimal string
    let hex_omni_tx = hex::encode(encoded_omni_tx);

    // We simply have sent a transaction to the bitcoin network where the spender is the derived address
    let raw_tx_result: serde_json::Value = btc_client
        .call("sendrawtransaction", &[json!(hex_omni_tx)])
        .unwrap();

    println!("raw_tx_result: {:?}", raw_tx_result);

    btc_client.generate_to_address(101, &bob.address)?;

    println!("Bob has sent a transaction to the bitcoin network where the spender is the derived address");

    btc_client.generate_to_address(101, &near_contract_address)?;
    btc_client.generate_to_address(101, &near_contract_address)?;

    println!("near_contract_address: {:?}", near_contract_address);

    // Now we need to get the UTXO of the NEAR contract, we use scantxoutset to get the UTXO
    let scan_txout_set_result: serde_json::Value = btc_client
        .call(
            "scantxoutset",
            &[
                json!("start"),
                json!([{ "desc": format!("addr({})", near_contract_address) }]),
            ],
        )
        .unwrap();

    println!("scan_txout_set_result: {:?}", scan_txout_set_result);

    // Now the near contract has a UTXO, we can call the NEAR contract to get the sighash and sign it
    // But before we need to create another transaction where the spender is the derived address

    // TODO: Get the TXID of the transaction where the spender is the derived address
    // Place that value in the previous_output field
    // The script_sig is the script_pubkey of the derived address
    // The sequence is MAX
    // The witness is empty

    // Build the transaction where the sender is the derived address
    let near_contract_spending_txid_str = first_unspent["txid"].as_str().unwrap();
    let near_contract_spending_hash = OmniHash::from_hex(near_contract_spending_txid_str).unwrap();
    let near_contract_spending_txid = Txid(near_contract_spending_hash);
    let near_contract_spending_vout = first_unspent["vout"].as_u64().unwrap() as usize;

    let near_contract_spending_txin: TxIn = TxIn {
        previous_output: OutPoint::new(
            near_contract_spending_txid,
            near_contract_spending_vout as u32,
        ),
        script_sig: ScriptBuf::default(), // For a p2pkh script_sig is initially empty.
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    let near_contract_spending_txout = TxOut {
        value: OMNI_SPEND_AMOUNT,
        script_pubkey: ScriptBuf(script_pubkey.as_bytes().to_vec()),
    };

    let near_contract_spending_change_txout = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf(bob.script_pubkey.as_bytes().to_vec()),
    };

    let near_contract_spending_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::One)
        .lock_time(LockTime::from_height(1).unwrap())
        .inputs(vec![near_contract_spending_txin])
        .outputs(vec![
            near_contract_spending_txout,
            near_contract_spending_change_txout,
        ])
        .build();

    // let method_name = "generate_sighash_p2pkh";
    // let args = json!({
    //     "bitcoin_tx": btc_tx
    // });

    // let request = methods::query::RpcQueryRequest {
    //     block_reference: BlockReference::Finality(Finality::Final),
    //     request: QueryRequest::CallFunction {
    //         account_id: account_id.clone(),
    //         method_name: method_name.to_string(),
    //         args: FunctionArgs::from(args.to_string().into_bytes()),
    //     },
    // };

    // let response = near_json_rpc_client.call(request).await?;

    // // Parse result
    // if let QueryResponseKind::CallResult(call_result) = response.kind {
    //     if let Ok(result_str) = String::from_utf8(call_result.result.clone()) {
    //         let sighash_omni = sha256d::Hash::hash(result_str.as_bytes());
    //         let msg_omni = Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();

    //         let args = json!({
    //             "sighash_p2pkh": hex::encode(msg_omni.as_ref())
    //         });

    //         // Call the MPC Signer

    //         // 1.- Create the action
    //         let signing_action = Action::FunctionCall(Box::new(FunctionCallAction {
    //             method_name: "sign_sighash_p2pkh".to_string(),
    //             args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
    //             gas: 300_000_000_000_000,
    //             deposit: 100000000000000000000000,
    //         }));

    //         let result =
    //             get_nonce_and_block_hash(&near_json_rpc_client, account_id.clone(), public_key)
    //                 .await;

    //         let (nonce, block_hash) = result.unwrap();

    //         let nonce = nonce + 1;

    //         // 2.- Create the transaction
    //         let near_tx: Transaction = Transaction::V0(TransactionV0 {
    //             signer_id: account_id.clone(),
    //             public_key: signer.public_key(),
    //             nonce,
    //             receiver_id: account_id.clone(),
    //             block_hash,
    //             actions: vec![signing_action],
    //         });

    //         // 3.- Sign the transaction
    //         let signer = &signer.into();
    //         let signed_transaction = near_tx.sign(signer);

    //         // 4.- Send the transaction
    //         let request = methods::send_tx::RpcSendTransactionRequest {
    //             signed_transaction,
    //             wait_until: TxExecutionStatus::Final,
    //         };

    //         let signer_response = send_transaction(&near_json_rpc_client, request).await?;
    //         println!("Transaction sent: {:?}", signer_response);

    //         let response_str = serde_json::to_string(&signer_response)?;

    //         let (big_r, s) = extract_big_r_and_s(&response_str).unwrap();
    //         println!("big_r: {:?}", big_r);
    //         println!("s: {:?}", s);

    //         let signature_built = create_signature(&big_r, &s);
    //         println!("signature_built: {:?}", signature_built);

    //         // Encode the signature
    //         let signature = bitcoin::ecdsa::Signature {
    //             signature: signature_built.unwrap(),
    //             sighash_type: bitcoin::EcdsaSighashType::All,
    //         };

    //         println!("signature: {:?}", signature);

    //         // Create the script_sig
    //         let script_sig_new = Builder::new()
    //             .push_slice(signature.serialize())
    //             .push_key(&bob.bitcoin_public_key)
    //             .into_script();

    //         // Assign script_sig to txin
    //         let omni_script_sig = ScriptBuf(script_sig_new.as_bytes().to_vec());
    //         let encoded_omni_tx =
    //             btc_tx.build_with_script_sig(0, omni_script_sig, TransactionType::P2PKH);

    //         // TODO: for each UTXO I need to sign and attach again....

    //         // Convert the transaction to a hexadecimal string
    //         let hex_omni_tx = hex::encode(encoded_omni_tx);

    //         // We now deploy to the bitcoin network (regtest mode)
    //         let raw_tx_result: serde_json::Value = btc_client
    //             .call("sendrawtransaction", &[json!(hex_omni_tx)])
    //             .unwrap();

    //         println!("raw_tx_result: {:?}", raw_tx_result);

    //         btc_client.generate_to_address(1, &bob.address)?;

    //         // assert_utxos_for_address(client, alice.address, 1);
    //     } else {
    //         println!("Result contains non-UTF8 bytes");
    //     }
    // }

    Ok(())
}

const TIMEOUT: Duration = Duration::from_secs(300);

async fn wait_for_transaction(
    client: &JsonRpcClient,
    tx_hash: CryptoHash,
    sender_account_id: AccountId,
    sent_at: Instant,
) -> Result<
    near_jsonrpc_primitives::types::transactions::RpcTransactionResponse,
    Box<dyn std::error::Error>,
> {
    loop {
        let response = client
            .call(methods::tx::RpcTransactionStatusRequest {
                transaction_info: TransactionInfo::TransactionId {
                    tx_hash,
                    sender_account_id: sender_account_id.clone(),
                },
                wait_until: TxExecutionStatus::Final,
            })
            .await;

        if sent_at.elapsed() > TIMEOUT {
            return Err("Time limit exceeded for the transaction to be recognized".into());
        }

        match response {
            Ok(response) => {
                return Ok(response);
            }
            Err(err) => {
                if matches!(err.handler_error(), Some(RpcTransactionError::TimeoutError)) {
                    continue;
                }
                return Err(err.into());
            }
        }
    }
}

fn extract_big_r_and_s(signer_response: &str) -> Result<(String, String), String> {
    // Parse the JSON response
    let v: Value = serde_json::from_str(signer_response).map_err(|e| e.to_string())?;

    // Navigate through the JSON structure to extract big_r and s
    if let Some(success_value) = v["final_execution_outcome"]["status"]["SuccessValue"].as_str() {
        if let Ok(inner) = serde_json::from_str::<Value>(success_value) {
            if let Some(big_r) = inner["big_r"]["affine_point"].as_str() {
                if let Some(s) = inner["s"]["scalar"].as_str() {
                    return Ok((big_r.to_string(), s.to_string()));
                }
            }
        }
    }

    Err("Failed to extract big_r and s".to_string())
}

fn create_signature(big_r_hex: &str, s_hex: &str) -> Result<Signature, secp256k1::Error> {
    // Convert hex strings to byte arrays
    let big_r_bytes = hex::decode(big_r_hex).unwrap();
    let s_bytes = hex::decode(s_hex).unwrap();

    // Remove the first byte from big_r (compressed point indicator)
    let big_r_x_bytes = &big_r_bytes[1..];

    // Ensure the byte arrays are the correct length
    if big_r_x_bytes.len() != 32 || s_bytes.len() != 32 {
        return Err(secp256k1::Error::InvalidSignature);
    }

    // Create the signature from the bytes
    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(big_r_x_bytes);
    signature_bytes[32..].copy_from_slice(&s_bytes);

    // Create the signature object
    let signature = Signature::from_compact(&signature_bytes)?;

    Ok(signature)
}

async fn send_transaction(
    client: &JsonRpcClient,
    request: methods::send_tx::RpcSendTransactionRequest,
) -> Result<
    near_jsonrpc_primitives::types::transactions::RpcTransactionResponse,
    Box<dyn std::error::Error>,
> {
    let sent_at: Instant = Instant::now();

    match client.call(request.clone()).await {
        Ok(response) => Ok(response),
        Err(err) => {
            if matches!(err.handler_error(), Some(RpcTransactionError::TimeoutError)) {
                let tx_hash = request.signed_transaction.get_hash();
                let sender_account_id = request.signed_transaction.transaction.signer_id().clone();
                wait_for_transaction(client, tx_hash, sender_account_id, sent_at).await
            } else {
                Err(err.into())
            }
        }
    }
}

// fn read_config(filename: &str) -> Result<Config, Box<dyn std::error::Error>> {
//     let mut file = File::open(filename)?;
//     let mut contents = String::new();
//     file.read_to_string(&mut contents)?;
//     let config: Config = serde_json::from_str(&contents)?;
//     Ok(config)
// }

// fn setup_bitcoin_testnet() -> Result<bitcoind::BitcoinD, Box<dyn std::error::Error>> {}
