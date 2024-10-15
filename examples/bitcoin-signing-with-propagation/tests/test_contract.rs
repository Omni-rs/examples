// Rust Bitcoin Dependencies
use bitcoin::hashes::{ripemd160, sha256d, Hash};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{self, Message};
use bitcoin::Network;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::sha2::{Digest, Sha256};
// NEAR Dependencies
use near_crypto::InMemorySigner;
use near_jsonrpc_client::methods;
use near_jsonrpc_client::methods::tx::RpcTransactionResponse;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::types::{BlockReference, Finality, FunctionArgs};
use near_primitives::views::{FinalExecutionStatus, QueryRequest, TxExecutionStatus};
// Omni Transaction Dependencies
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{
    Amount, Hash as OmniHash, LockTime, OutPoint, ScriptBuf, Sequence, TransactionType, TxIn,
    TxOut, Txid, Version, Witness,
};
use omni_transaction::transaction_builder::{TransactionBuilder, TxBuilder};
use omni_transaction::types::BITCOIN;
// Other Dependencies
use serde_json::json;
use std::str::FromStr;
use utils::near::{get_near_rpc_client, get_nonce_and_block_hash, send_transaction};

mod utils;

use utils::{
    address::get_derived_address,
    bitcoin::{get_bitcoin_instance, BTCTestContext},
    environment::get_user_account_info_from_file,
    near::compile_and_deploy_contract,
};

const OMNI_SPEND_AMOUNT: Amount = Amount::from_sat(500_000);
const PATH: &str = "bitcoin-1";

#[tokio::test]
async fn test_sighash_p2pkh_btc_signing_remote_with_propagation(
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
    let mut btc_test_context = BTCTestContext::new(btc_client).unwrap();

    // Setup Bob (the receiver)
    let bob = btc_test_context.setup_account().unwrap();

    // Get the derived address of the NEAR contract
    let derived_address = get_derived_address(&user_account.account_id, PATH);
    let derived_public_key_bytes = derived_address.public_key.to_encoded_point(false); // Ensure this method exists
    let derived_public_key_bytes_array = derived_public_key_bytes.as_bytes();

    // Calculate publish key hash
    let sha256_hash = Sha256::digest(&derived_public_key_bytes_array);
    let ripemd160_hash = ripemd160::Hash::hash(&sha256_hash);

    // The script_pubkey for the NEAR contract to be the spender
    let near_contract_script_pubkey = Builder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(&ripemd160_hash.as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    // In order to generate UTXOs, we parse the derived address to a bitcoin address and call the generate_to_address method
    let near_contract_address = bitcoin::Address::from_str(&derived_address.address.to_string())?;
    let near_contract_address = near_contract_address
        .require_network(Network::Regtest)
        .unwrap();

    btc_client.generate_to_address(101, &near_contract_address)?;

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

    // Get the first UTXO
    let first_unspent_near_contract = scan_txout_set_result
        .as_object()
        .unwrap()
        .get("unspents")
        .unwrap()
        .as_array()
        .unwrap()
        .into_iter()
        .next()
        .expect("There should be at least one unspent output");

    // Generate more blocks to avoid issues with confirmations
    btc_client.generate_to_address(101, &near_contract_address)?;

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
        script_sig: ScriptBuf::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    // Create the transaction output
    let near_contract_spending_txout = TxOut {
        value: OMNI_SPEND_AMOUNT,
        script_pubkey: ScriptBuf(bob.script_pubkey.as_bytes().to_vec()),
    };

    let utxo_amount = Amount::from_sat(
        (first_unspent_near_contract["amount"].as_f64().unwrap() * 100_000_000.0) as u64,
    );

    let change_amount: Amount = utxo_amount - OMNI_SPEND_AMOUNT - Amount::from_sat(1000); // 1000 satoshis for fee

    let near_contract_spending_change_txout = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf(near_contract_script_pubkey.as_bytes().to_vec()),
    };

    let mut near_contract_spending_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::One)
        .lock_time(LockTime::from_height(1).unwrap())
        .inputs(vec![near_contract_spending_txin])
        .outputs(vec![
            near_contract_spending_txout,
            near_contract_spending_change_txout,
        ])
        .build();

    // We add the script_pubkey of the NEAR contract as the script_sig
    near_contract_spending_tx.input[0].script_sig =
        ScriptBuf(near_contract_script_pubkey.as_bytes().to_vec());

    // Call the NEAR contract to generate the sighash
    let method_name = "generate_sighash_p2pkh";
    let args = json!({
        "bitcoin_tx": near_contract_spending_tx
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
            // Calculate the sighash
            let result_bytes: Vec<u8> = result_str
                .trim_matches(|c| c == '[' || c == ']') // Eliminar corchetes
                .split(',') // Dividir por comas
                .map(|s| s.trim().parse::<u8>().unwrap()) // Convertir cada parte a u8
                .collect();

            let sighash_omni = sha256d::Hash::hash(&result_bytes);
            let msg_omni = Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();

            let args = json!({
                "sighash_p2pkh": hex::encode(msg_omni.as_ref())
            });

            // 1.- Create the action
            let signing_action = Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "sign_sighash_p2pkh".to_string(),
                args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
                gas: 300_000_000_000_000,
                deposit: 100000000000000000000000,
            }));

            let result = get_nonce_and_block_hash(
                &near_json_rpc_client,
                user_account.account_id.clone(),
                signer.public_key(),
            )
            .await;

            let (nonce, block_hash) = result.unwrap();

            let nonce = nonce + 1;

            // 2.- Create the transaction
            let near_tx: Transaction = Transaction::V0(TransactionV0 {
                signer_id: user_account.account_id.clone(),
                public_key: signer.public_key(),
                nonce,
                receiver_id: user_account.account_id.clone(),
                block_hash,
                actions: vec![signing_action],
            });

            // 3.- Sign the transaction
            let signer = &signer.into();
            let signed_transaction = near_tx.sign(signer);

            // 4.- Send the transaction
            let request = methods::send_tx::RpcSendTransactionRequest {
                signed_transaction,
                wait_until: TxExecutionStatus::Final,
            };

            let signer_response = send_transaction(&near_json_rpc_client, request).await?;
            let (big_r, s) = extract_big_r_and_s(&signer_response).unwrap();

            let signature_built = create_signature(&big_r, &s);

            // Encode the signature
            let signature = bitcoin::ecdsa::Signature {
                signature: signature_built.unwrap(),
                sighash_type: bitcoin::EcdsaSighashType::All,
            };

            // Create the public key from the derived address
            let secp_pubkey =
                bitcoin::secp256k1::PublicKey::from_slice(derived_public_key_bytes_array)
                    .expect("Invalid public key");

            let bitcoin_pubkey = bitcoin::PublicKey::new_uncompressed(secp_pubkey);

            let script_sig_new = Builder::new()
                .push_slice(signature.serialize())
                .push_key(&bitcoin_pubkey)
                .into_script();

            // Assign script_sig to txin
            let omni_script_sig = ScriptBuf(script_sig_new.as_bytes().to_vec());

            // Encode the script sig
            let encoded_omni_tx = near_contract_spending_tx.build_with_script_sig(
                0,
                omni_script_sig,
                TransactionType::P2PKH,
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

            btc_client.generate_to_address(1, &near_contract_address)?;
        }
    }

    Ok(())
}

fn extract_big_r_and_s(response: &RpcTransactionResponse) -> Result<(String, String), String> {
    if let Some(near_primitives::views::FinalExecutionOutcomeViewEnum::FinalExecutionOutcome(
        final_outcome,
    )) = &response.final_execution_outcome
    {
        if let FinalExecutionStatus::SuccessValue(success_value) = &final_outcome.status {
            let success_value_str =
                String::from_utf8(success_value.clone()).map_err(|e| e.to_string())?;
            let inner: serde_json::Value =
                serde_json::from_str(&success_value_str).map_err(|e| e.to_string())?;

            let big_r = inner["big_r"]["affine_point"]
                .as_str()
                .ok_or("Missing big_r affine_point")?;
            let s = inner["s"]["scalar"].as_str().ok_or("Missing s scalar")?;

            return Ok((big_r.to_string(), s.to_string()));
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
