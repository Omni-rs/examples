// Rust Bitcoin Dependencies
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{self, Message};
use bitcoin::EcdsaSighashType;
// NEAR Dependencies
use near_crypto::{InMemorySigner, PublicKey, SecretKey};
use near_jsonrpc_client::methods::tx::{RpcTransactionError, TransactionInfo};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::action::{Action, DeployContractAction, FunctionCallAction};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::types::{BlockReference, Finality, FunctionArgs};
use near_primitives::views::{QueryRequest, TxExecutionStatus};
use near_sdk::AccountId;
// Omni Transaction Dependencies
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{
    Amount, Hash as OmniHash, LockTime, OutPoint, ScriptBuf, Sequence, TransactionType, TxIn,
    TxOut, Txid, Version, Witness,
};
use omni_transaction::transaction_builder::{TransactionBuilder, TxBuilder};
use omni_transaction::types::BITCOIN;
// Other Dependencies
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::time::{Duration, Instant};
use tempfile::TempDir;

mod bitcoin_utils;

use bitcoin_utils::BTCTestContext;

#[derive(Debug, Deserialize)]
struct Config {
    account_id: String,
    private_key: String,
    public_key: String,
}

const NEAR_RPC_TESTNET: &str = "https://rpc.testnet.near.org";
const OMNI_SPEND_AMOUNT: Amount = Amount::from_sat(500_000_000);

#[tokio::test]
async fn test_sighash_p2pkh() -> Result<(), Box<dyn std::error::Error>> {
    let should_deploy = std::env::var("DEPLOY").is_ok();

    // Start Bitcoin node
    let bitcoind = setup_bitcoin_testnet().unwrap();
    let btc_client = &bitcoind.client;
    let blockchain_info = btc_client.get_blockchain_info().unwrap();
    assert_eq!(0, blockchain_info.blocks);

    // Read the config
    let config = read_config("config.json")?;

    let account_id: AccountId = config.account_id.parse().unwrap();
    let private_key: SecretKey = config.private_key.parse().unwrap();
    let public_key: PublicKey = config.public_key.parse().unwrap();

    // Create signer
    let signer: InMemorySigner =
        InMemorySigner::from_secret_key(account_id.clone(), private_key.clone());

    // Compile the contract
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Deploy the contract to near testnet
    let near_json_rpc_client = JsonRpcClient::connect(NEAR_RPC_TESTNET);

    // Get the block hash and nonce
    let result = get_nonce_and_block_hash(
        &near_json_rpc_client,
        account_id.clone(),
        public_key.clone(),
    )
    .await;

    let (nonce, block_hash) = result.unwrap();

    let nonce = nonce + 1;

    if should_deploy {
        // Create the deploy transaction
        let deploy_action = Action::DeployContract(DeployContractAction {
            code: contract_wasm,
        });

        let near_tx: Transaction = Transaction::V0(TransactionV0 {
            signer_id: account_id.clone(),
            public_key: signer.public_key(),
            nonce,
            receiver_id: account_id.clone(),
            block_hash,
            actions: vec![deploy_action],
        });

        let signer = &signer.clone().into();

        // Sign and send the transaction
        let request = methods::send_tx::RpcSendTransactionRequest {
            signed_transaction: near_tx.sign(signer),
            wait_until: TxExecutionStatus::Final,
        };

        let _ = send_transaction(&near_json_rpc_client, request).await?;

        println!("Contract deployed");
    }

    // Prepare the BTCTestContext
    let mut btc_test_context = BTCTestContext::new(btc_client).unwrap();

    // Setup Bob
    let bob = btc_test_context.setup_account().unwrap();

    let alice = btc_test_context.setup_account().unwrap();

    // Generate 101 blocks to the address
    btc_client.generate_to_address(101, &bob.address)?;

    // List UTXOs for Bob
    let unspent_utxos_bob = btc_test_context.get_utxo_for_address(&bob.address).unwrap();

    // println!("unspent_utxos_bob: {:?}", unspent_utxos_bob);

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

    let txout = TxOut {
        value: OMNI_SPEND_AMOUNT,
        script_pubkey: ScriptBuf(alice.script_pubkey.as_bytes().to_vec()),
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

    // Call the contract to get the sighash
    let method_name = "generate_sighash_p2pkh";
    let args = json!({
        "bitcoin_tx": btc_tx
    });

    let request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::CallFunction {
            account_id: account_id.clone(),
            method_name: method_name.to_string(),
            args: FunctionArgs::from(args.to_string().into_bytes()),
        },
    };

    let response = near_json_rpc_client.call(request).await?;

    // Parse result
    if let QueryResponseKind::CallResult(call_result) = response.kind {
        if let Ok(result_str) = String::from_utf8(call_result.result.clone()) {
            let sighash_omni = sha256d::Hash::hash(result_str.as_bytes());
            let msg_omni = Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();

            let args = json!({
                "sighash_p2pkh": hex::encode(msg_omni.as_ref())
            });

            // Call the MPC Signer

            // 1.- Create the action
            let signing_action = Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: "sign_sighash_p2pkh".to_string(),
                args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
                gas: 300_000_000_000_000,
                deposit: 100000000000000000000000,
            }));

            let result =
                get_nonce_and_block_hash(&near_json_rpc_client, account_id.clone(), public_key)
                    .await;

            let (nonce, block_hash) = result.unwrap();

            let nonce = nonce + 1;

            // 2.- Create the transaction
            let near_tx: Transaction = Transaction::V0(TransactionV0 {
                signer_id: account_id.clone(),
                public_key: signer.public_key(),
                nonce,
                receiver_id: account_id.clone(),
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
            println!("Transaction sent: {:?}", signer_response);

            let response_str = serde_json::to_string(&signer_response)?;

            let (big_r, s) = extract_big_r_and_s(&response_str).unwrap();
            println!("big_r: {:?}", big_r);
            println!("s: {:?}", s);

            let signature_built = create_signature(&big_r, &s);
            println!("signature_built: {:?}", signature_built);

            // Encode the signature
            let signature = bitcoin::ecdsa::Signature {
                signature: signature_built.unwrap(),
                sighash_type: EcdsaSighashType::All,
            };

            println!("signature: {:?}", signature);

            // Create the script_sig
            let script_sig_new = Builder::new()
                .push_slice(signature.serialize())
                .push_key(&bob.bitcoin_public_key)
                .into_script();

            // Assign script_sig to txin
            let omni_script_sig = ScriptBuf(script_sig_new.as_bytes().to_vec());
            let encoded_omni_tx =
                btc_tx.build_with_script_sig(0, omni_script_sig, TransactionType::P2PKH);

            // for each UTXO I need to sign and attach again....

            // Convert the transaction to a hexadecimal string
            let hex_omni_tx = hex::encode(encoded_omni_tx);

            // We now deploy to the bitcoin network (regtest mode)
            let raw_tx_result: serde_json::Value = btc_client
                .call("sendrawtransaction", &[json!(hex_omni_tx)])
                .unwrap();

            println!("raw_tx_result: {:?}", raw_tx_result);

            btc_client.generate_to_address(1, &bob.address)?;

            // assert_utxos_for_address(client, alice.address, 1);
        } else {
            println!("Result contains non-UTF8 bytes");
        }
    }

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

fn main() {
    let big_r = "03ACA6D62D6D74076ED555CC1F76C3B87E49255FB9036806F255A6B3A85E875A12";
    let s = "266777C51..."; // Complete the scalar value

    match create_signature(big_r, s) {
        Ok(signature) => println!("Signature created successfully: {:?}", signature),
        Err(e) => println!("Error creating signature: {:?}", e),
    }
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

async fn get_nonce_and_block_hash(
    client: &JsonRpcClient,
    account_id: AccountId,
    public_key: PublicKey,
) -> Result<(u64, CryptoHash), Box<dyn std::error::Error>> {
    let access_key_query_response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: QueryRequest::ViewAccessKey {
                account_id: account_id.clone(),
                public_key: public_key.clone(),
            },
        })
        .await
        .expect("Failed to call RPC");

    match access_key_query_response.kind {
        QueryResponseKind::AccessKey(access_key) => {
            Ok((access_key.nonce, access_key_query_response.block_hash))
        }
        _ => panic!("Failed to extract current nonce"),
    }
}

fn read_config(filename: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: Config = serde_json::from_str(&contents)?;
    Ok(config)
}

fn setup_bitcoin_testnet() -> Result<bitcoind::BitcoinD, Box<dyn std::error::Error>> {
    if std::env::var("CI_ENVIRONMENT").is_ok() {
        let curr_dir_path = std::env::current_dir().unwrap();

        let bitcoind_path = if cfg!(target_os = "macos") {
            curr_dir_path.join("tests/bin").join("bitcoind-mac")
        } else if cfg!(target_os = "linux") {
            curr_dir_path.join("tests/bin").join("bitcoind-linux")
        } else {
            return Err(
                std::io::Error::new(std::io::ErrorKind::Other, "Unsupported platform").into(),
            );
        };

        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        let mut conf = bitcoind::Conf::default();
        conf.tmpdir = Some(temp_dir.path().to_path_buf());
        let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_path, &conf).unwrap();
        Ok(bitcoind)
    } else {
        let bitcoind = bitcoind::BitcoinD::from_downloaded().unwrap();
        Ok(bitcoind)
    }
}
