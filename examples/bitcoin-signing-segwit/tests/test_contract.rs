// Rust Bitcoin Dependencies
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{Message, PublicKey as BitcoinSecp256k1PublicKey, Secp256k1};
use bitcoin::{ScriptBuf as BitcoinScriptBuf, WPubkeyHash};
// NEAR Dependencies
use near_jsonrpc_client::methods;
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::views::TxExecutionStatus;
// Omni Transaction Dependencies
use omni_transaction::bitcoin::types::{
    Amount, LockTime, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Version, Witness,
};
use omni_transaction::bitcoin::BitcoinTransaction;
use omni_transaction::BITCOIN;
use omni_transaction::{TransactionBuilder, TxBuilder};
// OmniBox Dependencies
use omni_box::utils::address::{self, get_uncompressed_bitcoin_pubkey};
use omni_box::utils::signature;
use omni_box::OmniBox;
// Other Dependencies
use serde_json::json;

const OMNI_SPEND_AMOUNT: Amount = Amount::from_sat(500_000);
const PATH: &str = "bitcoin-1";
const MPC_CONTRACT_ACCOUNT: &str = "v1.signer-prod.testnet";

#[tokio::test]
async fn test_sighash_p2wpkh_btc_signing_remote_with_propagation(
) -> Result<(), Box<dyn std::error::Error>> {
    // Start the OmniBox
    let omni_box = OmniBox::new().await;
    let btc_context = &omni_box.btc_context;
    let bob = &btc_context.bob_legacy;

    // Get the derived address of the NEAR contract / deployer account
    let derived_address =
        address::get_derived_address_for_btc_legacy(&omni_box.deployer_account.account_id, PATH);
    let near_contract_script_pubkey = address::get_public_key_hash(&derived_address);

    // Give some BTC (UTXOs) to the NEAR contract
    btc_context.generate_to_derived_address(&derived_address)?;

    // Now we need to get the UTXO of the NEAR contract, we use scantxoutset to get the first UTXO
    let binding = btc_context
        .scan_utxo_for_address_with_count(&derived_address, 1)
        .unwrap();

    let first_unspent_near_contract = binding.first().unwrap();

    // Generate more blocks to avoid issues with confirmations
    btc_context.generate_to_derived_address(&derived_address)?;

    // Create the transaction input
    let near_contract_spending_txin: TxIn = TxIn {
        previous_output: OutPoint::new(
            first_unspent_near_contract.txid,
            first_unspent_near_contract.vout,
        ),
        script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
        sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
        witness: Witness::default(), // Filled in after signing.
    };

    let utxo_amount = first_unspent_near_contract.amount;

    let change_amount: Amount = utxo_amount - OMNI_SPEND_AMOUNT - Amount::from_sat(1000); // 1000 satoshis for fee

    // Create the transaction output
    let near_contract_spending_txout = TxOut {
        value: OMNI_SPEND_AMOUNT,
        script_pubkey: ScriptBuf(bob.script_pubkey.as_bytes().to_vec()),
    };

    // Create the change output
    let near_contract_spending_change_txout = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf(near_contract_script_pubkey.clone()),
    };

    let near_contract_spending_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::Two)
        .lock_time(LockTime::from_height(0).unwrap())
        .inputs(vec![near_contract_spending_txin])
        .outputs(vec![
            near_contract_spending_txout,
            near_contract_spending_change_txout,
        ])
        .build();

    let near_p2wpkh = WPubkeyHash::from_slice(&near_contract_script_pubkey).unwrap();

    let script_pubkey_near_contract = BitcoinScriptBuf::new_p2wpkh(&near_p2wpkh)
        .p2wpkh_script_code()
        .unwrap();

    let near_script_code = ScriptBuf(script_pubkey_near_contract.into_bytes());

    // Call the NEAR contract to generate the sighash
    let method_name = "generate_sighash_p2wpkh";
    let args = json!({
        "bitcoin_tx": near_contract_spending_tx,
        "input_index": 0,
        "script_code":near_script_code,
        "value": OMNI_SPEND_AMOUNT.to_sat()
    });

    let sighash_value = omni_box
        .friendly_near_json_rpc_client
        .call_contract::<Vec<u8>>(method_name, args)
        .await?;

    // Calculate the sighash
    let sighash_omni = sha256d::Hash::hash(&sighash_value);
    let msg_omni = Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();

    let attached_deposit = omni_box.get_experimental_signature_deposit().await?;

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

    // Verify signature
    let secp = Secp256k1::new();

    let public_key_as_bytes = get_public_key_as_bytes(&derived_address);

    let bitcoin_secp256k1_public_key =
        BitcoinSecp256k1PublicKey::from_slice(&public_key_as_bytes).unwrap();

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

    Ok(())
}
