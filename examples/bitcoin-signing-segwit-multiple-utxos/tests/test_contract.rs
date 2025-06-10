// Rust Bitcoin Dependencies
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{Message, PublicKey as BitcoinSecp256k1PublicKey, Secp256k1};
use bitcoin::{ScriptBuf as BitcoinScriptBuf, WPubkeyHash};
// NEAR Dependencies
use near_primitives::action::{Action, FunctionCallAction};
// Omni Transaction Dependencies
use omni_transaction::bitcoin::types::{
    Amount, Hash as OmniHash, LockTime, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Version,
    Witness,
};
use omni_transaction::bitcoin::BitcoinTransaction;
use omni_transaction::{TransactionBuilder, TxBuilder, BITCOIN};
// OmniBox Dependencies
use omni_box::utils::address::{self};
use omni_box::utils::signature;
use omni_box::OmniBox;
// Other Dependencies
use futures::future::join_all;
use serde_json::json;

const OMNI_SPEND_AMOUNT: Amount = Amount::from_sat(500_000);
const PATH: &str = "bitcoin-1";

#[tokio::test]
async fn test_sighash_p2wpkh_btc_multiple_signing_remote() -> Result<(), Box<dyn std::error::Error>>
{
    // Start the OmniBox
    let omni_box = OmniBox::new().await;
    let btc_test_context = &omni_box.btc_context;
    let bob = &btc_test_context.bob_legacy;

    // Get the derived address of the NEAR contract
    let derived_address =
        address::get_derived_address_for_btc_legacy(&omni_box.deployer_account.account_id, PATH);
    let public_key_hash = address::get_public_key_hash(&derived_address);

    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;
    btc_test_context.generate_to_derived_address(&derived_address)?;

    // Now we need to get the UTXO of the NEAR contract, we use scantxoutset to get the first UTXO
    let unspent_utxos = btc_test_context
        .scan_utxo_for_address_with_count(&derived_address, 5)
        .unwrap();

    // Generate more blocks to avoid issues with confirmations
    btc_test_context.generate_to_derived_address(&derived_address)?;

    let mut inputs = Vec::new();
    let mut total_utxo_amount = 0;

    for unspent in &unspent_utxos {
        // Build the transaction where the sender is the derived address
        let near_contract_spending_txid_str = unspent.txid.to_string();
        let near_contract_spending_hash =
            OmniHash::from_hex(&near_contract_spending_txid_str).unwrap();
        let near_contract_spending_txid = Txid(near_contract_spending_hash);
        let near_contract_spending_vout = unspent.vout;

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

        let utxo_amount = Amount::from_sat(unspent.amount.to_sat());

        total_utxo_amount += utxo_amount.to_sat();
    }

    let change_amount: Amount =
        Amount::from_sat(total_utxo_amount) - OMNI_SPEND_AMOUNT - Amount::from_sat(1000); // 1000 satoshis for fee

    let near_p2wpkh = WPubkeyHash::from_slice(&public_key_hash).unwrap();

    // The change output is locked to a key controlled by us.
    let change_txout = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf(BitcoinScriptBuf::new_p2wpkh(&near_p2wpkh).into_bytes()),
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

    let futures = unspent_utxos.iter().enumerate().map(|(i, unspent)| {
        let _utxo_amount = Amount::from_sat(unspent.amount.to_sat());

        let script_pub_key = BitcoinScriptBuf::new_p2wpkh(&near_p2wpkh);
        let script_pubkey_near = script_pub_key.p2wpkh_script_code().unwrap();
        let script_code = ScriptBuf(script_pubkey_near.into_bytes());

        // Call the NEAR contract to generate the sighash
        let method_name = "generate_sighash_p2wpkh";

        let args = json!({
            "bitcoin_tx": near_contract_spending_tx,
            "input_index": i,
            "script_code":script_code,
            "value": OMNI_SPEND_AMOUNT.to_sat()
        });

        (method_name, args)
    });

    let responses = join_all(futures.map(|(method_name, args)| {
        omni_box
            .friendly_near_json_rpc_client
            .call_contract::<Vec<u8>>(method_name, args)
    }))
    .await;
    let mut actions = Vec::new();
    let mut sighhashes_messages = Vec::new();

    for response in responses {
        let sighash_omni = sha256d::Hash::hash(response.unwrap().as_slice());
        let msg_omni = Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();
        sighhashes_messages.push(msg_omni);

        let attached_deposit: u128 = 1;

        // Create the args for the sign_sighash_p2pkh method
        let args = json!({
            "sighash_p2wpkh": hex::encode(msg_omni.as_ref()),
            "attached_deposit": attached_deposit.to_string()
        });

        // Create the action
        let signing_action = Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: "sign_sighash_p2wpkh".to_string(),
            args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
            gas: 60_000_000_000_000,
            deposit: 100000000000000,
        }));

        actions.push(signing_action);
    }

    // Send the transaction using the actions created
    let signer_response = omni_box
        .friendly_near_json_rpc_client
        .send_actions(actions)
        .await?;

    println!("signer_response: {:?}", signer_response);

    let signatures = signature::extract_multiple_signatures(&signer_response).unwrap();

    for (index, (big_r, s)) in signatures.iter().enumerate() {
        println!("Verifying signature {}", index);

        // Build the signature
        let signature_built = signature::create_signature(big_r, s);

        // Verify signature
        let secp = Secp256k1::new();

        let public_key_as_bytes = address::get_public_key_as_bytes(&derived_address);

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
