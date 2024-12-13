// Near dependencies
use near_primitives::action::FunctionCallAction;
// Omni Transaction Dependencies
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{
    Amount, LockTime, OutPoint, ScriptBuf, Sequence, TransactionType, TxIn, TxOut, Version, Witness,
};
use omni_transaction::transaction_builder::{TransactionBuilder, TxBuilder};
use omni_transaction::types::BITCOIN;
// OmniBox Dependencies
use omni_box::utils::{address, signature};
use omni_box::OmniBox;
// Other Dependencies
use serde_json::json;

const OMNI_SPEND_AMOUNT: Amount = Amount::from_sat(500_000);
const PATH: &str = "bitcoin-1";

#[tokio::test]
async fn test_sighash_p2pkh_btc_signing_remote_with_propagation(
) -> Result<(), Box<dyn std::error::Error>> {
    // Start the OmniBox
    let omni_box = OmniBox::new().await;
    let btc_context = &omni_box.btc_context;
    let bob = &btc_context.bob_legacy;

    // Get the derived address of the NEAR contract / deployer account
    let derived_address =
        address::get_derived_address_for_btc_legacy(&omni_box.deployer_account.account_id, PATH);
    let near_contract_script_pubkey = address::get_script_pub_key(&derived_address);

    // Give some BTC (UTXOs) to the NEAR contract
    btc_context.generate_to_derived_address(&derived_address)?;

    // We scan and get the UTXO of the NEAR contract
    let unspent_near_contracts = btc_context
        .scan_utxo_for_address_with_count(&derived_address, 1)
        .unwrap();

    let first_unspent_near_contract = unspent_near_contracts.first().unwrap();

    // Give UTXOs again to avoid confirmations issues
    btc_context.generate_to_derived_address(&derived_address)?;

    // Create the transaction input
    let near_contract_spending_txin: TxIn = TxIn {
        previous_output: OutPoint::new(
            first_unspent_near_contract.txid,
            first_unspent_near_contract.vout,
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

    let change_amount: Amount =
        first_unspent_near_contract.amount - OMNI_SPEND_AMOUNT - Amount::from_sat(1000); // 1000 satoshis for fee

    let near_contract_spending_change_txout = TxOut {
        value: change_amount,
        script_pubkey: ScriptBuf(near_contract_script_pubkey.clone()),
    };

    let mut near_contract_spending_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::One)
        .lock_time(LockTime::from_height(0).unwrap())
        .inputs(vec![near_contract_spending_txin])
        .outputs(vec![
            near_contract_spending_txout,
            near_contract_spending_change_txout,
        ])
        .build();

    // We add the script_pubkey of the NEAR contract as the script_sig
    near_contract_spending_tx.input[0].script_sig = ScriptBuf(near_contract_script_pubkey);

    let attached_deposit = omni_box.get_experimental_signature_deposit().await?;

    let args = json!({
        "bitcoin_tx": near_contract_spending_tx,
        "attached_deposit": attached_deposit.to_string()
    });

    let signer_response = omni_box
        .friendly_near_json_rpc_client
        .send_action(FunctionCallAction {
            method_name: "create_sighash_and_sign_p2pkh".to_string(),
            args: args.to_string().into_bytes(), // Convert directly to Vec<u8>
            gas: 300000000000000,
            deposit: 1000000000000000000000000,
        })
        .await?;

    println!("signer_response: {:?}", signer_response);

    // let (big_r, s) = signature::extract_big_r_and_s(&signer_response).unwrap();
    // let signature_built = signature::create_signature(&big_r, &s);

    // Encode the signature
    // let signature = bitcoin::ecdsa::Signature {
    //     signature: signature_built.unwrap(),
    //     sighash_type: bitcoin::EcdsaSighashType::All,
    // };

    // Build the script sig
    // let script_sig_new = address::build_script_sig_as_bytes(derived_address, signature);

    // // Assign script_sig to txin
    // let omni_script_sig = ScriptBuf(script_sig_new);

    // // Encode the transaction with the script sig
    // let encoded_omni_tx =
    //     near_contract_spending_tx.build_with_script_sig(0, omni_script_sig, TransactionType::P2PKH);

    // // Convert the transaction to a hexadecimal string
    // let hex_omni_tx = hex::encode(encoded_omni_tx);
    // let maxfeerate = 0.10;
    // let maxburnamount = 10.00;

    // // We now deploy to the bitcoin network (regtest mode)
    // let raw_tx_result: serde_json::Value = btc_context
    //     .client()
    //     .call(
    //         "sendrawtransaction",
    //         &[json!(hex_omni_tx), json!(maxfeerate), json!(maxburnamount)],
    //     )
    //     .unwrap();

    // println!("raw_tx_result: {:?}", raw_tx_result);

    Ok(())
}
