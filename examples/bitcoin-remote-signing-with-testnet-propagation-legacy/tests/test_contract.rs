use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::PublicKey;
use bitcoin::{Address, Network};
use hex;
use near_primitives::action::FunctionCallAction;
use omni_box::utils::address::get_uncompressed_bitcoin_pubkey;
use omni_box::utils::{address, signature};
use omni_box::OmniBox;
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{
    Amount, Hash as OmniHash, LockTime, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Version,
    Witness,
};
use omni_transaction::transaction_builder::{TransactionBuilder, TxBuilder};
use omni_transaction::types::BITCOIN;
use reqwest::Client;

use serde_json::json;
use std::str::FromStr;

const PATH: &str = "bitcoin-1";

#[tokio::test]
async fn test_sighash_p2pkh_btc_signing_remote_with_propagation(
) -> Result<(), Box<dyn std::error::Error>> {
    // The phrase to generate the seed
    let phrase = "blame fall flame require shift similar square drive pass credit gold web tonight turn fine";

    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, &phrase).expect("Invalid Mnemonic");

    let seed = mnemonic.to_seed("");

    // Generate the extended private key
    let xpriv =
        Xpriv::new_master(Network::Testnet, &seed).expect("Error generating extended private key");

    println!("XPriv: {:?}", xpriv);

    println!("Path: {:?}", PATH);

    let derivation_path = DerivationPath::from_str("m/44'/1'/0'/0/0").expect("Invalid route");

    println!("Derivation Path: {:?}", derivation_path);

    // Derive the child private key
    let secp = Secp256k1::new();
    let child_key = xpriv
        .derive_priv(&secp, &derivation_path)
        .expect("Error deriving child key");

    // Convert secp256k1::PublicKey to bitcoin::PublicKey
    let pubkey = PublicKey::new(child_key.private_key.public_key(&secp));

    // Generate the legacy address of the receiver (P2PKH)
    let address = Address::p2pkh(&pubkey, Network::Testnet);
    println!("Legacy Address (P2PKH): {:?}", address);

    let omni_box: OmniBox = OmniBox::new().await;

    // Get the derived address of the NEAR contract / deployer account
    let derived_address =
        address::get_derived_address_for_btc_legacy(&omni_box.deployer_account.account_id, PATH);

    println!(
        "BTC Legacy Derived Address of Contract Account: {:?}",
        derived_address.address
    );

    let near_contract_script_pubkey = address::get_script_pub_key(&derived_address);

    println!(
        "NEAR Contract Account Script Pub Key: {:?}",
        near_contract_script_pubkey
    );

    println!(
        "NEAR Contract Account Script Pub Key Hex: {:?}",
        hex::encode(near_contract_script_pubkey.clone())
    );

    // https://blockstream.info/testnet/tx/dd8943dea7df0a1b6687a4136b83a588a19f08a54875592915b5e02bfe3a58b8
    let tx_id_str = "dd8943dea7df0a1b6687a4136b83a588a19f08a54875592915b5e02bfe3a58b8";
    let tx_id = OmniHash::from_hex(tx_id_str).unwrap();
    let vout = 1;
    let previous_output = OutPoint::new(Txid(tx_id), vout);

    let tx_in: TxIn = TxIn {
        previous_output,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    let utxo_amount = Amount::from_sat(27668);
    let amount_to_spend = Amount::from_sat(3000); // 0.00003000 tBTC
    let change_amount: Amount = utxo_amount - amount_to_spend - Amount::from_sat(1000); // 1000 satoshis for fee

    // The script_pub_key of the NEAR contract account
    let contract_script_pub_key: ScriptBuf = ScriptBuf::from_bytes(near_contract_script_pubkey);

    let receiver_pub_key =
        ScriptBuf::from_hex("76a9142dc9b23fccc8935d0e4fe5b69d80302a7d41118d88ac").unwrap();

    // Create the transaction output for the receiver
    let spending_txout = TxOut {
        value: amount_to_spend,
        // mjh4Knmu8w3HYBrP4SGk6bXULj1QyaQ5dR (the derived address of the account I derive from the seed phrase)
        script_pubkey: receiver_pub_key.clone(),
    };

    // Create the transaction output for the change (sender)
    let change_txout = TxOut {
        value: change_amount,
        // n19iEMJE2L2YBfJFsXC8Gzs7Q2Z7TwdCqv (the derived address of the NEAR contract account)
        script_pubkey: contract_script_pub_key.clone(),
    };

    let mut spending_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::One)
        .lock_time(LockTime::from_height(0).unwrap())
        .inputs(vec![tx_in])
        .outputs(vec![spending_txout, change_txout])
        .build();

    let public_key_as_bytes = get_uncompressed_bitcoin_pubkey(&derived_address);

    // Add the script_sig to the transaction
    spending_tx.input[0].script_sig = contract_script_pub_key;

    let attached_deposit = omni_box.get_experimental_signature_deposit().await?;

    let args = json!({
        "bitcoin_tx": spending_tx,
        "bitcoin_pubkey": public_key_as_bytes,
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

    println!("Signer Response: {:?}", signer_response);

    // extract the payload
    let hex_omni_tx = signature::extract_signed_transaction(&signer_response).unwrap();

    // Convert the transaction to a hexadecimal string
    let raw_tx_hex = hex::encode(hex_omni_tx);
    println!("Raw Transaction Hex: {}", raw_tx_hex);

    // Now we propagate it
    let client = Client::new();
    let response = client
        .post("https://blockstream.info/testnet/api/tx")
        .body(raw_tx_hex)
        .send()
        .await?;

    if response.status().is_success() {
        println!("Transaction propagated successfully!");
    } else {
        eprintln!(
            "Failed to propagate transaction: {:?}",
            response.text().await?
        );
    }

    Ok(())
}
