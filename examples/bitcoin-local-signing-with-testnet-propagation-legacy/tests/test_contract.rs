use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::EcdsaSighashType as BitcoinEcdsaSighashType;
use bitcoin::PublicKey;
use bitcoin::{Address, Network};
use omni_box::utils::address;
use omni_box::OmniBox;
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;
use omni_transaction::bitcoin::types::{
    Amount, EcdsaSighashType, Hash as OmniHash, LockTime, OutPoint, ScriptBuf, Sequence,
    TransactionType, TxIn, TxOut, Txid, Version, Witness,
};
use omni_transaction::transaction_builder::{TransactionBuilder, TxBuilder};
use omni_transaction::types::BITCOIN;
use reqwest::Client;
use std::str::FromStr;

const PATH: &str = "bitcoin-1";

#[tokio::test]
async fn test_sighash_p2pkh_btc_signing_remote_with_propagation(
) -> Result<(), Box<dyn std::error::Error>> {
    // The phrase to generate the seed
    let phrase = "blame fall flame require shift similar square drive pass credit gold web tonight turn fine";

    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, phrase).expect("Invalid Mnemonic");

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

    // 3. Generate the legacy address (P2PKH)
    let address = Address::p2pkh(pubkey, Network::Testnet);
    println!("Legacy Address (P2PKH): {:?}", address);

    let omni_box = OmniBox::new().await;

    // Get the derived address of the NEAR contract / deployer account
    let derived_address =
        address::get_derived_address_for_btc_legacy(&omni_box.deployer_account.account_id, PATH);

    println!(
        "Derived Address of Contract Account: {:?}",
        derived_address.address
    );

    let tx_id_str = "e9e5a1adf897fc7488d89afe1f862a61ad4c738ecca94b877f71c32ce7bef3f3";
    let tx_id = OmniHash::from_hex(tx_id_str).unwrap();
    let vout = 1;
    let previous_output = OutPoint::new(Txid(tx_id), vout);

    let tx_in: TxIn = TxIn {
        previous_output,
        script_sig: ScriptBuf::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    let utxo_amount = Amount::from_sat(51705);
    let amount_to_spend = Amount::from_sat(30000); // 0.00030000 tBTC
    let change_amount: Amount = utxo_amount - amount_to_spend - Amount::from_sat(1000); // 1000 satoshis for fee

    // The script_pub_key of the NEAR contract account
    let contract_script_pub_key: ScriptBuf =
        ScriptBuf::from_hex("76a914b14da44077bd985df6eb9aa04fd18322a85ba30188ac").unwrap(); // TODO: Fix this

    let sender_pub_key =
        ScriptBuf::from_hex("76a9142dc9b23fccc8935d0e4fe5b69d80302a7d41118d88ac").unwrap();

    // Create the transaction output for the receiver
    let spending_txout = TxOut {
        value: amount_to_spend,
        // n19iEMJE2L2YBfJFsXC8Gzs7Q2Z7TwdCqv (the derived address of the NEAR contract account)
        script_pubkey: contract_script_pub_key.clone(),
    };

    // Create the transaction output for the change (sender)
    let change_txout = TxOut {
        value: change_amount,
        // mjh4Knmu8w3HYBrP4SGk6bXULj1QyaQ5dR (the derived address of the account I derive from the seed phrase)
        script_pubkey: sender_pub_key.clone(),
    };

    let mut spending_tx: BitcoinTransaction = TransactionBuilder::new::<BITCOIN>()
        .version(Version::One)
        .lock_time(LockTime::from_height(0).unwrap())
        .inputs(vec![tx_in])
        .outputs(vec![spending_txout, change_txout])
        .build();

    // --------------------------------------------
    // This is using the client code
    // --------------------------------------------

    // Add the script_sig to the transaction
    spending_tx.input[0].script_sig = sender_pub_key;

    // Encode the transaction for signing
    let sighash_type = EcdsaSighashType::All;
    let encoded_data = spending_tx.build_for_signing_legacy(sighash_type);

    // Calculate the sighash
    let sighash_omni = sha256d::Hash::hash(&encoded_data);
    let msg_omni = Message::from_digest_slice(sighash_omni.as_byte_array()).unwrap();

    // Sign the sighash and broadcast the transaction using the Omni library
    let secp = Secp256k1::new();
    let signature_omni = secp.sign_ecdsa(&msg_omni, &child_key.private_key);

    // Verify signature
    let is_valid = secp
        .verify_ecdsa(&msg_omni, &signature_omni, &pubkey.inner)
        .is_ok();

    println!("The signature should be valid: {:?}", is_valid);

    assert!(is_valid, "The signature should be valid");

    // Encode the signature
    let signature = bitcoin::ecdsa::Signature {
        signature: signature_omni,
        sighash_type: BitcoinEcdsaSighashType::All,
    };

    // Create the script_sig
    let script_sig_new = Builder::new()
        .push_slice(signature.serialize())
        .push_key(&pubkey)
        .into_script();

    // Assign script_sig to txin
    let omni_script_sig = ScriptBuf(script_sig_new.as_bytes().to_vec());
    let encoded_omni_tx =
        spending_tx.build_with_script_sig(0, omni_script_sig, TransactionType::P2PKH);

    // Convert the transaction to a hexadecimal string
    let raw_tx_hex = hex::encode(encoded_omni_tx);
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
