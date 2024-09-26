use near_sdk::near;
use omni_transaction::bitcoin::types::{
    Amount, EcdsaSighashType, Hash, LockTime, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid,
    Version, Witness,
};
use omni_transaction::transaction_builder::TransactionBuilder;
use omni_transaction::transaction_builder::TxBuilder;
use omni_transaction::types::BITCOIN;

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    pub fn sighash_p2pkh(&self) -> Vec<u8> {
        let txid_str = "2ece6cd71fee90ff613cee8f30a52c3ecc58685acf9b817b9c467b7ff199871c";
        let hash = Hash::from_hex(txid_str).unwrap();
        let txid = Txid(hash);
        let vout = 0;

        let txin: TxIn = TxIn {
            previous_output: OutPoint::new(txid, vout as u32),
            script_sig: ScriptBuf::default(), // For a p2pkh script_sig is initially empty.
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let sender_script_pubkey_hex = "76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac";
        let sender_script_pubkey = ScriptBuf(sender_script_pubkey_hex.as_bytes().to_vec());

        let receiver_script_pubkey_hex = "76a914406cf8a18b97a230d15ed82f0d251560a05bda0688ac";
        let receiver_script_pubkey = ScriptBuf(receiver_script_pubkey_hex.as_bytes().to_vec());

        // The spend output is locked to a key controlled by the receiver.
        let spend_txout: TxOut = TxOut {
            value: Amount::from_sat(500_000_000),
            script_pubkey: receiver_script_pubkey,
        };

        let change_txout = TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: sender_script_pubkey,
        };

        let bitcoin_tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::One)
            .inputs(vec![txin])
            .outputs(vec![spend_txout, change_txout])
            .lock_time(LockTime::from_height(0).unwrap())
            .build();

        bitcoin_tx.build_for_signing_legacy(EcdsaSighashType::All)
    }

    pub fn sighash_p2wpkh(&self) -> Vec<u8> {
        let txid_str = "2ece6cd71fee90ff613cee8f30a52c3ecc58685acf9b817b9c467b7ff199871c";
        let hash = Hash::from_hex(txid_str).unwrap();
        let txid = Txid(hash);
        let vout = 0;

        let txin: TxIn = TxIn {
            previous_output: OutPoint::new(txid, vout as u32),
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        };

        let sender_script_pubkey_hex = "76a914cb8a3018cf279311b148cb8d13728bd8cbe95bda88ac";
        let sender_script_pubkey = ScriptBuf(sender_script_pubkey_hex.as_bytes().to_vec());

        let receiver_script_pubkey_hex = "76a914406cf8a18b97a230d15ed82f0d251560a05bda0688ac";
        let receiver_script_pubkey = ScriptBuf(receiver_script_pubkey_hex.as_bytes().to_vec());

        // The spend output is locked to a key controlled by the receiver.
        let spend_txout: TxOut = TxOut {
            value: Amount::from_sat(500_000_000),
            script_pubkey: receiver_script_pubkey.clone(),
        };

        let change_txout = TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: sender_script_pubkey,
        };

        let bitcoin_tx = TransactionBuilder::new::<BITCOIN>()
            .version(Version::Two)
            .inputs(vec![txin])
            .outputs(vec![spend_txout, change_txout])
            .lock_time(LockTime::from_height(0).unwrap())
            .build();

        // Prepare the transaction for signing
        let sighash_type = EcdsaSighashType::All;
        let input_index = 0;
        let encoded_data = bitcoin_tx.build_for_signing_segwit(
            sighash_type,
            input_index,
            &receiver_script_pubkey,
            Amount::from_sat(500_000_000).to_sat(),
        );

        encoded_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sighash_p2pkh() {
        let contract = Contract::default();

        let sighash_p2pkh = contract.sighash_p2pkh();

        println!("sighash_p2pkh: {:?}", sighash_p2pkh);

        let expected_data = vec![
            1, 0, 0, 0, 1, 28, 135, 153, 241, 127, 123, 70, 156, 123, 129, 155, 207, 90, 104, 88,
            204, 62, 44, 165, 48, 143, 238, 60, 97, 255, 144, 238, 31, 215, 108, 206, 46, 0, 0, 0,
            0, 0, 255, 255, 255, 255, 2, 0, 101, 205, 29, 0, 0, 0, 0, 50, 55, 54, 97, 57, 49, 52,
            52, 48, 54, 99, 102, 56, 97, 49, 56, 98, 57, 55, 97, 50, 51, 48, 100, 49, 53, 101, 100,
            56, 50, 102, 48, 100, 50, 53, 49, 53, 54, 48, 97, 48, 53, 98, 100, 97, 48, 54, 56, 56,
            97, 99, 0, 225, 245, 5, 0, 0, 0, 0, 50, 55, 54, 97, 57, 49, 52, 99, 98, 56, 97, 51, 48,
            49, 56, 99, 102, 50, 55, 57, 51, 49, 49, 98, 49, 52, 56, 99, 98, 56, 100, 49, 51, 55,
            50, 56, 98, 100, 56, 99, 98, 101, 57, 53, 98, 100, 97, 56, 56, 97, 99, 0, 0, 0, 0, 1,
            0, 0, 0,
        ];

        assert!(!sighash_p2pkh.is_empty());
        assert_eq!(sighash_p2pkh, expected_data);
    }

    #[test]
    fn test_sighash_p2wpkh() {
        let contract = Contract::default();

        let sighash_p2wpkh = contract.sighash_p2wpkh();

        println!("sighash_p2wpkh: {:?}", sighash_p2wpkh);

        let expected_data = vec![
            2, 0, 0, 0, 190, 19, 35, 27, 24, 80, 118, 238, 28, 58, 96, 102, 217, 33, 170, 218, 166,
            161, 96, 97, 97, 101, 9, 116, 240, 177, 223, 37, 186, 193, 117, 136, 59, 177, 48, 41,
            206, 123, 31, 85, 158, 245, 231, 71, 252, 172, 67, 159, 20, 85, 162, 236, 124, 95, 9,
            183, 34, 144, 121, 94, 112, 102, 80, 68, 28, 135, 153, 241, 127, 123, 70, 156, 123,
            129, 155, 207, 90, 104, 88, 204, 62, 44, 165, 48, 143, 238, 60, 97, 255, 144, 238, 31,
            215, 108, 206, 46, 0, 0, 0, 0, 50, 55, 54, 97, 57, 49, 52, 52, 48, 54, 99, 102, 56, 97,
            49, 56, 98, 57, 55, 97, 50, 51, 48, 100, 49, 53, 101, 100, 56, 50, 102, 48, 100, 50,
            53, 49, 53, 54, 48, 97, 48, 53, 98, 100, 97, 48, 54, 56, 56, 97, 99, 0, 101, 205, 29,
            0, 0, 0, 0, 255, 255, 255, 255, 51, 246, 62, 154, 157, 45, 168, 65, 30, 226, 118, 42,
            92, 251, 84, 198, 60, 11, 30, 24, 93, 54, 136, 124, 222, 114, 103, 35, 173, 53, 186,
            251, 0, 0, 0, 0, 1, 0, 0, 0,
        ];

        assert!(!sighash_p2wpkh.is_empty());
        assert_eq!(sighash_p2wpkh, expected_data);
    }
}
