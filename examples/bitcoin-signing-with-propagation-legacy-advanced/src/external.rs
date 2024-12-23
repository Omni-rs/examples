use near_sdk::ext_contract;
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;

#[allow(dead_code)]
#[ext_contract(this_contract)]
trait ThisContract {
    fn callback(&self, bitcoin_tx: BitcoinTransaction, bitcoin_pubkey: Vec<u8>);
}
