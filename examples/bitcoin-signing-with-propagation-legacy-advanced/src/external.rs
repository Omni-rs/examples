use crate::types::SignRequest;
use near_sdk::ext_contract;
use near_sdk::NearToken;
use omni_transaction::bitcoin::bitcoin_transaction::BitcoinTransaction;

#[allow(dead_code)]
#[ext_contract(mpc_contract)]
trait MPCContract {
    fn sign(&self, request: SignRequest);
    fn experimental_signature_deposit(&self) -> NearToken;
}

#[allow(dead_code)]
#[ext_contract(this_contract)]
trait ThisContract {
    fn callback(&self, bitcoin_tx: BitcoinTransaction, bitcoin_pubkey: Vec<u8>);
}
