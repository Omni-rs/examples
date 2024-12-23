use near_sdk::ext_contract;

#[allow(dead_code)]
#[ext_contract(this_contract)]
trait ThisContract {
    fn callback(&self, ethereum_tx: Vec<u8>);
}
