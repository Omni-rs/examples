use near_sdk::ext_contract;
use omni_transaction::evm::evm_transaction::EVMTransaction;

#[allow(dead_code)]
#[ext_contract(this_contract)]
trait ThisContract {
    fn callback(&self, ethereum_tx: EVMTransaction);
}
