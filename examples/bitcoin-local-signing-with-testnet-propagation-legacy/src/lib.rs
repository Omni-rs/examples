use near_sdk::near;

pub mod external;

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {}
