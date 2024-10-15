use std::fs::File;
use std::io::Read;

use near_crypto::{PublicKey, SecretKey};
use near_sdk::AccountId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct ConfigJSON {
    account_id: String,
    private_key: String,
    public_key: String,
}

#[derive(Debug)]
pub struct Config {
    pub account_id: AccountId,
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

const DEFAULT_CONFIG_FILE_PATH: &str = "config.json";

pub fn get_user_account_info_from_file(
    config_file_path: Option<&str>,
) -> Result<Config, Box<dyn std::error::Error>> {
    let path = config_file_path.unwrap_or(DEFAULT_CONFIG_FILE_PATH);
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: ConfigJSON = serde_json::from_str(&contents)?;

    let account_id: AccountId = config.account_id.parse().unwrap();
    let private_key: SecretKey = config.private_key.parse().unwrap();
    let public_key: PublicKey = config.public_key.parse().unwrap();

    Ok(Config {
        account_id,
        private_key,
        public_key,
    })
}
