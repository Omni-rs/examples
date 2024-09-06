use omni_transaction::{
    near::{
        types::{AccessKey, AccessKeyPermission, Action, AddKeyAction, TransferAction, U128, U64},
        utils::PublicKeyStrExt,
    },
    transaction_builder::{TransactionBuilder, TxBuilder},
    types::NEAR,
};
use serde_json::json;

#[tokio::test]
async fn test_simple_encoding_with_args_for_near() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = near_workspaces::sandbox().await?;
    let contract_wasm = near_workspaces::compile_project("./").await?;

    let contract = sandbox.dev_deploy(&contract_wasm).await?;

    let signer_id = "forgetful-parent.testnet";
    let signer_public_key = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp"
        .to_public_key()
        .unwrap();

    let nonce = 1;
    let receiver_id = "forgetful-parent.testnet";
    let block_hash = "4reLvkAWfqk5fsqio1KLudk46cqRz9erQdaHkWZKMJDZ";
    let block_hash_as_bytes = block_hash.to_block_hash().unwrap();

    let transfer_action = Action::Transfer(TransferAction { deposit: U128(1) });
    let add_key_action = Action::AddKey(Box::new(AddKeyAction {
        public_key: signer_public_key.clone(),
        access_key: AccessKey {
            nonce: U64(0),
            permission: AccessKeyPermission::FullAccess,
        },
    }));

    let actions = vec![transfer_action, add_key_action];

    let near_tx = TransactionBuilder::new::<NEAR>()
        .signer_id(signer_id.to_string())
        .signer_public_key(signer_public_key)
        .nonce(nonce)
        .receiver_id(receiver_id.to_string())
        .block_hash(block_hash_as_bytes)
        .actions(actions)
        .build();

    let view_result = contract
        .view("get_transaction_encoded_data")
        .args_json(json!({
            "near_tx_params": near_tx
        }))
        .await?;

    let transaction_encoded_data: Vec<u8> = serde_json::from_slice(&view_result.result)?;

    let expected_data = vec![
        24, 0, 0, 0, 102, 111, 114, 103, 101, 116, 102, 117, 108, 45, 112, 97, 114, 101, 110, 116,
        46, 116, 101, 115, 116, 110, 101, 116, 0, 77, 167, 224, 244, 9, 106, 175, 44, 229, 94, 55,
        22, 87, 205, 48, 137, 186, 30, 159, 89, 244, 214, 226, 123, 208, 46, 71, 42, 22, 166, 29,
        193, 1, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 102, 111, 114, 103, 101, 116, 102, 117, 108, 45,
        112, 97, 114, 101, 110, 116, 46, 116, 101, 115, 116, 110, 101, 116, 57, 74, 190, 179, 94,
        112, 118, 9, 222, 143, 115, 182, 61, 67, 189, 26, 55, 111, 254, 103, 147, 92, 170, 104,
        147, 125, 210, 155, 192, 78, 103, 60, 2, 0, 0, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 5, 0, 77, 167, 224, 244, 9, 106, 175, 44, 229, 94, 55, 22, 87, 205, 48, 137, 186,
        30, 159, 89, 244, 214, 226, 123, 208, 46, 71, 42, 22, 166, 29, 193, 0, 0, 0, 0, 0, 0, 0, 0,
        1,
    ];

    assert_eq!(transaction_encoded_data, expected_data);

    Ok(())
}
