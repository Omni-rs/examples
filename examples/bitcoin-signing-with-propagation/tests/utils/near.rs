use near_crypto::{InMemorySigner, PublicKey};
use near_jsonrpc_client::methods::tx::{RpcTransactionError, TransactionInfo};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::action::{Action, DeployContractAction};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{Transaction, TransactionV0};
use near_primitives::types::BlockReference;
use near_primitives::views::{QueryRequest, TxExecutionStatus};
use near_sdk::AccountId;
use std::time::{Duration, Instant};

use super::environment::Config;

const NEAR_RPC_TESTNET: &str = "https://rpc.testnet.near.org";

pub fn get_near_rpc_client() -> JsonRpcClient {
    JsonRpcClient::connect(NEAR_RPC_TESTNET)
}

pub async fn compile_and_deploy_contract(
    user_account: &Config,
    signer: &InMemorySigner,
    near_json_rpc_client: &JsonRpcClient,
) -> Result<(), Box<dyn std::error::Error>> {
    // Compile the contract
    let contract_wasm = near_workspaces::compile_project("./").await?;

    // Get the block hash and nonce
    let result = get_nonce_and_block_hash(
        &near_json_rpc_client,
        user_account.account_id.clone(),
        user_account.public_key.clone(),
    )
    .await;

    let (nonce, block_hash) = result.unwrap();

    let nonce = nonce + 1;

    // Create the deploy transaction
    let deploy_action = Action::DeployContract(DeployContractAction {
        code: contract_wasm,
    });

    let near_tx: Transaction = Transaction::V0(TransactionV0 {
        signer_id: user_account.account_id.clone(),
        public_key: signer.public_key(),
        nonce,
        receiver_id: user_account.account_id.clone(),
        block_hash,
        actions: vec![deploy_action],
    });

    let signer = &signer.clone().into();

    // Sign and send the transaction
    let request = methods::send_tx::RpcSendTransactionRequest {
        signed_transaction: near_tx.sign(signer),
        wait_until: TxExecutionStatus::Final,
    };

    let _ = send_transaction(&near_json_rpc_client, request).await?;

    println!("Contract deployed");

    Ok(())
}

pub async fn get_nonce_and_block_hash(
    client: &JsonRpcClient,
    account_id: AccountId,
    public_key: PublicKey,
) -> Result<(u64, CryptoHash), Box<dyn std::error::Error>> {
    let access_key_query_response = client
        .call(methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: QueryRequest::ViewAccessKey {
                account_id: account_id.clone(),
                public_key: public_key.clone(),
            },
        })
        .await
        .expect("Failed to call RPC");

    match access_key_query_response.kind {
        QueryResponseKind::AccessKey(access_key) => {
            Ok((access_key.nonce, access_key_query_response.block_hash))
        }
        _ => panic!("Failed to extract current nonce"),
    }
}

pub async fn send_transaction(
    client: &JsonRpcClient,
    request: methods::send_tx::RpcSendTransactionRequest,
) -> Result<
    near_jsonrpc_primitives::types::transactions::RpcTransactionResponse,
    Box<dyn std::error::Error>,
> {
    let sent_at: Instant = Instant::now();

    match client.call(request.clone()).await {
        Ok(response) => Ok(response),
        Err(err) => {
            if matches!(err.handler_error(), Some(RpcTransactionError::TimeoutError)) {
                let tx_hash = request.signed_transaction.get_hash();
                let sender_account_id = request.signed_transaction.transaction.signer_id().clone();
                wait_for_transaction(client, tx_hash, sender_account_id, sent_at).await
            } else {
                Err(err.into())
            }
        }
    }
}

const TIMEOUT: Duration = Duration::from_secs(300);

pub async fn wait_for_transaction(
    client: &JsonRpcClient,
    tx_hash: CryptoHash,
    sender_account_id: AccountId,
    sent_at: Instant,
) -> Result<
    near_jsonrpc_primitives::types::transactions::RpcTransactionResponse,
    Box<dyn std::error::Error>,
> {
    loop {
        let response = client
            .call(methods::tx::RpcTransactionStatusRequest {
                transaction_info: TransactionInfo::TransactionId {
                    tx_hash,
                    sender_account_id: sender_account_id.clone(),
                },
                wait_until: TxExecutionStatus::Final,
            })
            .await;

        if sent_at.elapsed() > TIMEOUT {
            return Err("Time limit exceeded for the transaction to be recognized".into());
        }

        match response {
            Ok(response) => {
                return Ok(response);
            }
            Err(err) => {
                if matches!(err.handler_error(), Some(RpcTransactionError::TimeoutError)) {
                    continue;
                }
                return Err(err.into());
            }
        }
    }
}
