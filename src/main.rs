pub mod checkpoints;
pub mod eventlogs;
pub mod instantiations;
pub mod recovering_trie;
pub mod restore_contract_certain; // <-- Uses memory state to rebuild the mpt and check root hash
pub mod restore_contract_uncertain; // <-- Uses geth proofs
pub mod solidity_memory;
pub mod storage_utils;
pub mod utils;

use alloy_rpc_types::Header;
use dotenv::dotenv;
use instantiations::ierc20::{
  CertainMemoryHandler, IERC20MemoryHandler, IERC20MemoryHandlerCertain,
};
use instantiations::{shib::SHIBMemoryUpdates, usdt::USDTMemoryUpdates, wbtc::WBTCMemoryUpdates};
use reth_primitives::{Block, Receipt, Transaction};
use reth_rpc_api::EthApiClient;
use std::sync::Arc;
use utils::ThreadSafeError;

use jsonrpsee::http_client::HttpClientBuilder;
use std::env;

#[tokio::main]
async fn main() -> Result<(), ThreadSafeError> {
  dotenv().ok(); // Load the .env file
  let geth_url = env::var("GETH_URL").expect("Infura URL must be set");
  // alcht_yItiKw7kj3D5q5WJEudPbZzhOw5GcQ
  let client: Arc<jsonrpsee::http_client::HttpClient> =
    Arc::new(HttpClientBuilder::default().build(geth_url)?);

  let mut mem = CertainMemoryHandler::<WBTCMemoryUpdates>::new();
  // let mut mem = CertainMemoryHandler::<SHIBMemoryUpdates>::new();
  // let mut mem = CertainMemoryHandler::<USDTMemoryUpdates>::new();
  mem.initialize(client.clone()).await?;

  for _ in 0..1000 {
    let currrent_block = <jsonrpsee::http_client::HttpClient as EthApiClient<
      Transaction,
      Block,
      Receipt,
      Header
    >>::block_number(&*client)
    .await
    .unwrap()
    .try_into()
    .unwrap();
    let state_root = storage_utils::get_state_root(&*client.clone(), currrent_block).await?;
    mem.update(client.clone(), currrent_block, state_root).await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
  }

  // for i in 0..100 {
  // 	let current_block =
  // 	<jsonrpsee::http_client::HttpClient as EthApiClient<Transaction, Block, Receipt>>::block_number(&*client)
  // 		.await
  // 		.unwrap()
  // 		.try_into()
  // 		.unwrap();
  //   let state_root = get_state_root(&*client.clone(), current_block).await?;
  // 	mem.update(client.clone(), current_block, state_root).await?;
  //   tokio::time::sleep(tokio::time::Duration::from_secs(14)).await;
  // }

  Ok(())
}
