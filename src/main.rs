pub mod utils;
pub mod recovering_trie;
pub mod eventlogs;
pub mod solidity_memory;
pub mod instantiations;
pub mod storage_utils;
pub mod restore_contract_uncertain; // <-- Uses geth proofs
pub mod restore_contract_certain; // <-- Uses memory state to rebuild the mpt and check root hash
pub mod checkpoints;

use std::sync::Arc;
use dotenv::dotenv;
use instantiations::ierc20::{CertainMemoryHandler, IERC20MemoryHandler, IERC20MemoryHandlerCertain};
use instantiations::{
	usdt::USDTMemoryUpdates,
	wbtc::WBTCMemoryUpdates,
	shib::SHIBMemoryUpdates, 	
};
use reth_primitives::{Block, Receipt, Transaction};
use reth_rpc_api::EthApiClient;
use utils::ThreadSafeError;

use std::env;
use jsonrpsee::http_client::HttpClientBuilder;

#[tokio::main]
async fn main() -> Result<(), ThreadSafeError> {
	dotenv().ok(); // Load the .env file

	let geth_url = env::var("GETH_URL").expect("Infura URL must be set");

	let client:Arc<jsonrpsee::http_client::HttpClient> =  Arc::new(HttpClientBuilder::default().build(geth_url)?);
	
	let mut mem = CertainMemoryHandler::<WBTCMemoryUpdates>::new();
	// let mut mem = CertainMemoryHandler::<SHIBMemoryUpdates>::new();
	// let mut mem = CertainMemoryHandler::<USDTMemoryUpdates>::new();
	mem.initialize(client.clone()).await?;

	for _ in 0..1000 {
		let currrent_block = <jsonrpsee::http_client::HttpClient as EthApiClient<Transaction, Block, Receipt>>::block_number(&*client)
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