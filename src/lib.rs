use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types::{Block, Transaction};
use instantiations::ierc20::{
  CertainMemoryHandler, IERC20MemoryHandler, IERC20MemoryHandlerCertain, MemoryUpdateTrait,
};
use jsonrpsee::http_client::HttpClientBuilder;
use reth_primitives::Receipt;
use reth_rpc_api::EthApiClient;
use storage_utils::get_state_root;
use utils::ProviderTrait;
use utils::ThreadSafeError;

pub mod checkpoints;
pub mod eventlogs;
pub mod instantiations;
pub mod recovering_trie;
pub mod restore_contract_certain; // <-- Uses memory state to rebuild the mpt and check root hash
pub mod restore_contract_uncertain; // <-- Uses geth proofs
pub mod solidity_memory;
pub mod storage_utils;
pub mod utils;

pub struct StateVerifier<T: IERC20MemoryHandlerCertain> {
  pub client: Arc<jsonrpsee::http_client::HttpClient>,
  pub mem: T,
  pub pending_updates: HashMap<B256, B256>,
  pub block_id: u64,
  pub storage_root: B256,
}

impl<T: IERC20MemoryHandlerCertain> StateVerifier<T> {
  pub fn new(geth_url: &String) -> Result<Self, ThreadSafeError> {
    let client: Arc<jsonrpsee::http_client::HttpClient> =
      Arc::new(HttpClientBuilder::default().build(geth_url)?);
    let mem = T::new();
    Ok(Self {
      client,
      mem,
      pending_updates: HashMap::new(),
      block_id: 0,
      storage_root: B256::default(),
    })
  }

  pub async fn initialize(&mut self) -> Result<(), ThreadSafeError> {
    let (block_id, storage_root) = self.mem.initialize(self.client.clone()).await?;
    self.pending_updates = self.mem.memory().clone();
    self.block_id = block_id;
    self.storage_root = storage_root;
    Ok(())
  }

  pub async fn update(&mut self) -> Result<(), ThreadSafeError> {
    assert!(self.pending_updates.len() == 0);
    let target_block_number: U256 = <jsonrpsee::http_client::HttpClient as EthApiClient<
      Transaction,
      Block,
      Receipt,
    >>::block_number(&*self.client)
    .await?;
    let target_block: u64 = target_block_number.try_into().unwrap();
    let state_root = get_state_root(&*self.client.clone(), target_block).await?;
    self.pending_updates = self.mem.update(self.client.clone(), target_block, state_root).await?;
    self.block_id = target_block;
    self.storage_root = state_root;
    Ok(())
  }

  pub fn contract_address(&self) -> Address {
    T::contract_address()
  }
}
