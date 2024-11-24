use alloy_rpc_types::{serde_helpers::JsonStorageKey, state, BlockId};
use async_trait::async_trait;
use std::{
  collections::{HashMap, HashSet},
  sync::{Arc, Mutex},
};

use alloy_primitives::{Address, B256};
use eth_sparse_mpt::sparse_mpt::DiffTrie;

use crate::{
  eventlogs::{apply_to_logs, LogEvent},
  restore_contract_certain::{
    apply_updates, build_initial_storage_trie, simplify_updates, verify_memory_incremental,
  },
  storage_utils::{fetch_address_values, get_state_root, get_storage_root},
  utils::{ProviderTrait, ThreadSafeError},
  CHECK,
};

#[async_trait]
pub trait IERC20MemoryHandler {
  async fn initialize<T: ProviderTrait>(
    &mut self,
    provider: Arc<T>,
  ) -> Result<(u64, B256), ThreadSafeError>;
  async fn update<T: ProviderTrait>(
    &mut self,
    provider: Arc<T>,
    target_block: u64,
    state_root: B256,
  ) -> Result<HashMap<B256, B256>, ThreadSafeError>;
}

pub trait MemoryUpdateTrait: Clone + Send {
  fn new() -> Self;
  fn parse_log(&mut self, log: &LogEvent) -> Result<(), ThreadSafeError>;
  fn get_addresses(&self, state: &Self) -> HashSet<B256>;
  fn extend(&mut self, other: Self);
}

pub struct CertainMemoryHandler<TMemoryUpdates: MemoryUpdateTrait> {
  pub current_block: u64,
  pub memory: HashMap<B256, B256>,
  pub trie: DiffTrie,
  pub state: TMemoryUpdates,
}

#[macro_export]
macro_rules! implement_getters {
  ($type:ty) => {
    fn contract_address() -> Address {
      *CONTRACT_ADDRESS
    }
    fn tag() -> String {
      format!("{}.Storage", Self::contract_address())
    }
    fn start_block() -> u64 {
      *START_BLOCK
    }
    fn current_block(&self) -> u64 {
      self.current_block
    }
    fn current_block_mut(&mut self) -> &mut u64 {
      &mut self.current_block
    }
    fn trie(&self) -> &DiffTrie {
      &self.trie
    }
    fn trie_mut(&mut self) -> &mut DiffTrie {
      &mut self.trie
    }
    fn memory(&self) -> &HashMap<B256, B256> {
      &self.memory
    }
    fn memory_mut(&mut self) -> &mut HashMap<B256, B256> {
      &mut self.memory
    }
    fn state(&self) -> &$type {
      &self.state
    }
    fn state_mut(&mut self) -> &mut $type {
      &mut self.state
    }
    fn new() -> Self {
      Self {
        current_block: (Self::start_block() - (Self::start_block() % 100_000)) - 1,
        memory: HashMap::new(),
        trie: DiffTrie::new_empty(),
        state: Self::StateType::new(),
      }
    }
  };
}

pub trait IERC20MemoryHandlerCertain: IERC20MemoryHandler + Send {
  type StateType: MemoryUpdateTrait + Send;
  fn new() -> Self;
  fn start_block() -> u64;
  fn contract_address() -> Address;
  fn tag() -> String;
  fn current_block(&self) -> u64;
  fn current_block_mut(&mut self) -> &mut u64;
  fn trie(&self) -> &DiffTrie;
  fn trie_mut(&mut self) -> &mut DiffTrie;
  fn memory(&self) -> &HashMap<B256, B256>;
  fn memory_mut(&mut self) -> &mut HashMap<B256, B256>;
  fn state(&self) -> &Self::StateType;
  fn state_mut(&mut self) -> &mut Self::StateType;

  fn load_state(&mut self, current_block: u64) -> Result<(), ThreadSafeError>;
  fn save_state(&mut self) -> Result<(), ThreadSafeError>;
}

#[async_trait]
impl<INSTANCE> IERC20MemoryHandler for INSTANCE
where
  INSTANCE: IERC20MemoryHandlerCertain,
{
  async fn initialize<T: ProviderTrait>(
    &mut self,
    provider: Arc<T>,
  ) -> Result<(u64, B256), ThreadSafeError> {
    let current_block: u64 = provider.block_number().await.unwrap().try_into().unwrap();

    println!("Current block: {}", current_block);

    match self.load_state(current_block) {
      Ok(_) => {
        println!("Loaded state from checkpoint at block: {}", self.current_block());
        let initial_state_root = get_state_root(&*provider.clone(), self.current_block()).await?;
        let initial_storage_root = get_storage_root(
          provider.clone(),
          BlockId::from(self.current_block()),
          initial_state_root,
          Self::contract_address(),
        )
        .await?;

        *self.trie_mut() = build_initial_storage_trie(&self.memory(), Some(initial_storage_root))?;
      }
      Err(e) => {
        println!("No initial state checkpoint found: {:?}", e);
        *self.trie_mut() = build_initial_storage_trie(&self.memory(), None)?;
      }
    }

    let should_save = true;
    let state_root = get_state_root(&*provider.clone(), current_block).await?;

    let _updates = self.update(provider, current_block, state_root).await?;

    if should_save {
      let _ = self.save_state();
    }
    Ok((current_block, state_root))
  }

  async fn update<T: ProviderTrait>(
    &mut self,
    provider: Arc<T>,
    target_block: u64,
    state_root: B256,
  ) -> Result<HashMap<B256, B256>, ThreadSafeError> {
    CHECK!(target_block >= self.current_block());
    if target_block == self.current_block() {
      return Ok(HashMap::new());
    }
    // // Maybe we should test that target_block - current block is smaller than a certain value, otherwise these logs will be huge
    println!("Current block: {}", self.current_block());
    println!("Target block: {}", target_block);

    let block_id = BlockId::from(target_block);
    let storage_root =
      get_storage_root(provider.clone(), block_id, state_root, Self::contract_address()).await?;

    let state_updates = Arc::new(Mutex::new(INSTANCE::StateType::new()));
    {
      let state_updates_clone = state_updates.clone();
      apply_to_logs(
        &*provider,
        Self::contract_address(),
        self.current_block() + 1,
        target_block,
        move |logs| {
          let mut locked_state_updates = state_updates_clone.lock().unwrap();
          for log in logs {
            locked_state_updates.parse_log(&log)?;
          }
          Ok(())
        },
      )
      .await?;
    }

    let addresses: Vec<JsonStorageKey>;
    {
      let state_updates = state_updates.lock().unwrap();
      let raw_addresses = state_updates.get_addresses(self.state());
      addresses = raw_addresses.iter().map(|x| JsonStorageKey::Hash(*x)).collect();
    }

    let hm: HashMap<B256, B256>;
    {
      let hm_inter = fetch_address_values(
        provider.clone(),
        Self::contract_address(),
        block_id,
        storage_root,
        &addresses,
      )
      .await?;
      hm = simplify_updates(&self.memory(), hm_inter);
    }

    verify_memory_incremental(&mut self.trie_mut(), &hm, storage_root)?;
    apply_updates(&mut self.memory_mut(), &hm);

    self.state_mut().extend(state_updates.lock().unwrap().clone());
    *self.current_block_mut() = target_block;

    Ok(hm)
  }
}
