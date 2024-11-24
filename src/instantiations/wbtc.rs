use crate::{
  bail_error,
  checkpoints::{get_most_recent_checkpoint, save_checkpoint},
  eventlogs::LogEvent,
  implement_getters,
  solidity_memory::{
    add_2d_mapping_addresses, add_mapping_addresses, add_static_array_addresses,
    add_string_addresses, get_2d_mapping_address, get_mapping_address,
  },
  tprintln,
  utils::{b256, ThreadSafeError},
};
use std::collections::{HashMap, HashSet};

use eth_sparse_mpt::sparse_mpt::DiffTrie;
use lazy_static::lazy_static;
use reth_revm::primitives::{keccak256, Address, B256};
use std::io::Read;

use reth_primitives::LogData;

use super::ierc20::{CertainMemoryHandler, IERC20MemoryHandlerCertain, MemoryUpdateTrait};

lazy_static! {
  static ref TRANSFER_EVENT_SIGNATURE: B256 = keccak256("Transfer(address,address,uint256)");
  static ref APPROVAL_EVENT_SIGNATURE: B256 = keccak256("Approval(address,address,uint256)");
  static ref PAUSE_EVENT_SIGNATURE: B256 = keccak256("Pause()");
  static ref UNPAUSE_EVENT_SIGNATURE: B256 = keccak256("Unpause()");
  static ref OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE: B256 =
    keccak256("OwnershipTransferred(address,address)");
  static ref BURN_EVENT_SIGNATURE: B256 = keccak256("Burn(address,uint256)");
  static ref MINT_EVENT_SIGNATURE: B256 = keccak256("Mint(address,uint256)");
  static ref WBTC_OWNERS: [B256; 2] = [
    "0x0000000000000000000000008b41783ad99fcbeb8d575fa7a7b5a04fa0b8d80b".parse::<B256>().unwrap(),
    "0x000000000000000000000000ca06411bd7a7296d7dbdd0050dfc846e95febeb7".parse::<B256>().unwrap()
  ];
  static ref START_BLOCK: u64 = 6_766_284;
  static ref CONTRACT_ADDRESS: Address =
    "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599".parse().unwrap();
}

#[derive(Clone)]
pub struct WBTCMemoryUpdates {
  pub account_owners: HashSet<B256>,
  pub allowed_pairs: HashSet<(B256, B256)>,

  pub senders_used: HashSet<B256>,
  pub used_pairs: HashSet<(B256, B256)>,
}

impl MemoryUpdateTrait for WBTCMemoryUpdates {
  fn new() -> Self {
    let mut ret = WBTCMemoryUpdates {
      account_owners: HashSet::new(),
      allowed_pairs: HashSet::new(),
      senders_used: HashSet::new(),
      used_pairs: HashSet::new(),
    };
    ret.init();
    ret
  }

  fn parse_log(&mut self, log: &LogEvent) -> Result<(), ThreadSafeError> {
    let top = B256::from(log.topics()[0].0);
    // println!("Log: {:?}", log);

    if top == *TRANSFER_EVENT_SIGNATURE {
      let ld = LogData::from(log.data().clone());
      let from = B256::from(log.topics()[1].0);
      let to = B256::from(log.topics()[2].0);
      let amount_bytes: Vec<u8> = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      let amount_array: [u8; 32] = amount_bytes.try_into().expect("slice with incorrect length");
      let _amount = B256::from(amount_array);
      // println!("TRNF: {:?}:{:?}:{:?}", from, to, _amount);
      self.register_account_owner(from);
      self.register_account_owner(to);
      self.register_used_pair(from, to);
      self.register_sender(from);
    } else if top == *APPROVAL_EVENT_SIGNATURE {
      let ld = LogData::from(log.data().clone());
      let owner = B256::from(log.topics()[1].0);
      let spender = B256::from(log.topics()[2].0);
      let amount_bytes: Vec<u8> = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      let amount_array: [u8; 32] = amount_bytes.try_into().expect("slice with incorrect length");
      let _amount = B256::from(amount_array);
      // println!("APRV: {:?}:{:?}:{:?}", owner, spender, _amount);
      self.register_allowed_pair(owner, spender);
    } else if top == *OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE {
      let from = B256::from(log.topics()[1].0);
      let to = B256::from(log.topics()[2].0);
      println!("Ownership Transfer: {:?} -> {:?}", from, to);
    } else if top == *PAUSE_EVENT_SIGNATURE || top == *UNPAUSE_EVENT_SIGNATURE {
      println!("Paused/Unpaused");
    } else if top == *BURN_EVENT_SIGNATURE || top == *MINT_EVENT_SIGNATURE {
      // println!("Burn/Mint");
      // We don't need to care about burns, because they also emmit a transfer.
      //
    } else {
      println!("Log: {:?}", log);
      println!("top0: {:?}", top);
      bail_error!("Unknown event signature");
    }

    Ok(())
  }

  fn extend(&mut self, other: WBTCMemoryUpdates) {
    self.account_owners.extend(other.account_owners);
    self.allowed_pairs.extend(other.allowed_pairs);
    self.senders_used.extend(other.senders_used);
    self.used_pairs.extend(other.used_pairs);
  }

  fn get_addresses(&self, base: &WBTCMemoryUpdates) -> HashSet<B256> {
    tprintln!(
      "Getting addressses with: {} account owners, {} allowed pairs, {} senders, {} all pairs",
      self.account_owners.len(),
      self.allowed_pairs.len(),
      self.senders_used.len(),
      self.used_pairs.len()
    );
    let mut ret = HashSet::new();
    add_mapping_addresses("_balanceOf", &mut ret, b256(0), self.account_owners.iter());
    add_static_array_addresses("_totalSupply", &mut ret, b256(1), 1);
    add_2d_mapping_addresses("_allowance", &mut ret, b256(2), self.allowed_pairs.iter());
    add_string_addresses("_name", &mut ret, b256(3), 256);
    add_string_addresses("_symbol", &mut ret, b256(4), 256);
    // decimals, Owner, mintingfinished, paused
    add_static_array_addresses("_lots", &mut ret, b256(5), 1);
    add_static_array_addresses("_pendingOwner", &mut ret, b256(6), 1);

    let mut actual_pairs = HashSet::new();

    const FULL: bool = true;
    if FULL {
      for (from, to) in base.allowed_pairs.iter() {
        if self.senders_used.contains(from) {
          actual_pairs.insert((from.clone(), to.clone()));
        }
      }
    } else {
      for (from, to) in self.used_pairs.iter() {
        if base.allowed_pairs.contains(&(from.clone(), to.clone())) {
          actual_pairs.insert((from.clone(), to.clone()));
        }
      }
    }

    add_2d_mapping_addresses("_allowance", &mut ret, b256(2), actual_pairs.iter());

    ret
  }
}

impl WBTCMemoryUpdates {
  fn init(&mut self) {
    for account in WBTC_OWNERS.iter() {
      self.register_account_owner(*account);
    }
  }

  fn register_account_owner(&mut self, account: B256) {
    self.account_owners.insert(account);
  }

  fn register_used_pair(&mut self, owner: B256, spender: B256) {
    self.used_pairs.insert((owner, spender));
  }

  fn register_allowed_pair(&mut self, owner: B256, spender: B256) {
    self.allowed_pairs.insert((owner, spender));
  }

  fn register_sender(&mut self, sender: B256) {
    self.senders_used.insert(sender);
  }

  pub fn reset(&mut self) {
    self.account_owners.clear();
    self.allowed_pairs.clear();
    self.senders_used.clear();
    self.used_pairs.clear();
    self.init();
  }

  pub fn cleanup(&mut self, nonzero: &HashMap<B256, B256>) {
    let slot = b256(2);
    for (k, v) in self.allowed_pairs.clone().iter() {
      let addr = get_2d_mapping_address(&slot, k, v);
      if !nonzero.contains_key(&addr) {
        self.allowed_pairs.remove(&(k.clone(), v.clone()));
      }
    }

    let slot = b256(0);
    for k in self.account_owners.clone().iter() {
      let addr = get_mapping_address(&slot, k);
      if !nonzero.contains_key(&addr) {
        self.account_owners.remove(k);
      }
    }
  }
}

impl IERC20MemoryHandlerCertain for CertainMemoryHandler<WBTCMemoryUpdates> {
  type StateType = WBTCMemoryUpdates;
  implement_getters!(WBTCMemoryUpdates);

  fn load_state(&mut self, current_block: u64) -> Result<(), ThreadSafeError> {
    let state_checkpoint = get_most_recent_checkpoint(Self::tag().as_str(), current_block)?;
    (self.memory, self.state.allowed_pairs) =
      state_checkpoint.read::<(HashMap<B256, B256>, HashSet<(B256, B256)>)>()?;
    self.current_block = state_checkpoint.block;
    println!(
      "Restored state from checkpoint at block: {} with {} addresses and {} allowed_pairs",
      self.current_block,
      self.memory.len(),
      self.state.allowed_pairs.len()
    );
    Ok(())
  }

  fn save_state(&mut self) -> Result<(), ThreadSafeError> {
    self.state.cleanup(&self.memory);
    save_checkpoint(
      Self::tag().as_str(),
      self.current_block,
      &(&self.memory, &self.state.allowed_pairs),
    )?;
    Ok(())
  }
}
