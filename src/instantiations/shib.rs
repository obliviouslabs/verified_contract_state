use crate::{bail_error, checkpoints::{get_most_recent_checkpoint, save_checkpoint}, eventlogs::LogEvent, implement_getters, solidity_memory::{add_2d_mapping_addresses, add_mapping_addresses, add_static_array_addresses, add_string_addresses, get_2d_mapping_address, get_mapping_address}, tprintln, utils::{b256, ThreadSafeError}};
use std::collections::{HashMap, HashSet};

use eth_sparse_mpt::sparse_mpt::DiffTrie;
use reth_revm::primitives::{keccak256, B256,  Address};
use lazy_static::lazy_static;
use std::io::Read;

use reth_primitives::LogData;

use super::ierc20::{CertainMemoryHandler, IERC20MemoryHandlerCertain, MemoryUpdateTrait};



lazy_static! {
  static ref TRANSFER_EVENT_SIGNATURE: B256 = keccak256("Transfer(address,address,uint256)");
  static ref APPROVAL_EVENT_SIGNATURE: B256 = keccak256("Approval(address,address,uint256)");
  static ref SHIB_OWNERS: [B256; 1] = ["0x000000000000000000000000B8F226DDB7BC672E27DFFB67E4ADABFA8C0DFA08".parse::<B256>().unwrap(),
  ];

  static ref CONTRACT_ADDRESS: Address = "0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE".parse().unwrap();
  static ref START_BLOCK: u64 = 10_569_013;
}

#[derive(Clone)]
pub struct SHIBMemoryUpdates {
  pub account_owners: HashSet<B256>,
  pub allowed_pairs: HashSet<(B256,B256)>,
}

impl MemoryUpdateTrait for SHIBMemoryUpdates {
  fn new() -> Self {
    let mut ret = SHIBMemoryUpdates {
      account_owners: HashSet::new(),
      allowed_pairs: HashSet::new(),
    };
    ret.init();
    ret
  }

  fn parse_log(&mut self, log: &LogEvent) -> Result<(), ThreadSafeError> {
    let top = B256::from(log.topics()[0].0);
    // println!("Log: {:?}", log);
    // println!("top0: {:?}" , top);
    
    if top == *TRANSFER_EVENT_SIGNATURE {
      let ld = LogData::from(log.data().clone());
      let from = B256::from(log.topics()[1].0);
      let to = B256::from(log.topics()[2].0);
      let amount_bytes: Vec<u8> = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      let amount_array: [u8; 32] = amount_bytes.try_into().expect("slice with incorrect length");
      let _amount = B256::from(amount_array);
      // println!("TRNF: {:?}:{:?}:{:?}", from, to, amount);
      self.register_account_owner(from);
      self.register_account_owner(to);
    } else if top == *APPROVAL_EVENT_SIGNATURE {
      let ld = LogData::from(log.data().clone());
      let owner = B256::from(log.topics()[1].0);
      let spender = B256::from(log.topics()[2].0);
      let amount_bytes: Vec<u8> = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      let amount_array: [u8; 32] = amount_bytes.try_into().expect("slice with incorrect length");
      let _amount = B256::from(amount_array);
      // println!("APRV: {:?}:{:?}:{:?}", owner, spender, _amount);
      self.register_allowed_pair(owner, spender);
    } else {
      println!("Log: {:?}", log);
      println!("top0: {:?}" , top);
      println!("AES : {:?}", *APPROVAL_EVENT_SIGNATURE);
      println!("TES : {:?}", *TRANSFER_EVENT_SIGNATURE);
      bail_error!("Unknown event signature");
    }
    
    Ok(())
  }

  fn extend(&mut self, other: SHIBMemoryUpdates) {
    self.account_owners.extend(other.account_owners);
    self.allowed_pairs.extend(other.allowed_pairs);
  }

  fn get_addresses(&self, _base: &SHIBMemoryUpdates) -> HashSet<B256> {
    tprintln!("Getting addressses with: {} account owners, allowed pairs: {}", self.account_owners.len(), self.allowed_pairs.len());
    let mut ret = HashSet::new();
    add_mapping_addresses("_balanceOf", &mut ret, b256(0), self.account_owners.iter());
    add_2d_mapping_addresses("_allowance", &mut ret, b256(1), self.allowed_pairs.iter());
    add_static_array_addresses("_totalSupply", &mut ret, b256(2), 1);
    // TODO: make these smaller / hardcoded: ("SHIBA INU", "SHIB", 18)
    add_string_addresses("name", &mut ret, b256(3), 256);
    // symbol is array of uint256 at storage 8
    add_string_addresses("symbol", &mut ret, b256(4), 256);
    // decimals is uint256 at storage 9
    add_static_array_addresses("decimals", &mut ret, b256(5), 1);

    ret
  }
}

impl SHIBMemoryUpdates {
  fn init(&mut self) {
    for account in SHIB_OWNERS.iter() {
      self.register_account_owner(*account);
    }
  }

  fn register_account_owner(&mut self, account: B256) {
    self.account_owners.insert(account);
  }

  fn register_allowed_pair(&mut self, owner: B256, spender: B256) {
    self.allowed_pairs.insert((owner, spender));
  }

  pub fn cleanup(&mut self, nonzero: &HashMap<B256,B256>) {
    let slot =  b256(1);
    for (k, v) in self.allowed_pairs.clone().iter() {
      let addr = get_2d_mapping_address(&slot, k, v);
      if !nonzero.contains_key(&addr) {
        self.allowed_pairs.remove(&(k.clone(), v.clone()));
      }
    }

    let slot =  b256(0);
    for k in self.account_owners.clone().iter() {
      let addr = get_mapping_address(&slot, k);
      if !nonzero.contains_key(&addr) {
        self.account_owners.remove(k);
      }
    }
  }

}

impl IERC20MemoryHandlerCertain for CertainMemoryHandler<SHIBMemoryUpdates> {
  type StateType = SHIBMemoryUpdates;

  implement_getters!(SHIBMemoryUpdates);
  
  fn load_state(&mut self, current_block: u64) -> Result<(), ThreadSafeError> {
    let state_checkpoint = get_most_recent_checkpoint(Self::tag().as_str(), current_block)?;
    self.memory = state_checkpoint.read::<
          HashMap<B256,B256>
        >()?;
    self.current_block = state_checkpoint.block;
    println!("Restored state from checkpoint at block: {} with {} addresses and {} allowed_pairs", self.current_block, self.memory.len(), self.state.allowed_pairs.len());
    Ok(())
  }

  fn save_state(&mut self) -> Result<(), ThreadSafeError> {
    self.state.cleanup(&self.memory);
    save_checkpoint(Self::tag().as_str(), self.current_block, &self.memory)?;
    Ok(())
  }
}
