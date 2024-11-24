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
  static ref PAUSED_EVENT_SIGNATURE: B256 = keccak256("Paused()");
  static ref UNPAUSED_EVENT_SIGNATURE: B256 = keccak256("Unpaused()");
  static ref DESTROYED_BLACK_FUNDS_EVENT_SIGNATURE: B256 =
    keccak256("DestroyedBlackFunds(address,uint256)");
  static ref ADDED_BLACKLIST_EVENT_SIGNATURE: B256 = keccak256("AddedBlackList(address)");
  static ref REMOVED_BLACKLIST_EVENT_SIGNATURE: B256 = keccak256("RemovedBlackList(address)");
  static ref ISSUE_EVENT_SIGNATURE: B256 = keccak256("Issue(uint256)");
  static ref REDEEM_EVENT_SIGNATURE: B256 = keccak256("Redeem(uint256)");
  static ref DEPRECATE_EVENT_SIGNATURE: B256 = keccak256("Deprecate(address)");
  static ref PARAMS_EVENT_SIGNATURE: B256 = keccak256("Params(uint256,uint256)");
  static ref USDT_OWNERS: [B256; 2] = [
    "0x00000000000000000000000036928500bc1dcd7af6a2b4008875cc336b927d57".parse::<B256>().unwrap(),
    "0x000000000000000000000000c6cde7c39eb2f0f0095f41570af89efc2c1ea828".parse::<B256>().unwrap()
  ];
  static ref START_BLOCK: u64 = 4_634_748;
  static ref CONTRACT_ADDRESS: Address =
    "0xdac17f958d2ee523a2206206994597c13d831ec7".parse().unwrap();
}

#[derive(Clone)]
pub struct USDTMemoryUpdates {
  pub account_owners: HashSet<B256>,
  pub account_blacklists: HashSet<B256>,
  pub allowed_pairs: HashSet<(B256, B256)>,

  pub senders_used: HashSet<B256>,
  pub used_pairs: HashSet<(B256, B256)>,
}

impl MemoryUpdateTrait for USDTMemoryUpdates {
  fn new() -> Self {
    let mut ret = USDTMemoryUpdates {
      account_owners: HashSet::new(),
      account_blacklists: HashSet::new(),
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
    } else if top == *ADDED_BLACKLIST_EVENT_SIGNATURE || top == *REMOVED_BLACKLIST_EVENT_SIGNATURE {
      let ld = LogData::from(log.data().clone());
      let account_bytes = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      let account_array: [u8; 32] = account_bytes.try_into().expect("slice with incorrect length");
      let account = B256::from(account_array);
      // println!("BLEV: {:?}", account);
      self.register_account_blacklist(account);
    } else if top == *PAUSED_EVENT_SIGNATURE || top == *UNPAUSED_EVENT_SIGNATURE {
      println!("Paused/Unpaused");
    } else if top == *DESTROYED_BLACK_FUNDS_EVENT_SIGNATURE {
      let ld = LogData::from(log.data().clone());
      // acount is the first 32 bytes
      // amount in the last 32 bytes
      let allbytes = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      let account_bytes = &allbytes[..32];
      let amount_bytes = &allbytes[32..];
      let account_array: [u8; 32] = account_bytes.try_into().expect("slice with incorrect length");
      let account = B256::from(account_array);
      let amount_array: [u8; 32] = amount_bytes.try_into().expect("slice with incorrect length");
      let _amount = B256::from(amount_array);
      // println!("DBLF: {:?}:{:?}", account, amount);
      self.register_account_owner(account);
      self.register_account_blacklist(account);
    } else if top == *ISSUE_EVENT_SIGNATURE || top == *REDEEM_EVENT_SIGNATURE {
      let ld = LogData::from(log.data().clone());
      let amount_bytes: Vec<u8> = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      let amount_array: [u8; 32] = amount_bytes.try_into().expect("slice with incorrect length");
      let _amount = B256::from(amount_array);
      // println!("IRES: {:?}", amount);
    } else if top == *DEPRECATE_EVENT_SIGNATURE {
      bail_error!("Deprecate event not implemented");
      // let mut ld = LogData::from(log.data().clone());
      // let new_address = B256::from(log.topics()[1].0);
      // println!("New address: {:?}", new_address);
    } else if top == *PARAMS_EVENT_SIGNATURE {
      bail_error!("Params event not implemented");
      // let mut ld = LogData::from(log.data().clone());
      // let basisPointRate_bytes: Vec<u8> = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      // let basisPointRate_array: [u8; 32] = basisPointRate_bytes.try_into().expect("slice with incorrect length");
      // let basisPointRate = B256::from(basisPointRate_array);
      // let maxfee_bytes: Vec<u8> = ld.data.bytes().collect::<Result<Vec<u8>, _>>()?;
      // let maxfee_array: [u8; 32] = maxfee_bytes.try_into().expect("slice with incorrect length");
      // let maxfee = B256::from(maxfee_array);
      // println!("BasisPointRate: {:?}, MaxFee: {:?}", basisPointRate, maxfee);
    } else {
      println!("Log: {:?}", log);
      println!("top0: {:?}", top);
      println!("AES : {:?}", *APPROVAL_EVENT_SIGNATURE);
      println!("TES : {:?}", *TRANSFER_EVENT_SIGNATURE);
      println!("PES : {:?}", *PAUSED_EVENT_SIGNATURE);
      println!("UPES: {:?}", *UNPAUSED_EVENT_SIGNATURE);
      println!("DBFES: {:?}", *DESTROYED_BLACK_FUNDS_EVENT_SIGNATURE);
      println!("ABES: {:?}", *ADDED_BLACKLIST_EVENT_SIGNATURE);
      println!("RBES: {:?}", *REMOVED_BLACKLIST_EVENT_SIGNATURE);
      println!("IEES: {:?}", *ISSUE_EVENT_SIGNATURE);
      println!("REES: {:?}", *REDEEM_EVENT_SIGNATURE);
      println!("DEES: {:?}", *DEPRECATE_EVENT_SIGNATURE);
      println!("PRES: {:?}", *PARAMS_EVENT_SIGNATURE);
      bail_error!("Unknown event signature");
    }

    Ok(())
  }

  fn extend(&mut self, other: USDTMemoryUpdates) {
    self.account_owners.extend(other.account_owners);
    self.account_blacklists.extend(other.account_blacklists);
    self.allowed_pairs.extend(other.allowed_pairs);
    self.senders_used.extend(other.senders_used);
    self.used_pairs.extend(other.used_pairs);
  }

  fn get_addresses(&self, base: &USDTMemoryUpdates) -> HashSet<B256> {
    tprintln!("Getting addressses with: {} account owners, {} blacklists, {} allowed pairs, {} senders, {} all pairs", self.account_owners.len(), self.account_blacklists.len(), self.allowed_pairs.len(), self.senders_used.len(), self.used_pairs.len());
    let mut ret = HashSet::new();
    add_static_array_addresses("paused", &mut ret, b256(0), 1);
    add_static_array_addresses("_totalSupply", &mut ret, b256(1), 1);
    // balances is mapping of uint256 at storage 2
    add_mapping_addresses("balances", &mut ret, b256(2), self.account_owners.iter());
    // basisPointsRate is uint256 at storage 3
    add_static_array_addresses("basisPointsRate", &mut ret, b256(3), 1);
    // maximumFee is uint256 at storage 4
    add_static_array_addresses("maximumFee", &mut ret, b256(4), 1);
    // allowed is mapping of uint256 at storage 5
    add_2d_mapping_addresses("allowed", &mut ret, b256(5), self.allowed_pairs.iter());
    // stor6 is mapping of uint8 at storage 6
    add_mapping_addresses("isBlackListed", &mut ret, b256(6), self.account_blacklists.iter());
    // name is array of uint256 at storage 7
    add_string_addresses("name", &mut ret, b256(7), 256);
    // symbol is array of uint256 at storage 8
    add_string_addresses("symbol", &mut ret, b256(8), 256);
    // decimals is uint256 at storage 9
    add_static_array_addresses("decimals", &mut ret, b256(9), 1);
    // deprecated is uint8 at storage 10 offset 160
    // stor10 is uint128 at storage 10 offset 160
    // upgradedAddress is addr at storage 10
    add_static_array_addresses("deprecated", &mut ret, b256(10), 1);

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

    add_2d_mapping_addresses("allowed", &mut ret, b256(5), actual_pairs.iter());

    ret
  }
}

impl USDTMemoryUpdates {
  fn init(&mut self) {
    for account in USDT_OWNERS.iter() {
      self.register_account_owner(*account);
    }
  }

  fn register_account_owner(&mut self, account: B256) {
    self.account_owners.insert(account);
  }

  fn register_account_blacklist(&mut self, account: B256) {
    self.account_blacklists.insert(account);
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
    self.account_blacklists.clear();
    self.allowed_pairs.clear();
    self.senders_used.clear();
    self.used_pairs.clear();
    self.init();
  }

  pub fn cleanup(&mut self, nonzero: &HashMap<B256, B256>) {
    let slot = b256(5);
    for (k, v) in self.allowed_pairs.clone().iter() {
      let addr = get_2d_mapping_address(&slot, k, v);
      if !nonzero.contains_key(&addr) {
        self.allowed_pairs.remove(&(k.clone(), v.clone()));
      }
    }

    let slot = b256(2);
    for k in self.account_owners.clone().iter() {
      let addr = get_mapping_address(&slot, k);
      if !nonzero.contains_key(&addr) {
        self.account_owners.remove(k);
      }
    }

    let slot = b256(6);
    for k in self.account_blacklists.clone().iter() {
      let addr = get_mapping_address(&slot, k);
      if !nonzero.contains_key(&addr) {
        self.account_blacklists.remove(k);
      }
    }
  }
}

impl IERC20MemoryHandlerCertain for CertainMemoryHandler<USDTMemoryUpdates> {
  type StateType = USDTMemoryUpdates;
  implement_getters!(USDTMemoryUpdates);

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
