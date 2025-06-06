use crate::tprintln;
use crate::utils::ThreadSafeError;
use crate::CHECK;
use alloy_primitives::keccak256;
use alloy_primitives::Bytes;
use eth_sparse_mpt::sparse_mpt::DiffTrie;

use reth_revm::primitives::{B256, U256};
use reth_trie::root::storage_root_unhashed;
use std::collections::HashMap;

pub fn verify_memory_simple(
  mem: &HashMap<B256, B256>,
  storage_root: B256,
) -> Result<(), ThreadSafeError> {
  tprintln!("Typing memory");
  let mem_typed: Vec<(B256, U256)> = mem.iter().map(|(k, v)| (*k, v.clone().into())).collect();
  tprintln!("Hashing memory");
  let root = storage_root_unhashed(mem_typed);
  tprintln!("Root: {:?}", root);
  CHECK!(root == storage_root);
  Ok(())
}

pub fn simplify_updates(
  memory: &HashMap<B256, B256>,
  updates: HashMap<B256, B256>,
) -> HashMap<B256, B256> {
  let mut simplified_updates = HashMap::new();
  for (k, v) in updates {
    match memory.get(&k) {
      Some(orig) => {
        if orig != &v {
          simplified_updates.insert(k, v);
        }
      }
      None => {
        if v != B256::default() {
          simplified_updates.insert(k, v);
        }
      }
    }
  }

  simplified_updates
}

pub fn apply_updates(mem: &mut HashMap<B256, B256>, updates: &HashMap<B256, B256>) {
  for (k, v) in updates.iter() {
    if v == &B256::default() {
      mem.remove(k);
    } else {
      mem.insert(k.clone(), v.clone());
    }
  }
}

pub fn verify_memory_incremental(
  trie: &mut DiffTrie,
  changes: &HashMap<B256, B256>,
  storage_root: B256,
) -> Result<(), ThreadSafeError> {
  tprintln!("verify_memory_incremental!");

  for (k, v) in changes.iter() {
    let (key, val) = get_kv(k, v);
    if v == &B256::default() {
      let dbg = trie.delete(key.clone());
      CHECK!(!dbg.is_err()); // Deletion failed, just return err instead of panicking
    } else {
      let dbg = trie.insert(key.clone(), val.clone());
      CHECK!(!dbg.is_err()); // Insertion failed, just return err instead of panicking
    }
  }

  let root = trie.root_hash();
  tprintln!("Root: {:?}", root);
  let root = root?;

  CHECK!(root == storage_root);

  Ok(())
}

pub fn get_kv(k: &B256, v: &B256) -> (Bytes, Bytes) {
  let key = keccak256(k);
  let val: U256 = v.clone().into();
  let val = alloy_rlp::encode(val);
  (key.into(), val.into())
}

pub fn build_initial_storage_trie(
  mem: &HashMap<B256, B256>,
  target_hash: Option<B256>, // If None, we will not verify the initial hash (we still compute it)
) -> Result<DiffTrie, ThreadSafeError> {
  tprintln!("Building Initial Storage Trie");
  let mut trie = DiffTrie::new_empty();

  if let Some(target_hash) = target_hash {
    verify_memory_incremental(&mut trie, mem, target_hash)?;
  } else {
    let _ = verify_memory_incremental(&mut trie, mem, B256::default()); // We ignore the error
  }

  Ok(trie)
}
