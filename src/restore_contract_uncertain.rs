// use crate::bail_error;
use crate::tprintln;
use crate::utils::ThreadSafeError;
use alloy_rpc_types::{EIP1186StorageProof, Header};
use futures::lock::Mutex;
use std::sync::Arc;
use std::time::Duration;

use alloy_rpc_types::{serde_helpers::JsonStorageKey, Block, BlockId, Transaction};
use futures::stream::{FuturesUnordered, StreamExt};
use reth_primitives::Receipt;
use reth_revm::primitives::{keccak256, Address, FixedBytes, B256};
use reth_rpc_api::clients::EthApiClient;
use reth_trie_common::proof::verify_proof;
use reth_trie_common::{Nibbles, TrieAccount};
use std::collections::HashMap;
use std::collections::HashSet;
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::sleep;

use crate::recovering_trie::{reconstruct_tree_from_verified_storage_proof, RecoveringTrie};
use crate::storage_utils::{get_storage_proof, verify_storage_proof};

async fn restore_contract_memory_with_contract_root_thread(
  storage_proof: Vec<EIP1186StorageProof>,
  storage_root: FixedBytes<32>,
  addresses: Vec<JsonStorageKey>,
  rt: Arc<Mutex<RecoveringTrie>>,
  ht: Arc<Mutex<HashMap<B256, B256>>>,
) -> Result<(), ThreadSafeError> {
  let hm_l = verify_storage_proof(storage_root, &addresses, &storage_proof)?;
  tprintln!("Verified storage proofs");

  {
    ht.lock().await.extend(hm_l);
  }

  {
    for sproof in storage_proof {
      reconstruct_tree_from_verified_storage_proof(sproof, &rt).await?;
    }
  }
  Ok(())
}

async fn restore_contract_memory_with_contract_root<
  T: EthApiClient<Transaction, Block, Receipt, Header> + Send + Sync,
>(
  provider: Arc<T>,
  contract_address: Address,
  block_number: BlockId,
  storage_root: FixedBytes<32>,
  addresses: &Vec<JsonStorageKey>,
) -> Result<(RecoveringTrie, HashMap<B256, B256>), ThreadSafeError> {
  tprintln!("Restoring contract memory");
  tprintln!("Total addresses: {:?}", addresses.len());

  const CONCURENCY_LIMIT: usize = 24;
  let tasks = FuturesUnordered::new();
  let semaphore = Arc::new(Semaphore::new(CONCURENCY_LIMIT));

  let rt = Arc::new(Mutex::new(RecoveringTrie::new()));
  rt.lock().await.root = storage_root;
  let ht: Arc<Mutex<HashMap<B256, B256>>> = Arc::new(Mutex::new(HashMap::new()));

  tprintln!("Dispatching tasks");
  for addresses_batch in addresses.chunks(100000) {
    let provider_clone = provider.clone();
    let semphore_clone = semaphore.clone();
    let adrv = addresses_batch.to_vec();
    tasks.push(async move {
      let mut attempt = 0;
      loop {
        let ret;
        {
          let _permit = semphore_clone.acquire().await;
          ret =
            get_storage_proof(provider_clone.clone(), contract_address, block_number, adrv.clone())
              .await;
        }
        // println!("Task completed {:?}",addresses_batch[0]);
        match ret {
          Ok((addresses, resp)) => {
            break Ok((addresses, resp));
          }
          Err(e) => {
            attempt += 1;
            if attempt > 3 {
              break Err(e);
            }
            sleep(Duration::from_secs(1)).await;
          }
        }
      }
    });
  }
  tprintln!("Tasks dispatched!");

  tasks
    .for_each_concurrent(CONCURENCY_LIMIT, |result| async {
      let rtclone = rt.clone();
      let htclone = ht.clone();
      match result {
        Ok((addresses, resp)) => {
          let res = task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
              let res = restore_contract_memory_with_contract_root_thread(
                resp,
                storage_root,
                addresses.to_vec(),
                rtclone,
                htclone,
              )
              .await;
              res.unwrap();
            })
          })
          .await;
          res.unwrap();
        }
        Err(e) => {
          panic!("Error: {:?}", e);
        }
      }
    })
    .await;

  // for (k, v) in ht.iter() {
  // if v != &B256::default() {
  // println!("Key: {:?}, Value: {:?}", k, v);
  // }
  // }

  let rt = Arc::try_unwrap(rt).unwrap().into_inner();
  let mut ret = HashMap::new();
  rt.verify(storage_root, &mut ret)?;

  Ok((rt, ret))
}

pub async fn restore_contract_memory_uncertain<
  T: EthApiClient<Transaction, Block, Receipt, Header> + Send + Sync,
>(
  provider: Arc<T>,
  contract_address: Address,
  block_number: BlockId,
  state_root: FixedBytes<32>,
  addresses: &Vec<JsonStorageKey>,
) -> Result<(), ThreadSafeError> {
  let locations = vec![JsonStorageKey::Hash(B256::from([0; 32]))];
  let storage_value =
    provider.get_proof(contract_address, locations.clone(), Some(block_number)).await?;

  let trie_account = TrieAccount {
    nonce: storage_value.nonce,
    balance: storage_value.balance,
    storage_root: storage_value.storage_hash,
    code_hash: storage_value.code_hash,
  };

  let expected = Some(alloy_rlp::encode(&trie_account));
  let nibbles = Nibbles::unpack(keccak256(storage_value.address));
  verify_proof(state_root, nibbles, expected, &storage_value.account_proof)?;

  // If we arrive here it means we have the correct storage_root
  let storage_root = storage_value.storage_hash;
  println!("Block: {:?}", block_number);
  println!("state_root: {:?}", state_root);
  println!("Account: {:?}", trie_account);
  println!("Verified account proof for address: {:?}", storage_value.address);
  println!("storage_root: {:?}", storage_root);

  verify_storage_proof(storage_root, &locations, &storage_value.storage_proof)?;

  let (_rt, hm) = restore_contract_memory_with_contract_root(
    provider,
    contract_address,
    block_number,
    storage_root,
    addresses,
  )
  .await?;

  let mut addr_h = HashSet::new();
  for addr in addresses {
    let kek = keccak256(addr.as_b256());
    addr_h.insert(kek);
  }

  for (k, v) in hm.iter() {
    if !addr_h.contains(k) {
      println!("!!! Key: {:?}, Value: {:?}", k, v);
    }
  }

  tprintln!("Restored contract memory, total keys: {:?}", hm.len());

  Ok(())
}
