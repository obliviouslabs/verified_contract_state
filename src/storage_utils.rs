use crate::bail_error;
use crate::tprintln;
use crate::utils::ProviderTrait;
use crate::utils::ThreadSafeError;
use crate::CHECK;
use alloy_rpc_types::EIP1186StorageProof;
use futures::lock::Mutex;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use reth_rpc_api::EthFilterApiClient;
use std::cmp::max;
use std::cmp::min;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task;
use tokio::time::sleep;

use alloy_rlp::encode_fixed_size;
use alloy_rpc_types::{serde_helpers::JsonStorageKey, BlockId};
use reth_revm::primitives::{keccak256, Address, FixedBytes, B256};
use reth_trie_common::proof::verify_proof;
use reth_trie_common::{Nibbles, TrieAccount};
use std::collections::HashMap;
use std::collections::HashSet;

pub async fn get_state_root<T: ProviderTrait>(
  provider: &T,
  block_number: u64,
) -> Result<FixedBytes<32>, ThreadSafeError> {
  let block: alloy_rpc_types::Block =
    provider.block_by_number(block_number.into(), false).await?.ok_or("error")?;
  let state_root = block.header.state_root;
  Ok(state_root)
}

pub async fn get_account_info<T: ProviderTrait>(
  provider: Arc<T>,
  block_number: BlockId,
  state_root: FixedBytes<32>,
  contract_address: Address,
) -> Result<TrieAccount, ThreadSafeError> {
  let addreses = vec![JsonStorageKey::Hash(B256::from([0; 32]))];
  let storage_value =
    provider.get_proof(contract_address, addreses.clone(), Some(block_number)).await?;
  let trie_account = TrieAccount {
    nonce: storage_value.nonce,
    balance: storage_value.balance,
    storage_root: storage_value.storage_hash,
    code_hash: storage_value.code_hash,
  };
  println!("Block: {:?}", block_number);
  println!("Verified account proof for address: {:?}", contract_address);
  println!("Account: {:?}", trie_account);

  let expected = Some(alloy_rlp::encode(&trie_account));
  let nibbles = Nibbles::unpack(keccak256(storage_value.address));
  verify_proof(state_root, nibbles, expected, &storage_value.account_proof)?;
  CHECK!(storage_value.address == contract_address);

  Ok(trie_account)
}

pub async fn get_storage_root<T: ProviderTrait>(
  provider: Arc<T>,
  block_number: BlockId,
  state_root: FixedBytes<32>,
  contract_address: Address,
) -> Result<FixedBytes<32>, ThreadSafeError> {
  let addreses = vec![JsonStorageKey::Hash(B256::from([0; 32]))];
  let storage_value =
    provider.get_proof(contract_address, addreses.clone(), Some(block_number)).await?;
  let trie_account = TrieAccount {
    nonce: storage_value.nonce,
    balance: storage_value.balance,
    storage_root: storage_value.storage_hash,
    code_hash: storage_value.code_hash,
  };
  println!("Block: {:?}", block_number);
  println!("Verified account proof for address: {:?}", contract_address);
  println!("Account: {:?}", trie_account);

  let expected = Some(alloy_rlp::encode(&trie_account));
  let nibbles = Nibbles::unpack(keccak256(storage_value.address));
  verify_proof(state_root, nibbles, expected, &storage_value.account_proof)?;
  CHECK!(storage_value.address == contract_address);

  Ok(storage_value.storage_hash)
}

pub fn verify_storage_proof(
  storage_root: FixedBytes<32>,
  queried_locations: &Vec<JsonStorageKey>,
  storage_proof: &Vec<EIP1186StorageProof>,
) -> Result<HashMap<B256, B256>, ThreadSafeError> {
  println!("Verifying storage proof");
  let mut queried_locations_set = HashSet::new();
  let mut values: HashMap<B256, B256> = HashMap::new();
  for location in queried_locations {
    if queried_locations_set.contains(&location.as_b256()) {
      bail_error!("Duplicate queried val: {:?}", location);
    }
    // println!("Queried location: {:?}", location);
    queried_locations_set.insert(location.as_b256());
  }

  storage_proof.iter().try_for_each(
    |proof: &EIP1186StorageProof| -> Result<(), ThreadSafeError> {
      let key = proof.key;
      let keyb = key.as_b256();
      let value =
        if proof.value.is_zero() { None } else { Some(encode_fixed_size(&proof.value).to_vec()) };
      let nibbles = Nibbles::unpack(keccak256(key.as_b256()));
      verify_proof(storage_root, nibbles, value, &proof.proof)?;
      // println!("Key: {:?}, Value: {:?}", key, proof.value);
      values.insert(keyb, proof.value.into());
      if !queried_locations_set.contains(&keyb) {
        bail_error!("Key not found in queried locations: {:?}", key);
      }
      queried_locations_set.remove(&keyb);
      Ok(())
    },
  )?;
  if queried_locations_set.len() > 0 {
    bail_error!("Some keys not found in proof: {:?}", queried_locations_set);
  }
  Ok(values)
}

pub async fn get_storage_proof<T: ProviderTrait>(
  provider: Arc<T>,
  contract_address: Address,
  block_number: BlockId,
  addresses: Vec<JsonStorageKey>,
) -> Result<(Vec<JsonStorageKey>, Vec<EIP1186StorageProof>), ThreadSafeError> {
  const MAX_CHUNK_SIZE: usize = 1500;
  const MIN_CHUNK_SIZE: usize = 100;
  let mut chunk_size = MAX_CHUNK_SIZE;
  let mut i = 0;
  let mut ret = Vec::new();
  while i < addresses.len() {
    chunk_size = min(chunk_size, addresses.len() - i);
    {
      let storage_proof = provider
        .get_proof(contract_address, addresses[i..i + chunk_size].to_vec(), Some(block_number))
        .await;
      match storage_proof {
        Ok(storage_proof) => {
          ret.extend(storage_proof.storage_proof);
          i += chunk_size;
          chunk_size = min(MAX_CHUNK_SIZE, chunk_size + (chunk_size >> 1));
        }
        Err(e) => {
          println!("Error getting {:?} sproofs: {:?} ", chunk_size, e);
          chunk_size = max(MIN_CHUNK_SIZE, chunk_size / 2);
          continue;
        }
      }
    }
  }
  tprintln!("Got storage proof for {:?} addresses", ret.len());
  Ok((addresses, ret))
}

pub async fn get_validated_value_at_address<T: ProviderTrait + EthFilterApiClient<u64>>(
  provider: &T,
  contract_address: Address,
  storage_root: B256,
  address: B256,
  block_number: BlockId,
) -> Result<B256, ThreadSafeError> {
  println!("Getting value at address: {:?}", address);
  let locations = vec![JsonStorageKey::Hash(address)];
  let storage_value =
    provider.get_proof(contract_address, locations.clone(), Some(block_number)).await?;

  if storage_value.storage_hash != storage_root {
    bail_error!("Storage root does not match");
  }

  verify_storage_proof(storage_root, &locations, &storage_value.storage_proof)?;

  Ok(storage_value.storage_proof[0].value.into())
}

pub async fn fetch_address_values<'a, T>(
  provider: Arc<T>,
  contract_address: Address,
  block_number: BlockId,
  storage_root: FixedBytes<32>,
  addresses: &'a Vec<JsonStorageKey>,
) -> Result<HashMap<B256, B256>, ThreadSafeError>
where
  T: ProviderTrait + 'a,
{
  tprintln!("Restoring contract memory");
  tprintln!("Total addresses: {:?}", addresses.len());

  const CONCURENCY_LIMIT: usize = 24;
  const CONCURENCY_LIMIT_THREAD: usize = 24;
  const CHUNK_SIZE: usize = 20_000;
  let tasks = FuturesUnordered::new();
  let semaphore = Arc::new(Semaphore::new(CONCURENCY_LIMIT));
  let semaphor2 = Arc::new(Semaphore::new(CONCURENCY_LIMIT_THREAD));
  let failed = Arc::new(Mutex::new(false));

  let ht: Arc<Mutex<HashMap<B256, B256>>> = Arc::new(Mutex::new(HashMap::new()));

  tprintln!("Dispatching tasks");
  for addresses_batch in addresses.chunks(CHUNK_SIZE) {
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
    .for_each_concurrent(CONCURENCY_LIMIT, |res| async {
      let htclone = ht.clone();
      let failed_clone = failed.clone();
      let semaphor2_clone = semaphor2.clone();

      if res.is_err() {
        *failed_clone.lock().await = true;
        return;
      }
      let (addresses, resp) = res.unwrap();
      let res = task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async move {
          // let res2;
          let addresses = addresses.clone();
          let res;
          {
            let _lock = semaphor2_clone.acquire().await;
            res = verify_storage_proof(storage_root, &addresses, &resp);
          }
          if res.is_err() {
            *failed_clone.lock().await = true;
            return;
          }
          let hm = res.unwrap();
          htclone.lock().await.extend(hm);
        });
      })
      .await;

      if res.is_err() {
        *failed.lock().await = true;
      }
    })
    .await;

  CHECK!(!*failed.lock().await);

  let ret = ht.lock().await.clone();

  Ok(ret)
}
