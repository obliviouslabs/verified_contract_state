use alloy_rpc_types::Log;
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use reth_rpc_api::EthFilterApiClient;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::sleep;
use rand::Rng;
use std::cmp::{max, min};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use reth_rpc_api::clients::EthApiClient;
use alloy_rpc_types::{Block, Transaction};
use reth_primitives::{LogData, Receipt};
use reth_revm::primitives::{Address, B256};
use alloy_rpc_types::Filter;
use crate::checkpoints::{get_specific_checkpoint, save_checkpoint};
use crate::{tprintln, CHECK};
use crate::utils::ThreadSafeError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEvent {
  address: Address,
  data: LogData,
  // block_hash: B256,
  block_number: u64,
  block_timestamp: u64, // UNDONE(): deprecate this, it is 0
  // transaction_hash: B256,
  transaction_index: u64,
  log_index: u64,
  // removed: bool
}

impl From<Log> for LogEvent {
  fn from(log: Log) -> Self {
    LogEvent {
      address: log.inner.address,
      data: log.inner.data,
      // block_hash: log.block_hash.unwrap_or_default(),
      block_number: log.block_number.unwrap(),
      block_timestamp: 0, // UNDONE(): deprecate this, it is always
      // transaction_hash: log.transaction_hash.unwrap_or_default(),
      transaction_index: log.transaction_index.unwrap_or_default(),
      log_index: log.log_index.unwrap_or_default(),
      // removed: log.removed
    }
  }
}

impl LogEvent {
  pub fn topics(&self) -> &[B256] {
    self.data.topics()
  }

  pub fn data(&self) -> &LogData {
    &self.data
  }
}


pub async fn get_log_batch<T: EthApiClient<Transaction, Block, Receipt> + Send + Sync + EthFilterApiClient<u64>>(
  provider: &T,
  contract_address: Address,    
  start_block: u64,
  end_block: u64,
) -> Result<Vec<LogEvent>, ThreadSafeError> {
  println!("Getting logs from block {} to {}", start_block, end_block);
  let filter = Filter::new()
      .address(contract_address)
      .from_block(start_block)
      .to_block(end_block);

  let logs = provider.logs(filter).await?.into_iter().map(|log| {
    LogEvent::from(log)
  }).collect();

  Ok(logs)
}


// UNDONE() this is using manual tunning per contract for initilaization based on the log size (large for USDT, small for SHIB)
const LOG_CHUNK_SIZE: u64 = 100_000;
const THROTTLE_SLEEP_MS: u64 = 200;
const CONCURENCY_LIMIT: usize = 8;
const MIN_SIZE: u64 = 10;
// const MAX_SIZE: u64 = 700;
const MAX_SIZE: u64 = 10000;

pub fn is_checkpointable_range(start_block: u64, end_block: u64) -> bool {
     (start_block % LOG_CHUNK_SIZE == 0)
  && ((end_block - start_block + 1) == LOG_CHUNK_SIZE)
}

pub async fn get_log_batch_task<T: EthApiClient<Transaction, Block, Receipt> + Send + Sync + EthFilterApiClient<u64>>(
  provider: &T,
  contract_address: Address,    
  start_block: u64,
  end_block: u64,
) -> Result<Vec<LogEvent>, ThreadSafeError> {
  tprintln!("Getting logs from block {} to {}", start_block, end_block);
  let tag = format!("{}.Logs.{}",  contract_address, LOG_CHUNK_SIZE);
  if start_block / LOG_CHUNK_SIZE == end_block / LOG_CHUNK_SIZE {
    let range_block = start_block - (start_block % LOG_CHUNK_SIZE);
    let cpt = get_specific_checkpoint(tag.as_str(), range_block);
    match cpt {
      Ok(cpt) => {
        let ret = cpt.read::<Vec<LogEvent>>();
        if end_block - start_block + 1 == LOG_CHUNK_SIZE {
          tprintln!("Returning checkpointed logs");
          return ret;
        } else {
          tprintln!("Returning modified logs");
          return Ok(ret?.into_iter().filter(|log| {
            let bn = log.block_number;
            bn >= start_block && bn <= end_block
          }).collect());
        }
      },
      Err(_) => {
      }
    }
  }

  let mut ret = Vec::new();

  let mut oks = 0;
  
  let mut curr_block = start_block;
  let mut lastsize = MAX_SIZE;
  
  let mut last_request_time = std::time::Instant::now();

  while curr_block <= end_block {
    let currsize = min(lastsize, end_block - curr_block);
    
    {
      let now = std::time::Instant::now();
      let elapsed: u64 = now.duration_since(last_request_time).as_millis().try_into().unwrap_or(THROTTLE_SLEEP_MS);
      if elapsed < THROTTLE_SLEEP_MS {
        let sleep_time = THROTTLE_SLEEP_MS - elapsed;
        sleep(Duration::from_millis(sleep_time as u64)).await;
      }
      last_request_time = std::time::Instant::now();
      let provider_ = provider;
      // sleep(Duration::from_millis(500)).await;
      let logs_ = get_log_batch(provider_, contract_address, curr_block, curr_block + currsize).await;
      if let Err(_e) = &logs_ {
          let thread_id = thread::current().id();

          let e_str = logs_.err().unwrap().to_string();
          if e_str.contains("429") {
            tprintln!("[{:?}] Throttled: {:?}", thread_id, e_str);
            let sleep_duration = Duration::from_millis(rand::thread_rng().gen_range(100..=1000));
            sleep(sleep_duration).await;
            continue;
          } else if e_str.contains("Log response size exceeded"){
            tprintln!("[{:?}] Log Size Exceeded: {:?}", thread_id, e_str);
          } else {
            tprintln!("[{:?}] Unknown error getting logs: {:?}", thread_id, e_str);
          }

          // puts erros as string in a string:
          // match e {
          //   Error::Transport(web3::transports::http::Error::Rejected { status_code: 429 })
          // }
          


          lastsize = currsize/2;
          lastsize = max(lastsize, MIN_SIZE);
          oks = min(0, oks-1);
          continue;
      }
      ret.extend(logs_?);
    }

    if oks >= 3 {
      lastsize = min(currsize + (currsize>>1), MAX_SIZE);
    }
    oks = max(oks, oks+1);
    curr_block += currsize + 1;
  }

  if is_checkpointable_range(start_block, end_block) {
    let ok = save_checkpoint(tag.as_str(), start_block, &ret);
    if let Err(e) = ok {
      tprintln!("Error saving checkpoint (ignoring): {:?}", e);
    }
  }

  Ok(ret)
}

pub async fn apply_to_logs<'a, T, F>(
  provider: &'a T,
  contract_address: Address,
  start_block: u64,
  end_block: u64,
  f: F
) -> Result<(), ThreadSafeError>
where T: EthApiClient<Transaction, Block, Receipt> + Send + Sync + EthFilterApiClient<u64>,
      F: Fn(Vec<LogEvent>) -> Result<(), ThreadSafeError> + Send + Sync + 'a
{
  tprintln!("Getting logs between {} and {}", start_block, end_block);

  let mut tasks = FuturesOrdered::new();
  let semaphore = Arc::new(Semaphore::new(CONCURENCY_LIMIT));

  let mut range_start = start_block;
  
  while range_start <= end_block {

  // for range_start in (start_block..(end_block+1)).step_by(LOG_CHUNK_SIZE as usize) {
    let range_end = 
      if range_start % LOG_CHUNK_SIZE == 0 {
        (range_start + (LOG_CHUNK_SIZE - 1) as u64).min(end_block)
      } else {
        (range_start + (LOG_CHUNK_SIZE - 1) - (range_start % LOG_CHUNK_SIZE) as u64).min(end_block)
      };    
    let provider_clone = provider;
    let semaphore_clone = semaphore.clone();
    
    tasks.push_back(async move {
      let mut attempt = 0;
      loop {
        let logs;
        {
          let _permit = semaphore_clone.acquire().await;
          logs = get_log_batch_task(provider_clone, contract_address, range_start, range_end).await;
        }
        match logs {
          Ok(logs) => {
            return logs;
          },
          Err(_) => {
            attempt += 1;
            if attempt > 3 {
              return Vec::new();
            }
          }
        }
      }
    });

    range_start = range_end+1;
  }
  
  let errored = Arc::new(Mutex::new(false));

  tasks.for_each_concurrent(CONCURENCY_LIMIT, |x| {    
    let errored = errored.clone();
    let f = &f;
    async move {
      let e = f(x);
      if let Err(e) = e {
        tprintln!("Error applying to log: {:?}", e);
        *errored.lock().unwrap() = true;
      }
    }
  }).await;

  CHECK!(!*errored.lock().unwrap());

  Ok(())
}


pub async fn get_logs_between<T: EthApiClient<Transaction, Block, Receipt> + Send + Sync + EthFilterApiClient<u64>>(
  provider: &T,
  contract_address: Address,
  start_block: u64,  
  end_block: u64,
) -> Result<Vec<LogEvent>, ThreadSafeError> {
  let ret = Arc::new(Mutex::new(Vec::new()));

  let ret_clone = ret.clone();
  apply_to_logs(provider, contract_address, start_block, end_block, move |logs| {
    ret_clone.lock().unwrap().extend(logs);
    Ok(())
  }).await?;

  let rv = ret.lock().unwrap().clone();

  Ok(rv)
}