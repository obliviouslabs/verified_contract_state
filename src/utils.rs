use alloy_primitives::{B256, U256};
use alloy_rpc_types::{Block, Receipt, Transaction, Header};
use reth_rpc_api::{EthApiClient, EthFilterApiClient};

#[macro_export]
macro_rules! bail_error {
  ($fmt:expr) => {
      return Err(ThreadSafeError::from(format!($fmt)));
  };
  ($fmt:expr, $($arg:tt)*) => {
      return Err(ThreadSafeError::from(format!($fmt, $($arg)*)));
  };
}

#[macro_export]
macro_rules! CHECK {
  ($cond:expr) => {
    if !$cond {
      crate::bail_error!("Check failed: {:?}", stringify!($cond));
    }
  };
}

#[macro_export]
macro_rules! tprintln {
  ($fmt:expr) => {
      println!("[{:?}] {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(), $fmt);
  };
  ($fmt:expr, $($arg:tt)*) => {
      println!("[{:?}] {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(), format!($fmt, $($arg)*));
  };
}

pub type ThreadSafeError = Box<dyn std::error::Error + Send + Sync>;

pub fn b256(val: u64) -> B256 {
  B256::from(U256::from(val))
}

pub trait ProviderTrait:
  EthApiClient<Transaction, Block, Receipt, Header> + Send + Sync + EthFilterApiClient<u64>
{
}

impl<T> ProviderTrait for T where
  T: EthApiClient<Transaction, Block, Receipt, Header> + Send + Sync + EthFilterApiClient<u64>
{
}

// pub (crate) use bail_error;
// pub (crate) use CHECK;
// pub (crate) use tprintln;
