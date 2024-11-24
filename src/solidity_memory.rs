use reth_revm::primitives::{keccak256, ruint::Uint, B256, U256};
use std::collections::HashSet;

pub fn add_static_array_addresses(
  _name: &str,
  addresses: &mut HashSet<B256>,
  slot: B256,
  size: u64,
) {
  let slot = U256::from_be_bytes(slot.0);
  for i in 0..size {
    let offset = U256::from(i);
    let location = B256::from(slot + offset);
    addresses.insert(location);
  }
}

pub fn add_string_addresses(_name: &str, addresses: &mut HashSet<B256>, slot: B256, max_size: u64) {
  let slot = U256::from_be_bytes(slot.0);
  {
    addresses.insert(B256::from(slot));
  }
  if max_size > 31 {
    let base_addr = keccak256(B256::from(slot));
    for i in 0..(max_size / 32 + 2) {
      let local_base: Uint<256, 4> = U256::from_be_bytes(base_addr.0);
      let local_slot = local_base.wrapping_add(U256::from(i));
      let location = B256::from(local_slot);
      addresses.insert(location);
    }
  }
}

// #[allow(dead_code)]
pub fn add_dynamic_array_addresses(
  _name: &str,
  addresses: &mut HashSet<B256>,
  slot: B256,
  max_size: u64,
) {
  let slot = U256::from_be_bytes(slot.0);
  {
    addresses.insert(B256::from(slot));
  }
  if max_size > 0 {
    let base_addr = keccak256(B256::from(slot));
    for i in 0..max_size {
      let local_base: Uint<256, 4> = U256::from_be_bytes(base_addr.0);
      let local_slot = local_base.wrapping_add(U256::from(i));
      let location = B256::from(local_slot);
      addresses.insert(location);
    }
  }
}

pub fn get_mapping_address(slot: &B256, key: &B256) -> B256 {
  let slot_bytes = slot.0;
  let key_bytes = key.0;
  let mut concat_bytes = [0u8; 64];
  concat_bytes[..32].copy_from_slice(&key_bytes);
  concat_bytes[32..].copy_from_slice(&slot_bytes);

  let res = keccak256(concat_bytes);

  B256::from(res)
}

pub fn add_mapping_addresses<'a, T: Iterator<Item = &'a B256>>(
  _name: &str,
  addresses: &mut HashSet<B256>,
  slot: B256,
  access_keys: T,
) {
  {
    addresses.insert(slot);
  }
  for key in access_keys {
    let location = get_mapping_address(&slot, key);

    addresses.insert(location);
  }
}

pub fn get_2d_mapping_address(slot: &B256, key1: &B256, key2: &B256) -> B256 {
  let slot_bytes = slot.0;
  let key1_bytes = key1.0;
  let key2_bytes = key2.0;
  let mut concat_bytes = [0u8; 64];

  concat_bytes[..32].copy_from_slice(&key1_bytes);
  concat_bytes[32..].copy_from_slice(&slot_bytes);

  let h1 = keccak256(concat_bytes);
  concat_bytes[..32].copy_from_slice(&key2_bytes);
  concat_bytes[32..].copy_from_slice(&h1.0);

  let res = keccak256(concat_bytes);

  B256::from(res)
}

pub fn add_2d_mapping_addresses<'a, T: Iterator<Item = &'a (B256, B256)>>(
  _name: &str,
  addresses: &mut HashSet<B256>,
  slot: B256,
  access_keys: T,
) {
  {
    addresses.insert(slot);
  }
  for (key1, key2) in access_keys {
    let location = get_2d_mapping_address(&slot, key1, key2);
    addresses.insert(location);
  }
}
