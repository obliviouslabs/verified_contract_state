use crate::bail_error;
use crate::utils::ThreadSafeError;
use crate::CHECK;

use alloy_rlp::Decodable;
use alloy_rlp::Header;
use alloy_rpc_types::EIP1186StorageProof;
use alloy_trie::nodes::CHILD_INDEX_RANGE;
use futures::lock::Mutex;
use reth_revm::primitives::keccak256;
use reth_revm::primitives::FixedBytes;
use std::io::Read;
use std::sync::Arc;

use reth_trie_common::BranchNode;

use reth_revm::primitives::{Bytes, B256};
use reth_trie_common::Nibbles;
use reth_trie_common::TrieNode;
use std::collections::HashMap;

pub struct RecoveringTrie {
  pub root: B256,
  pub nodes: HashMap<B256, TrieNode>, // the nodes themselves
                                      // sources: HashMap<B256, NodeQuery> // the query that was used to fetch the node.
}

impl RecoveringTrie {
  pub fn new() -> Self {
    RecoveringTrie {
      root: B256::default(),
      nodes: HashMap::new(),
      // sources: HashMap::new(),
    }
  }

  fn _verify_branch(
    &self,
    branch: BranchNode,
    ret: &mut HashMap<B256, B256>,
    walked_path: &Nibbles,
  ) -> Result<(), ThreadSafeError> {
    // println!("Verifying branch: {:?}", branch);
    // let mut buf = BytesMut::with_capacity(branch.length());
    // branch.encode(&mut buf);
    // let node_hash = keccak256(&buf[..]);
    // println!("Node hash: {:?}", node_hash);

    let mut stack_ptr = branch.as_ref().first_child_index();
    for index in CHILD_INDEX_RANGE {
      if !branch.state_mask.is_bit_set(index) {
        continue;
      }

      let child = branch.stack[stack_ptr].clone();
      stack_ptr += 1;
      let mut nibbles_copy = walked_path.clone();
      nibbles_copy.push(index);
      self._verify_recursive_bytes(&mut &child[..], ret, nibbles_copy)?;
    }
    Ok(())
  }

  fn _verify_recursive_bytes(
    &self,
    current: &mut &[u8],
    ret: &mut HashMap<B256, B256>,
    walked_path: Nibbles,
  ) -> Result<(), ThreadSafeError> {
    CHECK!(walked_path.len() <= 64);

    // println!("Current: {:?}", current);
    let node_res = TrieNode::decode(&mut &current[..]);

    if node_res.is_err() {
      // Decode current as a hash.
      let child_hash = match Header::decode_raw(current)? {
        alloy_rlp::PayloadView::List(list) => {
          bail_error!("Expected str, got {:?}", list);
        }
        alloy_rlp::PayloadView::String(val) => {
          CHECK!(!val.is_empty());
          CHECK!(val.len() == 32);
          B256::from_slice(&val)
        }
      };
      // println!("Child hash: {:?}", child_hash);
      // println!("Walked_path: {:?}", walked_path);
      let node2 = self.nodes.get(&child_hash).ok_or(format!("Missing node: {}", child_hash))?;
      // println!("Node: {:?}", node2);
      self._verify_recursive_node(&node2, ret, walked_path)?;
      Ok(())
    } else {
      let node = node_res?;
      // println!("Node: {:?}", node);
      self._verify_recursive_node(&node, ret, walked_path)?;
      Ok(())
    }
  }

  fn _verify_recursive_node(
    &self,
    node: &TrieNode,
    ret: &mut HashMap<B256, B256>,
    walked_path: Nibbles,
  ) -> Result<(), ThreadSafeError> {
    if walked_path.len() == 64 {
      bail_error!("Walked path too long");
    }

    match node {
      TrieNode::Branch(branch) => {
        self._verify_branch(branch.clone(), ret, &walked_path)?;
      }
      TrieNode::Extension(extension) => {
        let mut nibbles_copy = walked_path.clone();
        nibbles_copy.extend_from_slice(&extension.key);
        let next = &mut &extension.child[..];
        CHECK!(nibbles_copy.len() <= 64);
        self._verify_recursive_bytes(next, ret, nibbles_copy)?;
      }
      TrieNode::Leaf(leaf) => {
        let mut nibbles_copy = walked_path.clone();
        nibbles_copy.extend_from_slice(&leaf.key);
        CHECK!(nibbles_copy.len() == 64);

        let key = B256::from_slice(&nibbles_copy.pack());
        // println!("Key: {:?}", key);
        // println!("Value: {:?}", leaf.value);
        let value = Bytes::decode(&mut &leaf.value[..])?;
        // println!("Value: {:?}", value);
        let value_bytes = value.bytes().collect::<Result<Vec<u8>, _>>()?;
        // println!("Value bytes: {:?}", value_bytes);
        let mut fixed_bytes = [0u8; 32];
        fixed_bytes[(32 - value_bytes.len())..].copy_from_slice(&value_bytes[..]);
        let actual_val = B256::from_slice(&fixed_bytes[..]);
        // println!("Value: {:?}", actual_val);

        ret.insert(key, actual_val);
        // CHECK!(ret.contains_key(&key));
        // CHECK!(ret[&key] == B256::from_slice(&leaf.value[..]));
      }
      TrieNode::EmptyRoot => {
        bail_error!("Empty root node, verify fails (TODO: it should not necessarily fail_");
      }
    }
    Ok(())
  }

  pub fn verify(
    &self,
    storage_root: FixedBytes<32>,
    ret: &mut HashMap<B256, B256>,
  ) -> Result<(), ThreadSafeError> {
    CHECK!(storage_root == self.root);

    let root_node = self.nodes.get(&self.root).ok_or("Root node not found")?;
    self._verify_recursive_node(root_node, ret, Nibbles::default())?;

    Ok(())
  }
}

fn reconstruct_step_branch_node(
  branch_node: &BranchNode,
  current_tree: &Arc<Mutex<RecoveringTrie>>,
) -> Result<Option<Vec<u8>>, ThreadSafeError> {
  let branch = &mut branch_node.clone();

  let mut _stack_ptr = 0;
  for index in CHILD_INDEX_RANGE {
    if !branch.state_mask.is_bit_set(index) {
      continue;
    }
    let child = branch.stack[_stack_ptr].clone();
    _stack_ptr += 1;
    if child.len() == B256::len_bytes() + 1 {
      // It's a leaf node indexed by hash, it should be in the next level of the proof, we can exit for now.
      // println!("Leaf node indexed by hash: {:?}", hex::encode(&child));
      return Ok(Some(child.to_vec()));
    } else {
      // The node is encoded in place
      match TrieNode::decode(&mut &child[..])? {
        TrieNode::Branch(child_branch) => {
          return reconstruct_step_branch_node(&child_branch, current_tree);
        }
        TrieNode::Extension(child_extension) => {
          match TrieNode::decode(&mut &child_extension.child[..])? {
            TrieNode::Branch(extension_child_branch) => {
              return reconstruct_step_branch_node(&extension_child_branch, current_tree);
            }
            node @ (TrieNode::EmptyRoot | TrieNode::Extension(_) | TrieNode::Leaf(_)) => {
              unreachable!("unexpected extension node child: {node:?}")
            }
          }
        }
        TrieNode::Leaf(child_leaf) => {
          return Ok(Some(child_leaf.value));
        }
        TrieNode::EmptyRoot => {
          bail_error!("Empty root node in branch node");
        }
      }
    }
  }

  Ok(Some(Vec::<u8>::default()))
}

pub async fn reconstruct_tree_from_verified_storage_proof(
  storage_proof: EIP1186StorageProof,
  current_tree: &Arc<Mutex<RecoveringTrie>>,
) -> Result<(), ThreadSafeError> {
  // println!("Reconstructing tree from storage proof");
  // let mut idx = 0;
  // let rnd = keccak256(storage_proof.key.0);
  for node in storage_proof.proof {
    // idx += 1;
    let current_node = TrieNode::decode(&mut &node[..])?;
    let expected_hash = keccak256(node.to_vec());
    // println!()
    match current_node {
      TrieNode::Branch(ref branch) => reconstruct_step_branch_node(&branch, &current_tree)?,
      TrieNode::Extension(ref extension) => Some(extension.child.to_vec()),
      TrieNode::Leaf(ref _leaf) => None,
      TrieNode::EmptyRoot => {
        bail_error!("Empty root node in proof");
      }
    };

    // println!("[{:?}][{:?}] Expected hash: {:?}", rnd, idx, expected_hash);
    {
      let mut current_tree = current_tree.lock().await;
      if !current_tree.nodes.contains_key(&expected_hash) {
        // println!("[{:?}][{:?}] Current node: {:?}", rnd, idx, current_node);
        // current_tree.nodes.insert(expected_hash, current_node);
        // current_tree.sources.insert(expected_hash, key);
      }
      current_tree.nodes.insert(expected_hash, current_node);
      // current_tree.sources.insert(expected_hash, key);
    }
  }

  Ok(())
}
