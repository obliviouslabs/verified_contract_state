use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::io::BufWriter;
use serde::Deserialize;
use serde::Serialize;

use std::io::BufReader;

use crate::tprintln;
use crate::utils::ThreadSafeError;
use crate::CHECK;

const CPT_BASE_DIR: &str = "checkpoints";

#[derive(Clone, Default)]
pub struct CheckPoint{
  pub block: u64,
  pub path: PathBuf
}

impl CheckPoint {
  pub fn read<T>(&self) -> Result<T, ThreadSafeError> 
  where 
    T: for<'de> Deserialize<'de>,
  {
    const CAPACITY: usize = 100 * 1024 * 1024;

    let file = OpenOptions::new()
      .read(true)
      .open(&self.path)?;

    let buf_reader = BufReader::with_capacity(CAPACITY, file);
    
    let ret: T = bincode::deserialize_from(buf_reader)?;
    // let ret: T = serde_json::from_reader(buf_reader)?;

    Ok(ret)
  }
}


pub fn save_checkpoint<T: Serialize>(
  tag: &str,
  block: u64,
  data: &T
) -> Result<CheckPoint, ThreadSafeError> {
  const CAPACITY: usize = 100 * 1024 * 1024;
  tprintln!("Saving checkpoint for {} at block {}", tag, block);

  let filename = format!("{}/{}_{}_.cpt", CPT_BASE_DIR, tag, block);
  let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&filename)
                .unwrap();
  let buf_writer = BufWriter::with_capacity(CAPACITY, file);

  bincode::serialize_into(buf_writer, data).unwrap()
  ;
  // serde_json::to_writer(buf_writer, data)?;
    
  Ok(CheckPoint{block: block, path: PathBuf::from(filename)})
}

// File format is: tag_block_timestamp_.cpt
//
pub fn get_checkpoints_for_tag(
  tag: &str
) -> Result<Vec<CheckPoint>, ThreadSafeError> {
  tprintln!("Getting checkpoint for {}", tag);
  let files: Vec<PathBuf> = fs::read_dir(CPT_BASE_DIR)?
    .filter_map(|res| res.ok().and_then(|e| {
      let path = e.path();      
      if e.file_type().ok()?.is_file() {
        let filename = path.file_name()?.to_str()?;
        let filetag = filename.split("_").nth(0)?;
        if filename.ends_with(".cpt") && filetag == tag {
          Some(path)
        } else {
          None
        }
      } else {
        None
      }
    }))
    .collect();

    let ret =  files.iter().filter_map(|path| {
      let filename = path.file_name()?.to_str()?;
      let parts = filename.split("_").collect::<Vec<_>>();
      let fileblock = parts.get(1)?.parse::<u64>().ok()?;
      // tprintln!("Found checkpoint file: {:?}", path);
      Some(CheckPoint{block: fileblock, path: path.clone()})
    }).collect::<Vec<CheckPoint>>();

    Ok(ret)
}

pub fn get_specific_checkpoint(
  tag: &str,
  block: u64
) -> Result<CheckPoint, ThreadSafeError> {
  tprintln!("Getting checkpoint {} for {}", block, tag);
  let cpts = get_checkpoints_for_tag(tag)?;
  let cpts = cpts.iter().filter(|cpt| cpt.block == block).collect::<Vec<&CheckPoint>>();
  
  CHECK!(cpts.len() != 0);
  tprintln!("Using checkpoint: {:?}", cpts[0].path);
  Ok(cpts[0].clone())
}

pub fn get_most_recent_checkpoint(
  tag: &str, 
  block: u64
) -> Result<CheckPoint, ThreadSafeError> {
  tprintln!("Getting checkpoint <= {} for {}", block, tag);
  let cpts = get_checkpoints_for_tag(tag)?;
  let cpts = cpts.iter().filter(|cpt| cpt.block <= block).collect::<Vec<&CheckPoint>>();
  
  CHECK!(cpts.len() != 0);
  let mut ret: CheckPoint = cpts[0].clone();
  for cpt in cpts {
    if cpt.block >= ret.block {
      ret = cpt.clone();
    }
  }

  tprintln!("Using checkpoint: {:?}", ret.path);
  Ok(ret)
}