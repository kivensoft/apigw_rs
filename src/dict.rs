use std::collections::HashMap;

use anyhow::{Result, Context};
use appconfig::Config;
use compact_str::CompactString;
use parking_lot::RwLock;
use serde::Serialize;
use triomphe::Arc;

lazy_static::lazy_static! {
    static ref DICT_MAP: RwLock<DictMap> = RwLock::new(DictMap::new());
}

pub type DictItems = Arc<Vec<DictItem>>;
type DictMap = HashMap<CompactString, DictItems>;

#[derive(Serialize, Clone)]
pub struct DictItem {
    pub key: CompactString,
    pub value: CompactString,
}

pub fn query(group: &str) -> Option<DictItems> {
    DICT_MAP.read().get(group).cloned()
}

pub fn load(filename: &str) -> Result<()> {
    // 将文件中的键值对，转换到map
    let cfg = Config::with_file(filename).context("load cfgdata error")?;
    let mut new_map = DictMap::new();

    for (key, value) in cfg.iter() {
        if let Some((k1, k2)) = key.split_once('.') {
            let items = new_map.get_mut(k1);

            let items = match items {
                Some(items) => items,
                None => {
                    let rec = Arc::new(Vec::new());
                    new_map.insert(CompactString::new(k1), rec);
                    new_map.get_mut(k1).unwrap()
                }
            };

            Arc::get_mut(items).unwrap().push(DictItem {
                key: CompactString::new(k2),
                value: CompactString::new(value),
            });
            log::trace!("[dict.load] add config [key = {}, value = {}]", k2, value);
        }
    }

    *DICT_MAP.write() = new_map;

    Ok(())
}
