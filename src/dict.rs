use std::{collections::HashMap, sync::OnceLock};

use anyhow::{Result, Context};
use appconfig::Config;
use compact_str::CompactString;
use dashmap::DashMap;
use serde::Serialize;
use triomphe::Arc;

static DICT_MAP: OnceLock<DictMap> = OnceLock::new();

pub type DictItems = Arc<Vec<DictItem>>;
type DictMap = DashMap<CompactString, DictItems>;

#[derive(Serialize, Clone)]
pub struct DictItem {
    pub key: CompactString,
    pub value: CompactString,
}

pub fn query(group: &str) -> Option<DictItems> {
    get_dict_map().get(group).map(|v| v.value().clone())
}

pub fn load(filename: &str) -> Result<()> {
    // 将文件中的键值对，转换到map
    let cfg = Config::with_file(filename).context("load cfgdata error")?;
    let mut tmp_map = HashMap::<CompactString, Vec<DictItem>>::new();

    for (key, value) in cfg.iter() {
        if let Some((k1, k2)) = key.split_once('.') {
            let dict_item = DictItem {
                key: CompactString::new(k2),
                value: CompactString::new(value),
            };

            match tmp_map.get_mut(k1) {
                Some(v) => { v.push(dict_item); }
                None => { tmp_map.insert(CompactString::new(k1), vec![dict_item]); }
            }

            log::trace!("[dict.load] add config [group = {}, key = {}, value = {}]", k1, k2, value);
        }
    }

    let new_map = DictMap::with_capacity(tmp_map.len());
    for (k, v) in tmp_map.into_iter() {
        new_map.insert(k, Arc::new(v));
    }

    if DICT_MAP.set(new_map).is_err() {
        log::error!("[dict.load] set dict map failed");
    }

    Ok(())
}

fn get_dict_map() -> &'static DictMap {
    DICT_MAP.get_or_init(DictMap::new)
}
