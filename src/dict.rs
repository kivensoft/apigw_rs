use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, bail};
use appcfg::Config;
use qp_trie::{Trie, wrapper::BString};
use serde::Serialize;

use crate::efmt;

pub type DictItems = Vec<DictItem>;
type DictValue = Arc<String>;
type DictData = Trie<BString, DictValue>;

#[derive(Serialize, Clone)]
pub struct DictItem {
    pub key: String,
    pub value: DictValue,
}


static DICT_MAP: OnceLock<Arc<DictData>> = OnceLock::new();


pub fn query(key_prefix: &str) -> Option<DictItems> {
    let dict_data = match DICT_MAP.get() {
        Some(v) => v.clone(),
        None => {
            log::error!("dict.rs::DICT_MAP not initialized");
            return None;
        }
    };

    let items: Vec<_> = dict_data
        .iter_prefix_str(key_prefix)
        .map(|(k, v)| DictItem::new(k.as_str(), v.clone()))
        .collect();

    if !items.is_empty() { Some(items) } else { None }
}

pub fn load(filename: &str) -> Result<()> {
    // 将文件中的键值对，转换到map
    let cfg = Config::with_file(filename)
        .with_context(|| format!("load {} fail", filename))
        .with_context(|| efmt!("load dict fail"))?;
    let mut dict_data = DictData::new();

    for (key, value) in cfg.iter() {
        dict_data.insert_str(key, Arc::new(String::from(value)));
    }

    match DICT_MAP.set(Arc::new(dict_data)) {
        Ok(_) => Ok(()),
        Err(_) => bail!("dict.rs, The variable has already been initialized"),
    }
}

impl DictItem {
    pub fn new(key: &str, value: Arc<String>) -> Self {
        DictItem {
            key: String::from(key),
            value,
        }
    }
}
