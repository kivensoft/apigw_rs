use anyhow_ext::{Result, Context};
use appcfg::Config;
// use arc_swap::ArcSwapOption;
use compact_str::CompactString;
use qp_trie::{wrapper::BString, Trie};
use serde::Serialize;
use triomphe::Arc;

pub type DictItems = Vec<DictItem>;
type DictValue = Arc<CompactString>;
type DictData = Trie<BString, DictValue>;

// static DICT_MAP: ArcSwapOption<DictData> = ArcSwapOption::const_empty();
static mut DICT_MAP: Option<Arc<DictData>> = None;

#[derive(Serialize, Clone)]
pub struct DictItem {
    pub key: CompactString,
    pub value: DictValue,
}

pub fn query(key_prefix: &str) -> Option<DictItems> {
    // let dict_data = DICT_MAP.load();
    // let dict_data = match dict_data.as_ref() {
    let dict_data = match unsafe { &DICT_MAP } {
        Some(v) => v.clone(),
        None => {
            log::warn!("config data is None");
            return None;
        }
    };

    let items: Vec<_> = dict_data
        .iter_prefix_str(key_prefix)
        .map(|(k, v)| DictItem::new(k.as_str(), v.clone()))
        .collect();

    if !items.is_empty() {
        Some(items)
    } else {
        None
    }
}

pub fn load(filename: &str) -> Result<()> {
    // 将文件中的键值对，转换到map
    let cfg = Config::with_file(filename).with_context(|| format!("load {} fail", filename))?;
    let mut dict_data = DictData::new();

    for (key, value) in cfg.iter() {
        dict_data.insert_str(key, Arc::new(CompactString::new(value)));
    }

    // DICT_MAP.store(Some(std::sync::Arc::new(dict_data)));
    unsafe { DICT_MAP = Some(Arc::new(dict_data)); }

    Ok(())
}

impl DictItem {
    pub fn new(key: &str, value: Arc<CompactString>) -> Self {
        DictItem {
            key: CompactString::new(key),
            value,
        }
    }
}
