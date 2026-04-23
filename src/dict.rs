use std::sync::{Arc, OnceLock};

use anyhow::Result;
use appcfg::Config;
use arc_swap::ArcSwap;
use compact_str::CompactString;
use fast_radix_trie::GenericRadixMap;
use tracing::{info, warn};

type DictMap = GenericRadixMap<String, CompactString>;

static DICT_MAP: OnceLock<ArcSwap<DictMap>> = OnceLock::new();

/// 获取字典项, 精确匹配key
#[allow(dead_code)]
pub fn get<K: Into<String> + AsRef<str>>(key: K) -> Option<CompactString> {
    get_instance().load().get(key).cloned()
}

/// 获取字典项, 模糊匹配key前缀, 建议查询前缀时结尾自带分隔符, 例如 "common.mysql."
pub fn query(key_prefix: &str) -> Vec<(String, CompactString)> {
    let mut ret = Vec::with_capacity(32);
    let map = get_instance().load();
    for (key, value) in map.iter_prefix(key_prefix) {
        ret.push((key, value.clone()));
    }

    ret
}

pub fn load(path: &str) -> Result<()> {
    // 将文件中的键值对，转换到map
    let cfg = match Config::with_file(path) {
        Ok(cfg) => cfg,
        Err(err) => {
            warn!(%err, %path, "加载公共配置失败");
            anyhow::bail!(err);
        }
    };

    let mut map = DictMap::new();
    for (key, value) in cfg.iter() {
        map.insert(key, value.into());
    }

    get_instance().store(Arc::new(map));
    info!(%path, "加载公共配置成功");

    Ok(())
}

fn get_instance() -> &'static ArcSwap<DictMap> {
    DICT_MAP.get_or_init(|| ArcSwap::from_pointee(DictMap::new()))
}
