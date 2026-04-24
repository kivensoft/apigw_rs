use std::sync::{Arc, OnceLock};

use anyhow::Result;
use appcfg::Config;
use arc_swap::ArcSwap;
use compact_str::CompactString;
use fast_radix_trie::RadixMap;
use tracing::{info, warn};

type DictMap = RadixMap<CompactString>;

static DICT_MAP: OnceLock<ArcSwap<DictMap>> = OnceLock::new();

/// 获取字典项, 模糊匹配key前缀, 建议查询前缀时结尾自带分隔符, 例如 "common.mysql."
pub fn query(key_prefix: &str) -> Vec<(String, CompactString)> {
    // 删除 key 末尾的 '.' 字符
    fn trim_end(key: Vec<u8>) -> String {
        let mut key = unsafe { String::from_utf8_unchecked(key) };
        if key.ends_with('.') {
            key.pop();
        }
        key
    }

    let mut key_prefix = CompactString::from(key_prefix);
    if !key_prefix.is_empty() && !key_prefix.ends_with('.') {
        key_prefix.push('.');
    }

    let mut ret = Vec::with_capacity(32);
    let map = get_instance().load();
    tracing::debug!(%key_prefix, "查询路径");
    if !key_prefix.is_empty() {
        for (key, value) in map.iter_prefix(&key_prefix) {
            ret.push((trim_end(key), value.clone()));
        }
    } else {
        for (key, value) in map.iter() {
            ret.push((trim_end(key), value.clone()));
        }
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
        // key 在末尾添加 '.'
        let mut key = CompactString::from(key);
        if !key.is_empty() && !key.ends_with('.') {
            key.push('.');
        }

        map.insert(&key, value.into());
    }

    get_instance().store(Arc::new(map));
    info!(%path, "加载公共配置成功");

    Ok(())
}

fn get_instance() -> &'static ArcSwap<DictMap> {
    DICT_MAP.get_or_init(|| ArcSwap::from_pointee(DictMap::new()))
}
