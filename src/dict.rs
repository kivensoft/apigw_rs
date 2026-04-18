use std::sync::OnceLock;

use anyhow::Result;
use appcfg::Config;
use compact_str::CompactString;
use fast_radix_trie::GenericRadixMap;
use tokio::sync::RwLock;

type DictMap = GenericRadixMap<String, CompactString>;

static DICT_MAP: OnceLock<RwLock<DictMap>> = OnceLock::new();

/// 获取字典项, 精确匹配key
#[allow(dead_code)]
pub async fn get<K: Into<String> + AsRef<str>>(key: K) -> Option<CompactString> {
    let map = get_instance().read().await;
    map.get(key).cloned()
}

/// 获取字典项, 模糊匹配key前缀, 建议查询前缀时结尾自带分隔符, 例如 "common.mysql."
pub async fn query(key_prefix: &str) -> Vec<(String, CompactString)> {
    let map = get_instance().read().await;
    let mut ret = Vec::with_capacity(32);
    for (key, value) in map.iter_prefix(key_prefix) {
        ret.push((key, value.clone()));
    }

    ret
}

pub async fn load(path: &str) -> Result<()> {
    // 将文件中的键值对，转换到map
    let cfg = match Config::with_file(path) {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::warn!(%err, %path, "加载公共配置失败");
            anyhow::bail!(err);
        }
    };

    let mut map = get_instance().write().await;

    map.clear();

    for (key, value) in cfg.iter() {
        map.insert(key, CompactString::new(value));
    }
    tracing::info!(%path, "加载公共配置成功");

    Ok(())
}

fn get_instance() -> &'static RwLock<DictMap> {
    DICT_MAP.get_or_init(|| RwLock::new(DictMap::new()))
}
