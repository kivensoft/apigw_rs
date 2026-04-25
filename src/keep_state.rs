use std::path::MAIN_SEPARATOR;

use compact_str::CompactString;
use kv_axum_util::{bean, unix_timestamp};
use tracing::{info, warn};

use crate::{
    apis::{self, RateReq},
    appvars::RATE_LIMITER_STATE,
    get_app_path,
    proxy::{self, EndpointConfig},
    rate_limit::RateLimitCfg,
};

const RUNNING_STATE_FILE: &str = "running_state.json";

#[bean]
struct ServiceItem {
    path: CompactString,
    cfg: EndpointConfig,
}

#[bean]
struct RateLimitItem {
    path: CompactString,
    cfg: RateLimitCfg,
}

#[bean]
struct RunningState {
    services: Vec<ServiceItem>,
    rate_limits: Vec<RateLimitItem>,
}

pub fn save_state() {
    info!("保存状态...");

    // 保存反向代理信息
    let mut services = Vec::new();
    for (path, endpoints_cfg) in proxy::SERVICES.read().iter() {
        let path = unsafe { std::str::from_utf8_unchecked(&path) };
        let path = CompactString::from(path);

        for endpoint_cfg in endpoints_cfg.lock().iter() {
            services.push(ServiceItem { path: path.clone(), cfg: endpoint_cfg.clone() });
        }
    }

    // 保存限速器信息
    let mut rate_limits = Vec::new();
    for (path, cfg) in RATE_LIMITER_STATE.query("") {
        rate_limits.push(RateLimitItem { path, cfg });
    }

    let state = RunningState { services, rate_limits };

    // 写入到文件中
    let data = serde_json::to_vec(&state).unwrap();
    let cfg_path = get_state_file();
    std::fs::write(&cfg_path, &data).unwrap();
}

pub fn load_state() {
    info!("加载状态...");

    let state_bytes = match std::fs::read(get_state_file()) {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(%err, "加载应用程序运行状态失败");
            return;
        },
    };

    let state: RunningState = match serde_json::from_slice(&state_bytes) {
        Ok(state) => state,
        Err(err) => {
            warn!(%err, "反序列化应用程序运行状态失败");
            return;
        },
    };

    let now = unix_timestamp();

    // 恢复反向代理信息
    for item in state.services.into_iter() {
        if item.cfg.expire_at != 0 && item.cfg.expire_at < now {
            continue;
        }
        let ttl = item.cfg.expire_at.saturating_sub(now);
        proxy::register_service(&item.path, &item.cfg.endpoint, ttl as u32);
    }

    // 恢复限速器信息
    for item in state.rate_limits.into_iter() {
        let req = RateReq {
            path: item.path,
            rtype: item.cfg.rtype as u32,
            per_second: item.cfg.per_second,
            seconds: item.cfg.seconds,
            allow_burst: item.cfg.allow_burst,
        };
        let _ = apis::rate(req);
    }
}

fn get_state_file() -> String {
    let app_path = get_app_path();
    format!("{}{}{}", app_path, MAIN_SEPARATOR, RUNNING_STATE_FILE)
}
