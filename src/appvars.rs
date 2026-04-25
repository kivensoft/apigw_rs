use std::sync::LazyLock;

use kv_axum_util::SimpleScheduler;

use crate::{rate_limit::RateLimiterState, static_val::StaticVal};

pub struct AppVar {
    pub startup_time: u64,
    pub heartbeat_interval: u32,
    pub jwt_ttl: u32,
    pub redis_ttl: u32,
    // pub use_redis: bool,
    pub srv_conn_timeout: u32,
}

pub static APP_VAR: StaticVal<AppVar> = StaticVal::new();

pub static SCHEDULER: LazyLock<SimpleScheduler> = LazyLock::new(|| SimpleScheduler::new(60));
pub static RATE_LIMITER_STATE: LazyLock<RateLimiterState> = LazyLock::new(RateLimiterState::new);
// pub static REDIS_CLIENT: StaticVal<RedisClient> = StaticVal::new();

pub const BANNER: &str = r#"
    ___          _    ______      __  Kivensoft ?
   /   |  ____  (_)  / ____/___ _/ /____ _      ______ ___  __
  / /| | / __ \/ /  / / __/ __ `/ __/ _ \ | /| / / __ `/ / / /
 / ___ |/ /_/ / /  / /_/ / /_/ / /_/  __/ |/ |/ / /_/ / /_/ /
/_/  |_/ .___/_/   \____/\__,_/\__/\___/|__/|__/\__,_/\__, /
      /_/                                            /____/
"#;

pub const APP_NAME: &str = include_str!(concat!(env!("OUT_DIR"), "/.app_name"));
/// app版本号, 来自编译时由build.rs从cargo.toml中读取的版本号(读取内容写入.version文件)
pub const APP_VER: &str = include_str!(concat!(env!("OUT_DIR"), "/.version"));
