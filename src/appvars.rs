use std::sync::OnceLock;

use compact_str::CompactString;

pub struct AppVar {
    pub startup_time: u64,
    pub heart_break_live_time: u32,
    pub redis_ttl: u32,
    pub use_redis: bool,
    pub jwt_key: CompactString,
    pub jwt_issuer: CompactString,
    pub jwt_ttl: u32,
    pub dict_file: CompactString,
    pub srv_conn_timeout: u32,
}

static APP_VAR: OnceLock<AppVar> = OnceLock::new();

pub fn init(av: AppVar) {
    if APP_VAR.set(av).is_err() {
        panic!("APP_VAR already initialized");
    }
}

pub fn get() -> &'static AppVar {
    debug_assert!(APP_VAR.get().is_some());
    match APP_VAR.get() {
        Some(v) => v,
        None => unsafe { std::hint::unreachable_unchecked() },
    }
}
