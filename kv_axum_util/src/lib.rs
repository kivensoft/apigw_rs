mod axum_ext;
mod reqid;
mod scheduler;
mod tracing_ext;

pub use axum_ext::*;
pub use kv_axum_proc_macro::{api, api_get, api_post, bean};
pub use kv_axum_route::{RouteEntry, build_router, inventory};
pub use reqid::{ReqId, ReqIdGenerator, req_id_middleware};
pub use scheduler::SimpleScheduler;
pub use tracing_ext::{DATETIME_FORMAT, TracingBuilder, custom_trace_layer, now_str, now_str_into};

/// 获取当前时间基于UNIX_EPOCH的秒数
pub fn unix_timestamp() -> u64 {
    use std::time::{Duration, SystemTime};
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// 从 vec 中删除 indices 指定索引值的元素, indices 的索引值必须从小到大排列,
/// 注意, 删除的方式是从后到前, 将数组最后1个元素移动到被删除位置, 从而避免整个移动数组,
/// 但这样的缺点是删除后排序与原来的并不一致
pub fn remove_from_vec<T>(vec: &mut Vec<T>, indices: &[u32]) {
    for &idx in indices.iter().rev() {
        let idx = idx as usize;
        if let Some(last) = vec.pop() {
            let last_idx = vec.len();
            if idx != last_idx {
                let _ = std::mem::replace(&mut vec[idx], last);
            }
        }
    }
}
