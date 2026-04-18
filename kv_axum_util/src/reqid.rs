//! 请求id生成中间件, 用于在每个新的http请求中生成一个自增的id
//! 建议将该中间件作为 axum 的第一个中间件, 这样确保后续的中间件都能得到 ReqId
//! 本单元同时也提供了 ReqId 的析取器, 可在 api 接口函数中, 通过 ReqId 类型的
//! 参数直接获取

use std::sync::atomic::AtomicU32;

use axum::{
    extract::{FromRequestParts, Request, State}, http::request::Parts,
    middleware::Next, response::Response
};
use rclite::Arc;

const MAX_REQ_ID: u32 = 9999_9999;

#[derive(Copy, Clone, Debug)]
pub struct ReqId(pub u32);

impl std::fmt::Display for ReqId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 全局请求ID生成器
#[derive(Clone)]
pub struct ReqIdGenerator(Arc<AtomicU32>);

impl ReqIdGenerator {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU32::new(1)))
    }

    /// 获取下一个请求ID（原子递增）
    pub fn next(&self) -> ReqId {
        use std::sync::atomic::Ordering::{AcqRel, Acquire};

        fn inc_round(current: u32) -> Option<u32> {
            Some(if current >= MAX_REQ_ID {
                1
            } else {
                current + 1
            })
        }

        let id = match self.0.fetch_update(AcqRel, Acquire, inc_round) {
            Ok(id) => id,
            _ => unsafe { std::hint::unreachable_unchecked() },
        };

        ReqId(id)
    }
}

/// 中间件, 为每个请求注入递增的 ReqId
pub async fn req_id_middleware(
    State(generator): State<ReqIdGenerator>, mut req: Request, next: Next
) -> Response {
    // 生成新的请求ID
    let req_id = generator.next();

    // 将 ReqId 添加到请求的扩展中
    req.extensions_mut().insert(req_id);

    // 执行后续中间件和处理程序
    next.run(req).await
}

/// 析取器, 支持在 api 接口中直接获取 ReqId 类型的变量
impl<S: Send + Sync> FromRequestParts<S> for ReqId {
    type Rejection = std::convert::Infallible;

    #[allow(clippy::manual_async_fn)]
    fn from_request_parts(
        parts: &mut Parts, _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            let req_id = parts.extensions.get::<ReqId>().map_or(0, |v| v.0);
            Ok(ReqId(req_id))
        }
    }
}
