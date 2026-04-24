use axum::{Router, middleware::from_fn_with_state, routing::{get, post}};
use kv_axum_util::{ReqIdGenerator, capture_response_body, custom_trace_layer, req_id_middleware};
use rclite::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::{
    appconf::AppConf,
    appvars::{APP_VAR, RATE_LIMITER_STATE},
    auth::{AuthState, auth_middleware},
    rate_limit::rate_limit_middleware,
};

macro_rules! path {
    ($path:literal) => {
        concat!("/", $path)
    };
}

fn build_gw_router() -> (&'static str, Router) {
    use crate::http_apis::*;

    let gw_router = Router::new()
        .route(path!("ping"), get(ping).post(ping))
        .route(path!("ping/{reply}"), get(ping).post(ping))
        .route(path!("status"), post(status))
        .route(path!("token"), post(token))
        .route(path!("query"), post(query))
        .route(path!("reg"), post(reg))
        .route(path!("unreg"), post(unreg))
        .route(path!("cfg"), post(cfg))
        .route(path!("recfg"), post(recfg))
        .route(path!("rate"), post(rate))
        .route(path!("rates"), post(rates))
        .route(path!("rate_del"), post(rate_del));

    let gw = AppConf::get().gw_prefix.as_str();
    let gw = gw.trim_end_matches('/');
    info!(context_path = %gw, "网关接口上下文地址");

    (gw, gw_router)
}

pub fn build_router() -> Router {
    let ac = AppConf::get();
    let av = APP_VAR.get();

    let mtcs = ac.mtcs.parse().expect("mtcs 不是数字格式");
    let auth_state = AuthState::new(&ac.jwt_key, &ac.jwt_iss, &ac.redis_prefix, mtcs, av.redis_ttl);
    let rate_limiter_state = RATE_LIMITER_STATE.clone();

    let (gw_path, gw_router) = build_gw_router();

    // 注意: 中间件 layer 的执行顺序是自底向上, 所以最开始执行的中间件是最底部的那个
    Router::new()
        // 注册 /gw 下面的所有api
        .nest(gw_path, gw_router)
        // 当未找到匹配的地址时的全局缺省处理函数
        .fallback(crate::http_apis::proxy)
        // 限速中间件
        .layer(from_fn_with_state(rate_limiter_state, rate_limit_middleware))
        // 解析 jwt 并在 request extensions 中存放解析结果, 非0 是已登录用户id, 0 表示用户尚未登录
        .layer(from_fn_with_state(Arc::new(auth_state), auth_middleware))
        // 允许跨域访问请求
        .layer(CorsLayer::permissive())
        // 捕获输出结果
        .layer(from_fn_with_state(256, capture_response_body))
        // 定制化日志输出格式
        .layer(custom_trace_layer())
        // 为每个请求生成自增的请求id
        .layer(from_fn_with_state(ReqIdGenerator::new(), req_id_middleware))
}
