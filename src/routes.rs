use axum::{Router, middleware::from_fn_with_state};
use kv_axum_util::{ReqIdGenerator, capture_response_body, custom_trace_layer, req_id_middleware};
use rclite::Arc;
use tower_http::cors::CorsLayer;

use crate::{appconf::AppConf, appvars::{APP_VAR, RATE_LIMITER_STATE}, auth::{AuthState, auth_middleware}, rate_limit::rate_limit_middleware, utils};

macro_rules! path {
    ($path:literal) => {
        concat!("/", $path)
    };
}

macro_rules! api {
    ($func:ident) => {
        axum::routing::get($func).post($func)
    };
}

fn build_gw_router() -> Router {
    use crate::http_apis::*;

    Router::new()
        .route(path!("ping"), api!(ping))
        .route(path!("ping/{reply}"), api!(ping))
        .route(path!("status"), api!(status))
        .route(path!("token/{uid}"), api!(token))
        .route(path!("blacklist"), api!(blacklist))
        .route(path!("query"), api!(query))
        .route(path!("query/{paths}"), api!(query))
        .route(path!("reg"), api!(reg))
        .route(path!("unreg"), api!(unreg))
        .route(path!("cfg"), api!(cfg))
        .route(path!("cfg/{q}"), api!(token))
        .route(path!("recfg"), api!(recfg))
        .route(path!("rate"), api!(rate))
        .route(path!("rates"), api!(rates))
        .route(path!("rate_del"), api!(rate_del))
}

pub fn build_router() -> Router {
    let ac = AppConf::get();
    let av = APP_VAR.get();

    // 规范化网关 api 前缀
    let gw = utils::normalize_path(&ac.gw_prefix, false);
    tracing::info!(context_path = %gw, "网关接口上下文地址");

    let mtcs = ac.mtcs.parse().expect("mtcs 不是数字格式");
    let auth_state = AuthState::new(&ac.jwt_key, &ac.jwt_iss, &ac.redis_prefix, mtcs, av.redis_ttl);
    let rate_limiter_state = RATE_LIMITER_STATE.clone();

    Router::new()
        .nest(&gw, build_gw_router())
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
