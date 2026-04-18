use axum::Router;

use crate::utils;

pub fn build_router(gw_path: &str) -> Router {
    use crate::http_apis::*;

    // 规范化网关 api 前缀
    let gw = utils::normalize_path(gw_path, false);
    tracing::info!(%gw, "网关接口上下文地址");

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

    let gw_routes = Router::new()
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
        .route(path!("rate_del"), api!(rate_del));


    Router::new()
        .nest(&gw, gw_routes)
        .fallback(proxy)
}
