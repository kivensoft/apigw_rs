//! 网关应用提供的服务接口

use crate::{apis::{self, TokenReq}, appconf::AppConf, auth::UserId, proxy};
use axum::{
    Json,
    extract::{Path, Query, Request}, response::IntoResponse,
};
use kv_axum_util::{ApiError, ApiResult, ClientIp, JsonString, ReqId, api_err, param_from_multi};
use tracing::debug;


type OptJson<T> = Option<Json<T>>;


/// 服务测试，测试服务是否存活
pub async fn ping(
    Path(path): Path<apis::PingReq>, // 路径中的 reply（如 /ping/{reply}）
    Query(query): Query<apis::PingReq>, // 查询参数中的 reply（如 /ping?reply=xxx）
    ClientIp(ip): ClientIp,          // 客户端 IP
    body: OptJson<apis::PingReq>, // body 中的 reply（如 POST {"reply": "xxx"}）
) -> JsonString {
    let reply = param_from_multi!(body, query, path, reply, "pong");
    apis::ping(reply, &ip)
}

/// 服务状态
pub async fn status() -> ApiResult<apis::StatusRes> {
    apis::status()
}

/// 生成token，生成jwt格式token
pub async fn token(Json(body): Json<TokenReq>) -> ApiResult<apis::TokenRes> {
    let uid = body.uid;
    if uid == 0 {
        api_err!("uid 必须大于0");
    }
    apis::token(uid)
}

/// 注册服务查询
pub async fn query(Json(body): Json<apis::QueryReq>) -> ApiResult<proxy::EndPointDisplayMap> {
    apis::query(&body.paths)
}

/// 注册服务(同时也作为心跳服务使用)
pub async fn reg(Json(body): Json<apis::RegReq>) -> ApiResult<()> {
    apis::reg(body)
}

/// 取消服务注册
pub async fn unreg(Json(body): Json<apis::UnregReq>) -> ApiResult<()> {
    apis::unreg(&body.endpoint)
}

/// 获取配置信息
pub async fn cfg(body: OptJson<apis::SimpleQueryReq>) -> ApiResult<apis::CfgRes> {
    let q = body.as_ref().and_then(|v| v.q.as_ref()).map_or("", |s| s);
    apis::cfg(q).await
}

/// 重新加载配置信息
pub async fn recfg() -> ApiResult<()> {
    apis::recfg().await
}

/// 设置接口限流，rate为毫秒为单位的令牌产生速率，例如1000表示每秒产生1个令牌
/// rate为0时，表示删除该限流器
pub async fn rate(Json(body): Json<apis::RateReq>) -> ApiResult<()> {
    apis::rate(body)
}

/// 查询所有限流器
pub async fn rates(body: OptJson<apis::SimpleQueryReq>) -> ApiResult<apis::RatesRes> {
    let q = body.as_ref().and_then(|v| v.0.q.as_ref()).map_or("", |s| s);
    apis::rates(q)
}

/// 设置接口限流，rate为毫秒为单位的令牌产生速率，例如1000表示每秒产生1个令牌
/// rate为0时，表示删除该限流器
pub async fn rate_del(Json(body): Json<apis::RateDelReq>) -> ApiResult<()> {
    apis::rate_del(&body.path)
}

/// 反向代理
pub async fn proxy(rid: ReqId, uid: UserId, req: Request) -> impl IntoResponse {
    let ac = AppConf::get();
    let path = req.uri().path();

    if path.starts_with(&ac.gw_prefix) {
        debug!(%path, "网关未提供该接口");
        ApiError::not_found().into_response()
    } else {
        proxy::proxy_handler(req, rid, uid).await
    }
}
