mod apis;
mod appconf;
mod appvars;
mod auth;
mod db;
mod dict;
mod http_apis;
mod logging_body;
mod macros;
mod path_iter;
mod proxy;
mod rate_limit;
mod routes;
mod static_val;
mod syssrv;
mod utils;

use std::{env, fmt::Write, net::SocketAddr, time::Duration};

use anyhow::Result;
use appvars::AppVar;
use axum::middleware::from_fn_with_state;
use compact_str::CompactString;
use kv_axum_util::{ReqIdGenerator, custom_trace_layer, req_id_middleware};
use kv_redis::RedisClient;
use rclite::Arc;
use smallstr::SmallString;
use tokio::task;
use tower_http::cors::CorsLayer;

use crate::{
    appconf::AppConf,
    appvars::{APP_NAME, APP_VAR, APP_VER, BANNER, RATE_LIMITER_STATE, REDIS_CLIENT, SCHEDULER},
    auth::{AuthState, auth_middleware},
    rate_limit::rate_limit_middleware,
    routes::build_router,
};

// 只在目标三元组为 x86_64-unknown-linux-musl 时使用 mimalloc
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "musl"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

macro_rules! arg_err {
    ($text:literal) => {
        concat!("参数[", $text, "]格式错误")
    };
}

fn get_app_path() -> CompactString {
    if let Ok(path) = env::current_exe() {
        // 获取可执行文件的目录路径
        if let Some(parent) = path.parent()
            && let Some(parent) = parent.to_str()
        {
            return parent.into();
        }
    }

    tracing::error!("获取程序的当前路径失败");
    "".into()
}

fn make_abs_path(db_path: &str) -> String {
    #[cfg(not(target_os = "windows"))]
    {
        if db_path.as_bytes()[0] == b'/' {
            db_path.to_string()
        } else {
            format!("{}/{}", get_app_path(), db_path)
        }
    }
    #[cfg(target_os = "windows")]
    {
        if db_path.len() > 2 && db_path.as_bytes()[1] == b':' {
            db_path.to_string()
        } else {
            format!(r#"{}\{}"#, get_app_path(), db_path)
        }
    }
}

fn parse_cfg() -> Option<(AppConf, AppVar)> {
    let mut buf = SmallString::<[u8; 512]>::new();

    let _ = write!(buf, "{APP_NAME} 版本 {APP_VER} 版权所有 Kivensoft 2023-2026.");
    let version = buf.as_str();

    let mut ac = AppConf::default();
    if !appcfg::parse_args(&mut ac, version).expect("解析应用程序参数失败") {
        return None;
    }

    if ac.install {
        syssrv::install();
        return None;
    }

    // 修复网关上下文地址
    ac.gw_prefix = utils::normalize_path(&ac.gw_prefix, true);

    let av = AppVar {
        startup_time: localtime::unix_timestamp(),
        heartbeat_interval: ac.expire_time.parse().expect(arg_err!("expire-time")),
        jwt_ttl: ac.jwt_ttl.parse().expect(arg_err!("jwt-ttl")),
        redis_ttl: ac.redis_ttl.parse().expect(arg_err!("redis-ttl")),
        use_redis: !ac.redis.is_empty(),
        srv_conn_timeout: ac.conn_timeout.parse().expect(arg_err!("conn-timeout")),
    };

    if !ac.listen.is_empty() && ac.listen.as_bytes()[0] == b':' {
        ac.listen.insert_str(0, "0.0.0.0");
    };

    if let Some((s1, s2)) = BANNER.split_once('?') {
        buf.clear();
        let _ = write!(buf, "{s1}{APP_VER}{s2}");
        appcfg::print_banner(&buf, true);
    }

    Some((ac, av))
}

/// 启动计划任务, 做一些定时清理的工作
async fn run_scheduler() {
    let scheduler = &SCHEDULER;

    // 数据库过期token清理
    scheduler.add_repeat_task(10 * 60, || async {
        let _ = task::spawn_blocking(db::remove_expired).await;
    }).await;

    // 过期反向代理的上游服务信息清理
    scheduler.add_repeat_task(10 * 60, || async {
        let _ = task::spawn_blocking(proxy::services_clean).await;
    }).await;

    // 限速器过期资源清理
    scheduler.add_repeat_task(10 * 60, || async {
        let _ = task::spawn_blocking(|| RATE_LIMITER_STATE.recycle()).await;
    }).await;

    tokio::spawn(scheduler.run());
}

async fn async_main(ac: AppConf, av: AppVar) -> Result<()> {
    // 初始化全局变量及全局配置
    let ac = AppConf::init(ac);
    APP_VAR.init(av, "APP_VER.init");
    let av = APP_VAR.get();

    // 加载配置文件内容
    if !ac.dict_file.is_empty() {
        let _ = dict::load(&ac.dict_file).await;
    }

    // 初始化redis连接池
    if !ac.redis.is_empty() {
        let rc = RedisClient::new(&ac.redis, av.redis_ttl).await.unwrap();
        REDIS_CLIENT.init(rc, "REDIS_CLIENT.init");
    }

    // 初始化无效token数据库
    if !ac.db_file.is_empty() {
        db::init(&make_abs_path(&ac.db_file));
    }

    // 创建定时任务
    run_scheduler().await;

    let mtcs = ac.mtcs.parse().expect(arg_err!("mtcs"));
    let auth_state = AuthState::new(&ac.jwt_key, &ac.jwt_iss, &ac.redis_prefix, mtcs, av.redis_ttl);
    let rate_limiter_state = RATE_LIMITER_STATE.clone();

    let router = build_router(&ac.gw_prefix)
        // 定制化日志输出格式
        .layer(custom_trace_layer())
        // 限速中间件
        .layer(from_fn_with_state(rate_limiter_state, rate_limit_middleware))
        // 解析 jwt 并在 request extensions 中存放解析结果, 非0 是已登录用户id, 0 表示用户尚未登录
        .layer(from_fn_with_state(Arc::new(auth_state), auth_middleware))
        // 允许跨域访问请求
        .layer(CorsLayer::permissive())
        // 为每个请求生成自增的请求id
        .layer(from_fn_with_state(ReqIdGenerator::new(), req_id_middleware));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 运行http server主服务
    let addr: std::net::SocketAddr = ac.listen.parse().unwrap();
    tracing::info!("🚀 {} {} running on http://{}", APP_NAME, APP_VER, addr);

    let http_task = tokio::spawn(async move {
        // 启动服务器
        let mut shutdown_rx_clone = shutdown_rx.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        // 支持获取ConnectInfo, 没有这个将无法获取客户端ip
        let app = router.into_make_service_with_connect_info::<SocketAddr>();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx_clone.changed().await;
                tracing::info!("⚠️ 收到关闭http服务信号");
            })
            .await
            .unwrap();
    });

    // 监听 Ctrl+C 信号
    tokio::signal::ctrl_c().await.unwrap();
    tracing::info!("👌 收到 Ctrl+C 信号, 正在关闭应用...");
    // 向 http 服务发送关闭信号
    let _ = shutdown_tx.send(true);
    // 等待10秒后结束应用程序
    let _ = tokio::time::timeout(Duration::from_secs(10), http_task).await;

    Ok(())
}

// #[tokio::main(worker_threads = 4)]
// #[tokio::main(flavor = "current_thread")]
fn main() {
    // 初始化应用程序参数
    let (ac, av) = match parse_cfg() {
        Some(v) => v,
        None => return,
    };

    // 初始化日志
    let _guard = kv_axum_util::TracingBuilder::new()
        .directives(&ac.log_filter)
        .file("logs", &ac.log_file)
        .disable_console(ac.no_console)
        .build();

    macro_rules! parse {
        ($expr:expr, $msg:literal) => {
            $expr.parse::<usize>().expect(arg_err!($msg))
        };
    }

    // 线程数量是1，则运行单线程模式，否则，运行多线程模式
    let task_threads = parse!(ac.task_threads, "task-threads");
    let blocking_threads = parse!(ac.blocking_threads, "blocking-threads");

    assert!(blocking_threads <= 1024, "blocking-threads 必须小于 512");

    let mut builder = if task_threads == 1 {
        tokio::runtime::Builder::new_current_thread()
    } else {
        assert!(task_threads <= 256, "multi-threads 范围在 0-256 之间");
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        if task_threads > 0 {
            builder.worker_threads(task_threads);
        }
        builder
    };

    builder
        .max_blocking_threads(blocking_threads)
        .thread_keep_alive(Duration::from_secs(30))
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            if let Err(e) = async_main(ac, av).await {
                eprintln!("应用程序错误: {e:?}");
            }
        })
}
