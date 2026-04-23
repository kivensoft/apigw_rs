mod apis;
mod appconf;
mod appvars;
mod auth;
mod db;
mod dict;
mod http_apis;
mod macros;
mod path_iter;
mod proxy;
mod rate_limit;
#[cfg(all(unix, feature = "hot-restart"))]
mod reboot;
mod routes;
mod static_val;
mod syssrv;
mod utils;

use std::{env, fmt::Write, net::SocketAddr, time::Duration};

use anyhow::Result;
use appvars::AppVar;
use compact_str::CompactString;
use kv_redis::RedisClient;
use smallstr::SmallString;
use tokio::task;
use tracing::{debug, error, info};

use crate::{
    appconf::AppConf,
    appvars::{APP_NAME, APP_VAR, APP_VER, BANNER, RATE_LIMITER_STATE, REDIS_CLIENT, SCHEDULER},
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

    error!("获取程序的当前路径失败");
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

fn parse_cfg() -> bool {
    let mut buf = SmallString::<[u8; 512]>::new();

    let _ = write!(buf, "{APP_NAME} 版本 {APP_VER} 版权所有 Kivensoft 2023-2026.");
    let version = buf.as_str();

    let mut ac = AppConf::default();
    if !appcfg::parse_args(&mut ac, version).expect("解析应用程序参数失败") {
        return false;
    }

    if ac.install {
        syssrv::install();
        return false;
    }

    // 修复网关上下文地址
    ac.gw_prefix = utils::normalize_path(&ac.gw_prefix, true);

    // 修复监听地址
    if !ac.listen.is_empty() && ac.listen.as_bytes()[0] == b':' {
        ac.listen.insert_str(0, "0.0.0.0");
    };

    let av = AppVar {
        startup_time: localtime::unix_timestamp(),
        heartbeat_interval: ac.expire_time.parse().expect(arg_err!("expire-time")),
        jwt_ttl: ac.jwt_ttl.parse().expect(arg_err!("jwt-ttl")),
        redis_ttl: ac.redis_ttl.parse().expect(arg_err!("redis-ttl")),
        use_redis: !ac.redis.is_empty(),
        srv_conn_timeout: ac.conn_timeout.parse().expect(arg_err!("conn-timeout")),
    };

    if let Some((s1, s2)) = BANNER.split_once('?') {
        buf.clear();
        let _ = write!(buf, "{s1}{APP_VER}{s2}");
        appcfg::print_banner(&buf, true);
    }

    // 初始化全局变量及全局配置
    AppConf::init(ac);
    APP_VAR.init(av, "APP_VER.init");

    true
}

/// 启动计划任务, 做一些定时清理的工作
async fn run_scheduler() {
    let scheduler = &SCHEDULER;

    // 数据库过期token清理
    scheduler
        .add_repeat_task(10 * 60, || async {
            let _ = task::spawn_blocking(db::InvalidToken::remove_expired).await;
        })
        .await;

    // 过期反向代理的上游服务信息清理
    scheduler
        .add_repeat_task(3 * 60, || async {
            let _ = task::spawn_blocking(proxy::services_clean).await;
        })
        .await;

    // 限速器过期资源清理
    scheduler
        .add_repeat_task(2 * 60, || async {
            let _ = task::spawn_blocking(|| RATE_LIMITER_STATE.recycle()).await;
        })
        .await;

    tokio::spawn(scheduler.run());
}

async fn async_main() -> Result<()> {
    // 初始化全局变量及全局配置
    let ac = AppConf::get();
    let av = APP_VAR.get();

    // 加载配置文件内容, 允许失败, 失败则相当于没有公共配置
    if !ac.dict_file.is_empty() {
        let _ = dict::load(&make_abs_path(&ac.dict_file));
    }

    // 初始化redis连接池
    if !ac.redis.is_empty() {
        let rc = RedisClient::new(&ac.redis, av.redis_ttl).await?;
        REDIS_CLIENT.init(rc, "REDIS_CLIENT.init");
    }

    // 初始化无效token数据库
    if !ac.db_file.is_empty() {
        db::init(&make_abs_path(&ac.db_file));
    }

    // 创建定时任务
    run_scheduler().await;

    // 创建路由器
    let router = build_router();

    // ---------- 创建关闭协调器 ----------
    cfg_if::cfg_if! {
        if #[cfg(all(unix, feature = "hot-restart"))] {
            // 这个令牌会用于两个目的：
            // 1. 传递给 Axum 实现优雅停机
            // 2. 当收到重启信号时，用它来触发旧进程退出
            let shutdown_token = tokio_util::sync::CancellationToken::new();
            let server_token = shutdown_token.clone();
        } else {
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        }
    }

    // 运行http server主服务
    let addr: std::net::SocketAddr = ac.listen.parse()?;
    debug!(%addr,"网关监听地址");
    info!("🚀 {} {} running on http://{}", APP_NAME, APP_VER, addr);

    // 启动新的任务运行服务, 主线任务留给 Ctrl + C 监听器
    let http_task = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        // 支持获取ConnectInfo, 没有这个将无法获取客户端ip
        let app = router.into_make_service_with_connect_info::<SocketAddr>();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cfg_if::cfg_if! {
                    if #[cfg(all(unix, feature = "hot-restart"))] {
                        server_token.cancelled().await;
                    } else {
                        let _ = shutdown_rx.changed().await;
                    }
                }
                info!("⚠️ 收到关闭http服务信号, 开始优雅停机...");
            })
            .await
            .unwrap();
        debug!("http服务正常关闭");
    });


    cfg_if::cfg_if! {
        if #[cfg(all(unix, feature = "hot-restart"))] {
            crate::reboot::run_as_reboot(&ac.unix_sock, shutdown_token).await;
        } else {
            // 监听 Ctrl+C 信号
            tokio::signal::ctrl_c().await?;
            info!("👌 收到 Ctrl+C 信号, 正在关闭应用...");
            // 向 http 服务发送关闭信号
            let _ = shutdown_tx.send(true);
            // 等待10秒后结束应用程序
            let _ = tokio::time::timeout(Duration::from_secs(10), http_task).await;
        }
    }

    Ok(())
}

fn build_tokio_runtime(ac: &AppConf) -> tokio::runtime::Runtime {
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
}

fn main() {
    // 初始化应用程序参数
    if !parse_cfg() {
        return;
    };

    let ac = AppConf::get();

    // 初始化日志
    let _guard = kv_axum_util::TracingBuilder::new()
        .directives(&ac.log_filter)
        .file(&make_abs_path("logs"), &ac.log_file)
        .disable_console(ac.no_console)
        .build();

    info!(pid = %std::process::id(), "{} 启动中...", APP_NAME);

    build_tokio_runtime(ac).block_on(async move {
        if let Err(e) = async_main().await {
            eprintln!("应用程序错误: {e:?}");
        }
    })
}
