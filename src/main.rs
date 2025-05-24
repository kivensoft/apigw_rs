mod apis;
mod appvars;
mod auth;
#[allow(dead_code)]
mod db;
mod dict;
mod macros;
mod proxy;
mod ratelimit;
#[allow(dead_code)]
mod redis;
mod statics;
mod syssrv;
mod utils;

use std::{
    env,
    fmt::Write,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result};
use appvars::AppVar;
use compact_str::ToCompactString;
use httpserver::{CancelSender, HttpServer};
use smallstr::SmallString;

const BANNER: &str = r#"
    ___          _    ______      __  Kivensoft ?
   /   |  ____  (_)  / ____/___ _/ /____ _      ______ ___  __
  / /| | / __ \/ /  / / __/ __ `/ __/ _ \ | /| / / __ `/ / / /
 / ___ |/ /_/ / /  / /_/ / /_/ / /_/  __/ |/ |/ / /_/ / /_/ /
/_/  |_/ .___/_/   \____/\__,_/\__/\___/|__/|__/\__,_/\__, /
      /_/                                            /____/
"#;

pub const APP_NAME: &str = include_str!(concat!(env!("OUT_DIR"), "/.app_name"));
/// app版本号, 来自编译时由build.rs从cargo.toml中读取的版本号(读取内容写入.version文件)
const APP_VER: &str = include_str!(concat!(env!("OUT_DIR"), "/.version"));

static CANCEL_SENDER: OnceLock<CancelSender> = OnceLock::new();

appcfg::appconfig_define!(app_conf, AppConf,
    log_level     : String => ["L",  "log-level",    "LogLevel",          "log level(trace/debug/info/warn/error/off)"],
    log_file      : String => ["F",  "log-file",     "LogFile",           "log filename"],
    log_max       : String => ["M",  "log-max",      "LogFileMaxSize",    "log file max size (unit: k/m/g)"],
    no_console    : bool   => ["",   "no-console",   "NoConsole",         "prohibit outputting logs to the console"],
    install       : bool   => ["",   "install",      "InstallService",    "install as a system Linux service"],
    listen        : String => ["l",  "listen",       "HttpServiceListen", "http service ip:port"],
    dict_file     : String => ["d",  "dict-file",    "DictConfigFile",    "set dict config file"],
    threads       : String => ["t",  "threads",      "RuntimeThreads",    "set tokio runtime worker threads"],
    token_db      : String => ["",   "token-db",     "TokenDB",           "set invalid token db path"],
    mtcs          : String => ["",   "mtcs",         "MaxTokenCacheSize", "max token cache size"],
    context_path  : String => ["",   "context-path", "HttpContextPath",   "http request content path"],
    gw_prefix     : String => ["",   "gw-prefix",    "GatewayPathPrefix", "Gateway path prefix"],
    api_expire    : String => ["",   "api-expire",   "ApiExpire",         "api service expire time (unit: seconds)"],
    conn_timeout  : String => ["",   "conn-timeout", "ConnectTimeout",    "service connect timeout (unit: seconds)"],
    jwt_issuer    : String => ["i",  "jwt-issuer",   "JwtIssuer",         "jwt token issuer, when this value is set, the iss of token will be verified"],
    jwt_key       : String => ["k",  "jwt-key",      "JwtKey",            "jwt token key, when this value if set, proxy will add header x-uid if token valid"],
    jwt_ttl       : String => ["T",  "jwt-ttl",      "JwtTTL",            "jwt token ttl (unit: seconds)"],
    redis_host    : String => ["H",  "redis-host",   "RedisHost",         "redis host, if set, redis will be used"],
    redis_port    : String => ["",   "redis-port",   "RedisPort",         "redis port"],
    redis_user    : String => ["",   "redis-user",   "RedisUser",         "redis username"],
    redis_pass    : String => ["P",  "redis-pass",   "RedisPass",         "redis password"],
    redis_db      : String => ["",   "redis-db",     "RedisDb",           "redis database"],
    redis_prefix  : String => ["R",  "redis-prefix", "RedisPrefix",       "redis key common prefix"],
    redis_ttl     : String => ["",   "redis-ttl",    "RedisTtl",          "redis cache ttl"],
);

impl Default for AppConf {
    fn default() -> Self {
        Self {
            log_level: String::from("info"),
            log_file: String::new(),
            log_max: String::from("10m"),
            no_console: false,
            install: false,
            listen: String::from("127.0.0.1:6400"),
            dict_file: String::new(),
            threads: String::from("2"),
            token_db: String::from("invalid_token.redb"),
            mtcs: String::from("128"),
            context_path: String::new(),
            gw_prefix: String::from("/gw"),
            api_expire: String::from("90"),
            conn_timeout: String::from("3"),
            jwt_issuer: String::new(),
            jwt_key: String::new(),
            jwt_ttl: String::from("86400"),
            redis_host: String::new(),
            redis_port: String::new(),
            redis_user: String::new(),
            redis_pass: String::new(),
            redis_db: String::new(),
            redis_prefix: String::from(APP_NAME),
            redis_ttl: String::from("300"),
        }
    }
}

macro_rules! arg_err {
    ($text:literal) => {
        concat!("arg ", $text, " format error")
    };
}

fn get_app_path() -> String {
    if let Ok(path) = env::current_exe() {
        // 获取可执行文件的目录路径
        if let Some(parent) = path.parent() {
            if let Some(parent) = parent.to_str() {
                return parent.to_string();
            }
        }
    }

    log::error!("获取程序的当前路径失败");
    String::new()
}

fn parse_cfg() -> Option<(AppConf, AppVar)> {
    let mut buf = SmallString::<[u8; 512]>::new();

    write!(buf, "{APP_NAME} version {APP_VER} CopyLeft Kivensoft 2023-2025.").unwrap();
    let version = buf.as_str();

    let mut ac = AppConf::default();
    if !appcfg::parse_args(&mut ac, version).expect("parse args error") {
        return None;
    }

    if ac.install {
        syssrv::install();
        return None;
    }


    let av = AppVar {
        startup_time: localtime::unix_timestamp(),
        heart_break_live_time: ac.api_expire.parse().expect(arg_err!("api-expire")),
        redis_ttl: ac.redis_ttl.parse().expect(arg_err!("redis-ttl")),
        use_redis: !ac.redis_host.is_empty(),
        jwt_key: ac.jwt_key.to_compact_string(),
        jwt_issuer: ac.jwt_issuer.to_compact_string(),
        jwt_ttl: ac.jwt_ttl.parse().expect(arg_err!("jwt-ttl")),
        dict_file: ac.dict_file.to_compact_string(),
        srv_conn_timeout: ac.conn_timeout.parse().expect(arg_err!("conn-timeout")),
    };

    if !ac.listen.is_empty() && ac.listen.as_bytes()[0] == b':' {
        ac.listen.insert_str(0, "0.0.0.0");
    };

    if let Some((s1, s2)) = BANNER.split_once('?') {
        // let s2 = &s2[APP_VER.len() - 1..];
        buf.clear();
        write!(buf, "{s1}{APP_VER}{s2}").unwrap();
        appcfg::print_banner(&buf, true);
    }

    // 加载配置文件内容
    if !ac.dict_file.is_empty() {
        dict::load(&ac.dict_file).unwrap();
    }

    Some((ac, av))
}

fn init_log(ac: &AppConf) {
    let log_level = asynclog::parse_level(&ac.log_level).expect(arg_err!("log-level"));
    let log_max = asynclog::parse_size(&ac.log_max).expect(arg_err!("log-max"));

    if log_level == log::Level::Trace {
        println!("config setting: {ac:#?}\n");
    }

    asynclog::Builder::new()
        .level(log_level)
        .log_file(ac.log_file.clone())
        .log_file_max(log_max)
        .use_console(!ac.no_console)
        .use_async(true)
        .builder()
        .expect("init log error");
    asynclog::set_level("mio".to_owned(), log::LevelFilter::Info);
    asynclog::set_level("tokio_util".to_owned(), log::LevelFilter::Info);
    asynclog::set_level("hyper_util".to_owned(), log::LevelFilter::Info);
}

async fn init_redis(ac: &AppConf, av: &AppVar) {
    // 初始化redis连接池
    if !ac.redis_host.is_empty() {
        let redis_config = redis::RedisConfig {
            host: &ac.redis_host,
            port: &ac.redis_port,
            user: &ac.redis_user,
            pass: &ac.redis_pass,
            db: &ac.redis_db,
        };
        redis::init(&redis_config, av.redis_ttl)
            .await
            .context("connect redis fail")
            .unwrap();
    }
}

fn init_invalid_token_db(ac: &AppConf) {
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
                format!(r"{}\{}", get_app_path(), db_path)
            }
        }
    }

    if !ac.token_db.is_empty() {
        db::init(&make_abs_path(&ac.token_db));
    }
}

fn register_apis(srv: &mut HttpServer, ac: &AppConf) {
    let gateway_prefix = ac.gw_prefix.as_bytes();
    let mut gateway_path = String::new();
    if gateway_prefix[0] != b'/' {
        gateway_path.push('/');
    }
    gateway_path.push_str(&ac.gw_prefix);
    if gateway_prefix[gateway_prefix.len() - 1] != b'/' {
        gateway_path.push('/');
    }

    apis::register_apis(srv, &gateway_path);
}

async fn async_main(ac: AppConf, av: AppVar) -> Result<()> {
    // 初始化全局变量及全局配置
    // AppConf::init(ac);
    appvars::init(av);
    let av = appvars::get();

    // 初始化日志组件
    init_log(&ac);
    // 初始化redis连接池
    init_redis(&ac, av).await;
    // 初始化无效token数据库
    init_invalid_token_db(&ac);

    // 初始化任务取消管理器
    let (cancel_sender, cancel_manager) = httpserver::new_cancel();
    CANCEL_SENDER.set(cancel_sender).expect("init CANCEL_SENDER failed");
    let mut cancel_receiver = cancel_manager.new_cancel_receiver();

    let mut srv = HttpServer::new();
    // 设置请求上下文路径
    srv.context_path(&ac.context_path)
        // 路由支持1级子路径匹配
        .fuzzy_find(httpserver::FuzzyFind::One)
        // 添加日志中间件
        .middleware(Arc::new(httpserver::AccessLog::new()))
        // 缺省处理函数改为反向代理处理函数
        .default_handler(proxy::proxy_handler)
        // 允许用户通过发送取消消息来优雅的终止服务
        .cancel_manager(cancel_manager);

    let max_jwt_cache_size = ac.mtcs.parse().expect(arg_err!("mtcs"));
    let gw_prefix = utils::concat_uri_path(&[&ac.context_path, &ac.gw_prefix], true);
    // 添加token校验中间件
    if !ac.jwt_key.is_empty() {
        srv.middleware(Arc::new(auth::Authentication::new(
            gw_prefix,
            &ac.jwt_key,
            &ac.jwt_issuer,
            &ac.redis_prefix,
            max_jwt_cache_size,
            10 * 60,
        )));
    };

    // 注册网关接口
    register_apis(&mut srv, &ac);

    // 添加限流中间件
    let rate_limiter = Arc::new(ratelimit::RateLimiter::new(&ac.context_path));
    srv.middleware(rate_limiter.clone());
    apis::RATE_LIMITER.init(rate_limiter);

    // 运行http server主服务
    let addr: std::net::SocketAddr = ac.listen.parse().unwrap();
    let listener = srv.listen(addr).await.expect("http server listen error");
    // 运行http服务
    tokio::spawn(async move {
        if let Err(e) = Arc::new(srv).serve(listener).await {
            log::error!("http server error: {e:?}");
        }
    });

    // 创建一个每10分钟触发一次的定时任务
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(180));
        interval.tick().await;
        loop {
            interval.tick().await;
            // 清理过期的反向代理服务项
            proxy::services_clean();
        }
    });

    tokio::select! {
        // 监听ctrl+c信号
        res = tokio::signal::ctrl_c() => {
            match res {
                Ok(_) => log::info!("The ctrl+c signal has been received, closed..."),
                Err(e) => log::error!("Listening to the ctrl+c signal failed: {e:?}"),
            }

            // 设置本任务取消标志
            cancel_receiver.finish();

            // 发送退出信号
            debug_assert!(CANCEL_SENDER.get().is_some());
            if let Some(cancel_sender) = CANCEL_SENDER.get() {
                cancel_sender.cancel(Duration::from_secs(2)).await;
            }
        }
        _ = cancel_receiver.cancel_event() => {
            // 设置本任务取消标志
            cancel_receiver.finish();
            log::info!("Received the exit signal, exiting...");
        }
    }

    Ok(())
}

// #[tokio::main(worker_threads = 4)]
// #[tokio::main(flavor = "current_thread")]
fn main() {
    let (ac, av) = match parse_cfg() {
        Some(v) => v,
        None => return,
    };

    let threads = ac.threads.parse::<usize>().expect(arg_err!("threads"));

    // 线程数量是1，则运行单线程模式，否则，运行多线程模式
    let mut builder = if threads == 1 {
        tokio::runtime::Builder::new_current_thread()
    } else {
        assert!(threads <= 256, "multi-threads range in 0-256");
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        if threads > 0 {
            builder.worker_threads(threads);
        }
        builder
    };

    builder.enable_all().build().unwrap().block_on(async move {
        if let Err(e) = async_main(ac, av).await {
            eprintln!("application error: {e:?}");
        }
    })
}
