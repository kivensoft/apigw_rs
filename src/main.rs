mod auth;
mod apis;
mod dict;
mod proxy;
mod syssrv;

use std::{fmt::Write, time::{SystemTime, Duration}};

use anyhow::Context;
use httpserver::HttpServer;
use smallstr::SmallString;

const BANNER: &str = r#"
    ___          _    ______      __  Kivensoft %
   /   |  ____  (_)  / ____/___ _/ /____ _      ______ ___  __
  / /| | / __ \/ /  / / __/ __ `/ __/ _ \ | /| / / __ `/ / / /
 / ___ |/ /_/ / /  / /_/ / /_/ / /_/  __/ |/ |/ / /_/ / /_/ /
/_/  |_/ .___/_/   \____/\__,_/\__/\___/|__/|__/\__,_/\__, /
      /_/                                            /____/
"#;

const APP_NAME: &str = "apigw";
/// app版本号, 来自编译时由build.rs从cargo.toml中读取的版本号(读取内容写入.version文件)
const APP_VER: &str = include_str!(concat!(env!("OUT_DIR"), "/.version"));

const SCHEDULED_SECS: u64 = 180;

appconfig::appglobal_define!(app_global, AppGlobal,
    connect_timeout      : u32,
    heart_break_live_time: u32,
    startup_time         : u64,
);

appconfig::appconfig_define!(app_conf, AppConf,
    log_level   : String => ["L",  "log-level",    "LogLevel",          "log level(trace/debug/info/warn/error/off)"],
    log_file    : String => ["F",  "log-file",     "LogFile",           "log filename"],
    log_max     : String => ["M",  "log-max",      "LogFileMaxSize",    "log file max size (unit: k/m/g)"],
    log_async   : bool   => ["",   "log-async",    "LogAsync",          "enable asynchronous logging"],
    no_console  : bool   => ["",   "no-console",   "NoConsole",         "prohibit outputting logs to the console"],
    install     : bool   => ["",   "install",      "Install",           "install as a system Linux service"],
    listen      : String => ["l",  "listen",       "Listen",            "http service ip:port"],
    dict_file   : String => ["d",  "dict-file",    "DictFile",          "set dict config file"],
    threads     : String => ["t",  "threads",      "Threads",           "set tokio runtime worker threads"],
    ignore_token: bool   => ["",   "igonre-token", "IgnoreToken",       "ignore token and do not perform verification"],
    mtcs        : String => ["",   "mtcs",         "MaxTokenCacheSize", "max token cache size"],
    api_expire  : String => ["",   "api-expire",   "ApiExpire",         "api service expire time (unit: seconds)"],
    conn_timeout: String => ["",   "conn-timeout", "ConnectTimeout",    "service connect timeout (unit: seconds)"],
    token_issuer: String => ["i",  "token-issuer", "TokenIssuer",       "token issuer"],
    token_key   : String => ["k",  "token-key",    "TokenKey",          "jwt token key"],
);

impl Default for AppConf {
    fn default() -> Self {
        Self {
            log_level   : String::from("info"),
            log_file    : String::with_capacity(0),
            log_max     : String::from("10m"),
            log_async   : false,
            no_console  : false,
            install     : false,
            listen      : String::from("127.0.0.1:6400"),
            dict_file   : String::new(),
            threads     : String::from("1"),
            ignore_token: false,
            mtcs        : String::from("128"),
            api_expire  : String::from("90"),
            conn_timeout: String::from("3"),
            token_issuer: String::from(APP_NAME),
            token_key   : String::from("Kivensoft Copyright 2023"),
        }
    }
}

/// 获取当前时间基于UNIX_EPOCH的秒数
fn unix_timestamp() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

fn init() -> bool {
    let mut buf = SmallString::<[u8; 512]>::new();

    write!(buf, "{APP_NAME} version {APP_VER} CopyLeft Kivensoft 2023.").unwrap();
    let version = buf.as_str();

    let ac = AppConf::init();
    if !appconfig::parse_args(ac, version).expect("parse args error") {
        return false;
    }

    if ac.install {
        syssrv::install();
        return false;
    }

    AppGlobal::init(AppGlobal {
        connect_timeout: ac.conn_timeout.parse().expect("arg conn-timeout is not a number"),
        heart_break_live_time: ac.api_expire.parse().expect("arg api-expire is not a number"),
        startup_time: unix_timestamp(),
    });

    if !ac.listen.is_empty() && ac.listen.as_bytes()[0] == b':' {
        ac.listen.insert_str(0, "0.0.0.0");
    };

    let log_level = asynclog::parse_level(&ac.log_level).expect("arg log-level format error");
    let log_max = asynclog::parse_size(&ac.log_max).expect("arg log-max format error");

    if log_level == log::Level::Trace {
        println!("config setting: {ac:#?}\n");
    }

    asynclog::init_log(log_level, ac.log_file.clone(), log_max,
        !ac.no_console, ac.log_async).expect("init log error");
    asynclog::set_level("mio".to_owned(), log::LevelFilter::Info);
    asynclog::set_level("want".to_owned(), log::LevelFilter::Info);

    if let Some((s1, s2)) = BANNER.split_once('%') {
        buf.clear();
        write!(buf, "{s1}{APP_VER}{s2}").unwrap();
        appconfig::print_banner(&buf, true);
    }

    // 加载配置文件内容
    if !ac.dict_file.is_empty() {
        dict::load(&ac.dict_file).unwrap();
    }

    true
}

// #[tokio::main(worker_threads = 4)]
// #[tokio::main(flavor = "current_thread")]
fn main() {
    if !init() { return; }
    let ac = AppConf::get();

    let max_token_cache_size = ac.mtcs.parse().expect("arg mtcs not a int number");
    let addr: std::net::SocketAddr = ac.listen.parse().unwrap();

    let mut srv = HttpServer::new("/api/", true);
    srv.default_handler(proxy::proxy_handler);

    let authenticaton = if ac.ignore_token {
        None
    } else {
        Some(srv.middleware(auth::Authentication::new(
            &ac.token_key,
            &ac.token_issuer,
            max_token_cache_size,
            10 * 60,
        )))
    };

    proxy::init_client(Some(Duration::from_secs(
        AppGlobal::get().connect_timeout as u64,
    )));

    httpserver::register_apis!(srv, "gw/",
        "ping": apis::ping,
        "ping/*": apis::ping,
        "token": apis::token,
        "status": apis::status,
        "query": apis::query,
        "query/*": apis::query,
        "reg": apis::reg,
        "unreg": apis::unreg,
        "cfg": apis::cfg,
        "cfg/*": apis::cfg,
        "reload-cfg": apis::reload_cfg,
    );

    let async_fn = async move {
        // 启动token缓存定时清理任务
        if !ac.ignore_token {
            auth::Authentication::start_recycle_task(authenticaton.unwrap(), SCHEDULED_SECS);
        }
        // 运行http server主服务
        srv.run(addr).await.context("http server run error").unwrap();
    };

    let threads = ac.threads.parse::<usize>().expect("arg threads is not a number");

    #[cfg(not(feature = "multi_thread"))]
    {
        assert!(threads == 1, "{APP_NAME} current version unsupport multi-threads");

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async_fn);
    }

    #[cfg(feature = "multi_thread")]
    {
        assert!(threads >= 0 && threads <= 256, "multi-threads range in 0-256");

        let mut builder = tokio::runtime::Builder::new_multi_thread();
        if threads > 0 {
            builder.worker_threads(threads);
        }

        builder.enable_all()
            .build()
            .unwrap()
            .block_on(async_fn)
    }
}
