mod auth;
mod apis;
mod dict;
mod proxy;
mod redis;
mod staticmut;
mod syssrv;

use std::fmt::Write;

use anyhow_ext::Context;
use compact_str::CompactString;
use httpserver::HttpServer;

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

appcfg::appglobal_define!(app_global, AppGlobal,
    heart_break_live_time: u32,
    redis_ttl            : u64,
    startup_time         : u64,
);

appcfg::appconfig_define!(app_conf, AppConf,
    log_level   : String => ["L",  "log-level",    "LogLevel",          "log level(trace/debug/info/warn/error/off)"],
    log_file    : String => ["F",  "log-file",     "LogFile",           "log filename"],
    log_max     : String => ["M",  "log-max",      "LogFileMaxSize",    "log file max size (unit: k/m/g)"],
    no_console  : bool   => ["",   "no-console",   "NoConsole",         "prohibit outputting logs to the console"],
    install     : bool   => ["",   "install",      "Install",           "install as a system Linux service"],
    listen      : String => ["l",  "listen",       "Listen",            "http service ip:port"],
    dict_file   : String => ["d",  "dict-file",    "DictFile",          "set dict config file"],
    threads     : String => ["t",  "threads",      "Threads",           "set tokio runtime worker threads"],
    mtcs        : String => ["",   "mtcs",         "MaxTokenCacheSize", "max token cache size"],
    context_path: String => ["",   "context-path", "ContextPath",       "http request content path"],
    gw_prefix   : String => ["",   "gw-prefix",    "GwPrefix",          "Gateway path prefix"],
    api_expire  : String => ["",   "api-expire",   "ApiExpire",         "api service expire time (unit: seconds)"],
    conn_timeout: String => ["",   "conn-timeout", "ConnectTimeout",    "service connect timeout (unit: seconds)"],
    jwt_issuer  : String => ["i",  "jwt-issuer",   "JwtIssuer",         "jwt token issuer, when this value is set, the iss of token will be verified"],
    jwt_key     : String => ["k",  "jwt-key",      "JwtKey",            "jwt token key, when this value if set, proxy will add header X-Token-Verified true or false"],
    redis_host  : String => ["H",  "redis-host",   "RedisHost",         "redis host, if set, redis will be used"],
    redis_port  : String => ["",   "redis-port",   "RedisPort",         "redis port"],
    redis_user  : String => ["",   "redis-user",   "RedisUser",         "redis username"],
    redis_pass  : String => ["P",  "redis-pass",   "RedisPass",         "redis password"],
    redis_db    : String => ["",   "redis-db",     "RedisDb",           "redis database"],
    redis_prefix: String => ["R",  "redis-prefix", "RedisPrefix",       "redis key common prefix"],
    redis_ttl:    String => ["",   "redis-ttl",    "RedisTtl",          "redis cache ttl"],
);

impl Default for AppConf {
    fn default() -> Self {
        Self {
            log_level   : String::from("info"),
            log_file    : String::with_capacity(0),
            log_max     : String::from("10m"),
            no_console  : false,
            install     : false,
            listen      : String::from("127.0.0.1:6400"),
            dict_file   : String::with_capacity(0),
            threads     : String::from("2"),
            mtcs        : String::from("128"),
            context_path: String::with_capacity(0),
            gw_prefix   : String::from("/gw"),
            api_expire  : String::from("90"),
            conn_timeout: String::from("3"),
            jwt_issuer  : String::with_capacity(0),
            jwt_key     : String::with_capacity(0),
            redis_host  : String::with_capacity(0),
            redis_port  : String::with_capacity(0),
            redis_user  : String::with_capacity(0),
            redis_pass  : String::with_capacity(0),
            redis_db    : String::with_capacity(0),
            redis_prefix: String::from(APP_NAME),
            redis_ttl   : String::from("300"),
        }
    }
}

macro_rules! arg_err {
    ($text:literal) => {
        concat!("arg ", $text, " format error")
    };
}

fn init() -> bool {
    let mut buf = String::with_capacity(512);

    write!(buf, "{APP_NAME} version {APP_VER} CopyLeft Kivensoft 2023-2024.").unwrap();
    let version = buf.as_str();

    let ac = AppConf::init();
    if !appcfg::parse_args(ac, version).expect("parse args error") {
        return false;
    }

    if ac.install {
        syssrv::install();
        return false;
    }

    AppGlobal::init(AppGlobal {
        heart_break_live_time: ac.api_expire.parse().expect(arg_err!("api-expire")),
        redis_ttl: ac.redis_ttl.parse().expect(arg_err!("redis-ttl")),
        startup_time: localtime::unix_timestamp(),
    });

    if !ac.listen.is_empty() && ac.listen.as_bytes()[0] == b':' {
        ac.listen.insert_str(0, "0.0.0.0");
    };

    let log_level = asynclog::parse_level(&ac.log_level).expect(arg_err!("log-level"));
    let log_max = asynclog::parse_size(&ac.log_max).expect(arg_err!("log-max"));

    if log_level == log::Level::Trace {
        println!("config setting: {ac:#?}\n");
    }

    asynclog::init_log(log_level, ac.log_file.clone(), log_max,
        !ac.no_console, true).expect("init log error");
    asynclog::set_level("mio".to_owned(), log::LevelFilter::Info);
    asynclog::set_level("hyper_util".to_owned(), log::LevelFilter::Info);

    if let Some((s1, s2)) = BANNER.split_once('?') {
        buf.clear();
        buf.push_str(s1);
        buf.push_str(APP_VER);
        // buf.push_str(&s2[APP_VER.len() - 1..]);
        buf.push_str(s2);
        appcfg::print_banner(&buf, true);
    }

    // 加载配置文件内容
    if !ac.dict_file.is_empty() {
        dict::load(&ac.dict_file).unwrap();
    }

    true
}

fn register_apis(srv: &mut HttpServer, ac: &AppConf) {
    let gps = ac.gw_prefix.as_bytes();
    let mut gw_path = CompactString::with_capacity(0);
    if gps[0] != b'/' {
        gw_path.push('/');
    }
    gw_path.push_str(&ac.gw_prefix);
    if gps[gps.len() - 1] != b'/' {
        gw_path.push('/');
    }

    httpserver::register_apis!(srv, &gw_path,
        "ping": apis::ping,
        "ping/*": apis::ping,
        "token": apis::token,
        "blacklist": apis::blacklist,
        "status": apis::status,
        "query": apis::query,
        "query/*": apis::query,
        "reg": apis::reg,
        "unreg": apis::unreg,
        "cfg": apis::cfg,
        "cfg/*": apis::cfg,
        "recfg": apis::recfg,
    );
}

// #[tokio::main(worker_threads = 4)]
// #[tokio::main(flavor = "current_thread")]
fn main() {
    if !init() { return; }
    let ac = AppConf::get();

    let max_jwt_cache_size = ac.mtcs.parse().expect(arg_err!("mtcs"));
    let addr: std::net::SocketAddr = ac.listen.parse().unwrap();
    let (cancel_sender, cancel_manager) = httpserver::new_cancel();

    let mut srv = HttpServer::new();
    // 设置请求上下文路径
    srv.set_context_path(&ac.context_path);
    // 路由支持1级子路径匹配
    srv.set_fuzzy_find(httpserver::FuzzyFind::One);
    // 添加日志中间件
    srv.set_middleware(httpserver::AccessLog);
    // 缺省处理函数改为反向代理处理函数
    srv.set_default_handler(proxy::proxy_handler);
    // 允许用户通过发送取消消息来优雅的终止服务
    srv.set_cancel_manager(cancel_manager);

    if !ac.jwt_key.is_empty() {
        // 添加token校验中间件
        srv.set_middleware(auth::Authentication::new(
            &ac.jwt_key,
            &ac.jwt_issuer,
            max_jwt_cache_size,
            10 * 60,
        ))
    };

    // 注册网关接口
    register_apis(&mut srv, ac);

    let async_fn = async move {
        // 初始化redis连接池
        if !ac.redis_host.is_empty() {
            redis::init(&redis::RedisConfig {
                host: &ac.redis_host,
                port: &ac.redis_port,
                user: &ac.redis_user,
                pass: &ac.redis_pass,
                db: &ac.redis_db,
            }).await.context("connect redis fail").unwrap();
        }

        // 运行http server主服务
        let listener = srv.listen(addr).await.expect("http server listen error");

        tokio::spawn(async move {
            srv.arc().serve(listener).await.expect("http server run error");
        });

        // 监听ctrl+c事件
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                println!("{APP_NAME} shutdowning, waiting {} connections closed...", cancel_sender.count());
                cancel_sender.cancel_and_wait().await.unwrap();
            }
            Err(e) => {
                eprintln!("Unable to listen for shutdown signal: {e:?}");
            }
        }
    };

    let threads = ac.threads.parse::<usize>().expect(arg_err!("threads"));

    #[cfg(not(feature = "multi_thread"))]
    let mut builder = {
        assert!(threads == 1, "{APP_NAME} current version unsupport multi-threads");
        tokio::runtime::Builder::new_current_thread()
    };

    #[cfg(feature = "multi_thread")]
    let mut builder = {
        assert!(threads <= 256, "multi-threads range in 0-256");

        let mut builder = tokio::runtime::Builder::new_multi_thread();
        if threads > 0 {
            builder.worker_threads(threads);
        }

        builder
    };

    builder.enable_all()
        .build()
        .unwrap()
        .block_on(async_fn)
}
