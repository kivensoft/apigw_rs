use crate::APP_NAME;

appcfg::appconfig_define!(app_conf, AppConf,
    log_filter       : String => ["L",  "log-filter",       "LogFilter",             "日志级别, 例如:(info,axum=debug,tower_http::request=trace)"],
    log_file         : String => ["F",  "log-file",         "LogFile",               "日志文件名(不带扩展名)"],
    no_console       : bool   => ["",   "no-console",       "",                      "禁止将日志输出到控制台"],
    install          : bool   => ["",   "install",          "",                      "输出linux的systemd服务文件"],
    listen           : String => ["l",  "listen",           "HttpServiceListen",     "服务端点 (ip地址:端口号)"],
    dict_file        : String => ["d",  "dict-file",        "ApiCfgFile",            "公共配置文件名"],
    task_threads     : String => ["t",  "task-threads",     "TokioAsyncTaskThreads", "执行异步任务的线程数"],
    blocking_threads : String => ["t",  "blocking-threads", "TokioBlockingThreads",  "执行阻塞任务的线程数"],
    db_file          : String => ["D",  "db-file",          "LocalDBFile",           "本地数据库文件名"],
    // context_path     : String => ["",   "context-path",     "HttpContextPath",       "服务上下文地址"],
    gw_prefix        : String => ["g",  "gw-prefix",        "GatewayPathPrefix",     "网关服务地址前缀"],
    expire_time      : String => ["e",  "expire-time",      "ApiExpireTime",         "服务注册超时时间(单位: 秒)"],
    conn_timeout     : String => ["T",  "conn-timeout",     "ApiConnectTimeout",     "接口连接超时时间(单位: 秒)"],
    jwt_iss          : String => ["i",  "jwt-iss",          "JwtIss",                "jwt令牌发行者, 当发行者存在时校验令牌中的发行者是否相符"],
    jwt_key          : String => ["k",  "jwt-key",          "JwtKey",                "jwt令牌密钥, 当密钥存在时将校验令牌并设置请求头X-UID"],
    jwt_ttl          : String => ["T",  "jwt-ttl",          "JwtTTL",                "jwt令牌过期时间(单位: 秒)"],
    mtcs             : String => ["",   "mtcs",             "MaxLocalJwtCacheSize",  "令牌的本地缓存最大数量"],
    redis            : String => ["R",  "redis-host",       "RedisURL",              "格式: redis://[<username>][:<password>@]<hostname>[:port][/[<db>][?protocol=<protocol>]]"],
    redis_prefix     : String => ["P",  "redis-prefix",     "RedisKeyPrefix",        "redis公共键前缀"],
    redis_ttl        : String => ["",   "redis-ttl",        "RedisTTL",              "redis缓存项缺省过期时间"],
);

impl Default for AppConf {
    fn default() -> Self {
        let mut log_file = String::with_capacity(APP_NAME.len() + 4);
        log_file.push_str(APP_NAME);
        log_file.push_str(".log");

        Self {
            log_filter: "debug,redis_async::reconnect=warn".to_string(),
            log_file: "".to_string(),
            no_console: false,
            install: false,
            listen: "127.0.0.1:6400".to_string(),
            dict_file: "dict.cfg".to_string(),
            task_threads: "1".to_string(),
            blocking_threads: "32".to_string(),
            db_file: "invalid_token.redb".to_string(),
            // context_path: String::new(),
            gw_prefix: "/gw".to_string(),
            expire_time: "90".to_string(),
            conn_timeout: "10".to_string(),
            jwt_key: "SysApi CopyRight by kivensoft 2023-05-04".to_string(),
            jwt_iss: "SysApi".to_string(),
            jwt_ttl: "1440".to_string(),
            mtcs: "128".to_string(),
            redis: "redis://:password@127.0.0.1:6379/0".to_string(),
            redis_prefix: APP_NAME.to_string(),
            redis_ttl: "300".to_string(),
        }
    }
}
