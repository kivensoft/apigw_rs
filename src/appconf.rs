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
            log_filter: "debug,tower_http::trace::on_eos=info,redis_async::reconnect=warn".into(),
            log_file: "".into(),
            no_console: false,
            install: false,
            listen: "127.0.0.1:6400".into(),
            dict_file: "dict.cfg".into(),
            task_threads: "1".into(),
            blocking_threads: "32".into(),
            db_file: "invalid_token.redb".into(),
            // context_path: String::new(),
            gw_prefix: "/gw".into(),
            expire_time: "90".into(),
            conn_timeout: "3".into(),
            jwt_key: "apigw CopyRight by kivensoft 2023-05-04".into(),
            jwt_iss: "apigw".into(),
            jwt_ttl: "1440".into(),
            mtcs: "128".into(),
            redis: "redis://:password@127.0.0.1:6379/0".into(),
            redis_prefix: APP_NAME.into(),
            redis_ttl: "300".into(),
        }
    }
}
