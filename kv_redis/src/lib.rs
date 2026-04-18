//! 简单的redis客户端

use anyhow::{Context, Result};
use redis_async::{
    client::{ConnectionBuilder, PairedConnection},
    resp::{FromResp, RespValue},
    resp_array as ra,
};
use url::Url;

/// 用于错误上下文的宏，例如 `file.read().with_context(|| emsg!("文件读取失败"))`
/// 用法类似format!宏
macro_rules! efmt {
    () => {
        format!("at [{}:{}]", file!(), line!())
    };
    ($msg:expr) => {
        format!("{} at [{}:{}]", $msg, file!(), line!())
    };
    ($fmt:expr, $($arg:tt)*) => {
        format!("{} at [{}:{}]", format_args!($fmt, $($arg)*), file!(), line!())
    };
}

pub struct RedisClient {
    conn: PairedConnection,
    expire_secs: u32,
}

impl RedisClient {

    pub async fn new(url: &str, expire_secs: u32) -> Result<Self> {
        let builder = parse_redis_url(url)?;
        let conn = builder.paired_connect().await.with_context(|| efmt!("redis connect fail"))?;
        let client = RedisClient { conn, expire_secs };
        Self::send::<RespValue>(&client, ra!["PING"]).await.with_context(|| efmt!("send ping fail"))?;
        Ok(client)
    }

    pub async fn get<S: Into<String>, T: FromResp + Unpin>(&self, key: S) -> Result<T> {
        self.send(ra!["GET", key.into()]).await
    }

    pub async fn set<S: Into<String>, V: Into<RespValue>>(&self, key: S, value: V) -> Result<()> {
        self.setex(key, value, self.expire_secs).await
    }

    pub async fn setex<S, V>(&self, key: S, value: V, expire_secs: u32) -> Result<()>
    where
        S: Into<String>,
        V: Into<RespValue>,
    {
        let mut buf = itoa::Buffer::new();
        let cmd = ra!["SETEX", key.into(), buf.format(expire_secs), value.into()];
        self.send(cmd).await
    }

    pub async fn del<S: Into<String>>(&self, key: S) -> Result<bool> {
        self.send::<usize>(ra!["DEL", key.into()]).await.map(|v| v == 1)
    }

    pub async fn expire<S: Into<String>>(&self, key: S, expire_secs: u32) -> Result<bool> {
        let cmd = ra!["EXPIRE", key.into(), expire_secs as usize];
        self.send::<usize>(cmd).await.map(|v| v == 1)
    }

    pub async fn ttl<S: Into<String>>(&self, key: S) -> Result<i64> {
        self.send(ra!["TTL", key.into()]).await
    }

    pub async fn incr<S: Into<String>>(&self, key: S) -> Result<i64> {
        self.send(ra!["INCR", key.into()]).await
    }

    pub async fn send<T: FromResp + Unpin>(&self, resp: RespValue) -> Result<T> {
        Ok(self.conn.send(resp).await?)
    }

    pub fn send_and_forget(&self, resp: RespValue) {
        self.conn.send_and_forget(resp)
    }

}

fn parse_redis_url(url_str: &str) -> Result<ConnectionBuilder> {
    let url = Url::parse(url_str)?;

    // 验证协议
    if url.scheme() != "redis" && url.scheme() != "rediss" {
        anyhow::bail!("不支持的协议: {}", url.scheme());
    }

    // 解析主机和端口
    let host = url.host_str().ok_or_else(|| anyhow::anyhow!("缺少主机名"))?;
    let port = url.port().unwrap_or(6379);

    // 解析用户名和密码
    let username = if url.username().is_empty() {
        None
    } else {
        Some(url.username())
    };

    let password = url.password().map(|p| p);

    // 解析数据库编号
    // let db = if let Some(path) = url.path().strip_prefix('/') {
    //     if path.is_empty() {
    //         0
    //     } else {
    //         path.parse::<i64>().unwrap_or(0)
    //     }
    // } else {
    //     0
    // };

    let mut builder = ConnectionBuilder::new(host, port)?;
    if let Some(username) = username {
        builder.username(username);
    }
    if let Some(password) = password {
        builder.password(password);
    }

    Ok(builder)
}
