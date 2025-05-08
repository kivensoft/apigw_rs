//! 简单的redis客户端
use anyhow::Result;
use redis_async::{
    client::{ConnectionBuilder, PairedConnection},
    resp::{FromResp, RespValue},
    resp_array,
};

use crate::statics::StaticVal;

macro_rules! ra {
    // 直接转发到 resp_array!
    ($($arg:tt)*) => {
        resp_array!($($arg)*)
    };
}

pub struct RedisConfig<'a> {
    pub host: &'a str,
    pub port: &'a str,
    pub user: &'a str,
    pub pass: &'a str,
    pub db: &'a str,
}

struct GlobalVal {
    conn: PairedConnection,
    expire_secs: u32,
}


static GLOBAL_VAL: StaticVal<GlobalVal> = StaticVal::new();


pub async fn init(cfg: &RedisConfig<'_>, expire_secs: u32) -> Result<()> {
    let port = cfg.port.parse::<u16>().unwrap_or(6379);
    // let db = cfg.db.parse::<usize>().unwrap_or(0);

    let mut builder = ConnectionBuilder::new(cfg.host, port)?;
    if !cfg.user.is_empty() {
        builder.username(cfg.user);
    }
    if !cfg.pass.is_empty() {
        builder.password(cfg.pass);
    }

    let conn = builder.paired_connect().await?;
    // if !cfg.db.is_empty() {
    //     let param = ra!["SELECT", db];
    //     conn.send::<()>(param).await?;
    // }

    GLOBAL_VAL.init(GlobalVal { conn, expire_secs });
    send::<()>("PING".into()).await?;

    Ok(())
}

pub async fn get(key: &str) -> Result<Option<String>> {
    send(ra!["GET", key]).await
}

pub async fn set(key: &str, value: &str) -> Result<()> {
    setex(key, value, GLOBAL_VAL.get().expire_secs).await
}

pub async fn setex(key: &str, value: &str, expire_secs: u32) -> Result<()> {
    let cmd = ra!["SETEX", key, expire_secs as usize, value];
    send(cmd).await
}

pub async fn del(key: &str) -> Result<bool> {
    send::<usize>(ra!["DEL", key]).await.map(|v| v == 1)
}

pub async fn expire(key: &str, expire_secs: u32) -> Result<bool> {
    let cmd = ra!["EXPIRE", key, expire_secs as usize];
    send::<usize>(cmd).await.map(|v| v == 1)
}

pub async fn ttl(key: &str) -> Result<i64> {
    send(ra!["TTL", key]).await
}

pub async fn incr(key: &str) -> Result<i64> {
    send(ra!["INCR", key]).await
}

async fn send<T: FromResp + Unpin>(resp: RespValue) -> Result<T> {
    Ok(GLOBAL_VAL.get().conn.send(resp).await?)
}

fn send_and_forget(resp: RespValue) {
    GLOBAL_VAL.get().conn.send_and_forget(resp)
}
