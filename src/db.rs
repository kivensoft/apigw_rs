use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use localtime::unix_timestamp;
use redb::{Database, ReadableDatabase, TableDefinition};

use crate::{efmt, static_val::StaticVal};

const TABLE: TableDefinition<&str, u64> = TableDefinition::new("invalid_tokens");

static DB: StaticVal<Database> = StaticVal::new();

/// 初始化数据库，应用启动前调用
pub fn init(path: &str) {
    let db = Database::create(path)
        .with_context(|| efmt!("打开redb数据库 {} 失败", path))
        .unwrap();
    DB.init(db, "db::init");
}

/// 判断指定的token的签名是否存在
pub fn exists(token_sign: &str) -> bool {
    let exp = match get(token_sign) {
        Ok(Some(exp)) => exp,
        _ => return false,
    };

    let now = unix_timestamp();
    if exp >= now {
        return true;
    }

    // 该token已过期，删除
    let _ = delete(token_sign);
    false
}

/// 获取指定token的过期时间
pub fn get(token_sign: &str) -> Result<Option<u64>> {
    let db = DB.get();
    let txn = db.begin_read()?;
    let table = txn.open_table(TABLE)?;
    Ok(table.get(token_sign)?.map(|v| v.value()))
}

/// 设置token的过期时间
pub fn put(token_sign: &str, expire: u64) -> Result<()> {
    let db = DB.get();
    let txn = db.begin_write()?;
    let mut table = txn.open_table(TABLE)?;
    table.insert(token_sign, expire)?;
    Ok(())
}

/// 删除token
pub fn delete(token_sign: &str) -> Result<()> {
    let db = DB.get();
    let txn = db.begin_write()?;
    let mut table = txn.open_table(TABLE)?;
    table.remove(token_sign)?;
    Ok(())
}

/// 删除库表中过期的键，由用户自行周期性调用以删除无效记录
pub fn remove_expired() {
    static RUNNING: AtomicBool = AtomicBool::new(false);

    let result = RUNNING.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed);
    if result.is_err() {
        return;
    }

    let db = DB.get();
    let now = unix_timestamp();
    match db.begin_write() {
        Ok(txn) => match txn.open_table(TABLE) {
            Ok(mut table) => {
                if let Err(err) = table.retain(|_, v| v >= now) {
                    tracing::error!(%err, "redb表过期数据删除失败")
                }
            },
            Err(err) => tracing::error!(%err, "打开redb表失败"),
        },
        Err(err) => tracing::error!(%err, "创建redb表可写事务失败"),
    }
}
