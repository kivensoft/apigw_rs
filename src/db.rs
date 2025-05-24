use std::sync::OnceLock;

use anyhow::{Result, bail};
use localtime::unix_timestamp;
use redb::{Database, TableDefinition};

const TABLE: TableDefinition<&str, u64> = TableDefinition::new("invalid_token");

static DB: OnceLock<Database> = OnceLock::new();

/// 初始化数据库，应用启动前调用
pub fn init(path: &str) {
    let db = Database::create(path).unwrap();
    if DB.set(db).is_err() {
        panic!("init db error");
    }
}

/// 判断数据库是否已经初始化
pub fn is_valid() -> bool {
    DB.get().is_some()
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
    match DB.get() {
        Some(db) => {
            let txn = db.begin_read()?;
            let table = txn.open_table(TABLE)?;
            Ok(table.get(token_sign)?.map(|v| v.value()))
        }
        None => bail!("db not init"),
    }
}

/// 设置token的过期时间
pub fn put(token_sign: &str, expire: u64) -> Result<()> {
    match DB.get() {
        Some(db) => {
            let txn = db.begin_write()?;
            let mut table = txn.open_table(TABLE)?;
            table.insert(token_sign, expire)?;
            Ok(())
        }
        None => bail!("db not init"),
    }
}

/// 删除token
pub fn delete(token_sign: &str) -> Result<()> {
    match DB.get() {
        Some(db) => {
            let txn = db.begin_write()?;
            let mut table = txn.open_table(TABLE)?;
            table.remove(token_sign)?;
            Ok(())
        }
        None => Ok(()),
    }
}

/// 删除库表中过期的键，由用户自行周期性调用以删除无效记录
pub fn remove_expired() {
    match DB.get() {
        Some(db) => {
            let now = unix_timestamp();
            match db.begin_write() {
                Ok(txn) => match txn.open_table(TABLE) {
                    Ok(mut table) => {
                        if let Err(e) = table.retain(|_, v| v >= now) {
                            log::error!("retain error: {e:?}")
                        }
                    }
                    Err(e) => log::error!("open table error: {e:?}"),
                },
                Err(e) => log::error!("create write trans error: {e:?}"),
            }
        }
        None => log::error!("db not init"),
    }
}
