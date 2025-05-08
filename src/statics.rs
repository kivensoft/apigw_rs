//! 程序运行时手动进行动态初始化的全局静态变量

use std::sync::OnceLock;

pub struct StaticVal<T>(pub OnceLock<T>);

impl<T> StaticVal<T> {
    pub const fn new() -> Self {
        Self(OnceLock::new())
    }

    pub fn init(&self, value: T) {
        if self.0.set(value).is_err() {
            panic!("StaticVal::init() failed");
        }
    }

    pub fn get(&self) -> &T {
        debug_assert!(self.0.get().is_some());
        match self.0.get() {
            Some(v) => v,
            None => unsafe { std::hint::unreachable_unchecked() },
        }
    }
}
