use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::watch::{Receiver, Sender};

#[derive(Debug)]
pub struct CancelSender {
    sender: Sender<bool>,
    count: Arc<AtomicU32>,
}

#[derive(Clone)]
pub struct CancelManager {
    receiver: Receiver<bool>,
    count: Arc<AtomicU32>,
}

pub struct CancelReceiver {
    receiver: Receiver<bool>,
    count: Arc<AtomicU32>,
}

pub fn new_cancel() -> (CancelSender, CancelManager) {
    let (sender, receiver) = tokio::sync::watch::channel(false);
    let count = Arc::new(AtomicU32::new(0));
    (
        CancelSender {
            sender,
            count: count.clone(),
        },
        CancelManager { receiver, count },
    )
}

impl CancelSender {
    /// 取消任务并等待任务结束或超时
    pub async fn cancel(&self, wait_seconds: Duration) {
        const TICK_MS: u64 = 50;
        const SEC_COUNT: u64 = 1000 / TICK_MS;

        // 发送退出信号，如果没有等待结束的任务，直接返回
        if self.sender.send(true).is_err() {
            return;
        }

        // 等待结束时间为0，直接返回
        let wait_seconds = wait_seconds.as_secs();
        if wait_seconds == 0 {
            return;
        }

        let mut tick_count = 0;
        let max_count = wait_seconds * SEC_COUNT;
        let tick = Duration::from_millis(TICK_MS);
        let mut wait_count = self.count.load(Ordering::Relaxed);

        // 等待直至剩余任务为0或者超时
        while wait_count != 0 && tick_count < max_count {
            tokio::time::sleep(tick).await;
            tick_count += 1;
            // 等待整秒时输出调试日志
            if log::log_enabled!(log::Level::Trace) && tick_count % SEC_COUNT == 0 {
                let secs = tick_count / SEC_COUNT;
                println!("waiting {secs}s for {wait_count} tasks ...");
            }
            wait_count = self.count.load(Ordering::Relaxed);
        }

        // 再次发送退出信号，通知所有任务强制退出
        let _ = self.sender.send(true);
    }

    /// 返回当前任务数
    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

impl CancelManager {
    pub fn is_cancel(&self) -> bool {
        *self.receiver.borrow()
    }

    pub fn new_cancel_receiver(&self) -> CancelReceiver {
        CancelReceiver::new(self.receiver.clone(), self.count.clone())
    }

    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

impl CancelReceiver {
    fn new(receiver: Receiver<bool>, count: Arc<AtomicU32>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        CancelReceiver { receiver, count }
    }

    /// 等待接收取消任务事件, 返回true表示发生取消事件，返回false表示sender对象已销毁
    pub async fn cancel_event(&mut self) -> bool {
        self.receiver.changed().await.is_ok()
    }

    /// 标志异步任务已经结束，返回剩余任务数
    pub fn finish(&self) -> u32 {
        self.count.fetch_sub(1, Ordering::Release) - 1
    }

    /// 当前任务是否已被取消
    pub fn is_cancel(&self) -> bool {
        *self.receiver.borrow()
    }

    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

impl Clone for CancelReceiver {
    fn clone(&self) -> Self {
        Self::new(self.receiver.clone(), self.count.clone())
    }
}
