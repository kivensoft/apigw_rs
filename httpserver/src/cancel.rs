use std::{sync::{atomic::{AtomicBool, AtomicU32, Ordering}, Arc}, time::Duration};

use tokio::sync::watch::{error::{RecvError, SendError}, Receiver, Sender};

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
    finished: AtomicBool,
}

pub fn new_cancel() -> (CancelSender, CancelManager) {
    let (sender, receiver) = tokio::sync::watch::channel(false);
    let count = Arc::new(AtomicU32::new(0));
    (
        CancelSender {
            sender,
            count: count.clone(),
        },
        CancelManager {
            receiver,
            count,
        },
    )
}

impl CancelSender {
    pub fn cancel(&self) -> Result<(), SendError<bool>> {
        // self.count.fetch_sub(1, Ordering::Release);
        self.sender.send(true)
    }

    pub async fn wait(&self, sleep: Duration) {
        while self.count.load(Ordering::Acquire) != 0 {
            tokio::time::sleep(sleep).await;
        }
    }

    pub async fn cancel_and_wait(&self, sleep: Duration) -> Result<(), SendError<bool>> {
        self.cancel()?;
        self.wait(sleep).await;
        Ok(())
    }

    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

impl CancelManager {
    pub fn is_cancel(&self) -> bool {
        *self.receiver.borrow()
    }

    pub fn new_task_cancel(&self) -> CancelReceiver {
        CancelReceiver::new(self.receiver.clone(), self.count.clone())
    }

    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

impl CancelReceiver {
    fn new(receiver: Receiver<bool>, count: Arc<AtomicU32>) -> Self {
        count.fetch_add(1, Ordering::Acquire);
        CancelReceiver {
            receiver,
            count,
            finished: AtomicBool::new(false),
        }
    }

    /// 等待接收取消任务事件
    pub async fn cancelled(&mut self) -> Result<(), RecvError> {
        self.receiver.changed().await
    }

    /// 标志异步任务已经结束
    pub fn finish(&self) {
        if self.finished.compare_exchange(false, true, Ordering::Release, Ordering::Relaxed).is_ok() {
            self.count.fetch_sub(1, Ordering::Release);
        }
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
