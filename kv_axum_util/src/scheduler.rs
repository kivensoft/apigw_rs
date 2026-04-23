//! 定时任务管理器, 定时(创建时指定扫描时间间隔)扫描任务列表, 执行到期任务
//! 任务有2种, 一种是一次性任务, 一种是重复执行的任务

use std::{pin::Pin, sync::Arc, time::Duration};

use tokio::sync::Mutex;

use crate::{remove_from_vec, unix_timestamp};

const TASKS_IDLE_SIZE: usize = 1024;

type TaskAction = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;


struct Task {
    /// 重复执行间隔秒数, 0 表示单次执行
    interval: u32,
    /// 下次执行时间戳, 相对于 Instant::now() 的秒数
    execute_at: u64,
    /// 任务执行方法
    action: TaskAction,
}

pub struct SimpleScheduler {
    /// 重复执行间隔秒数, 0 表示单次执行
    interval: u32,
    /// 定时执行任务列表
    tasks: Mutex<Vec<Task>>,
}

impl SimpleScheduler {
    /// 创建一个定时任务
    ///
    /// ### Arguments:
    /// * `interval` - 间隔秒数, 0 表示单次执行
    pub fn new(interval: u32) -> Self {
        Self { interval, tasks: Mutex::new(Vec::new()) }
    }

    /// 添加一个延迟执行任务, 在指定的 interval 秒数后执行, 执行完后删除任务不再执行
    ///
    /// ### Arguments:
    /// * `interval`: 延迟执行时间, 单位秒
    /// * `action`: 任务执行方法
    pub async fn add_lazy_task<F, Fut>(&self, interval: u32, action: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + Sync + 'static,
    {
        let mut tasks = self.tasks.lock().await;
        tasks.push(Task {
            interval: 0,
            execute_at: unix_timestamp() + interval as u64,
            action: Arc::new(move || Box::pin(action())),
        });
    }

    /// 添加一个重复执行的任务, interval为间隔时间，单位为秒
    ///
    /// ### Arguments:
    /// * `interval`: 间隔时间，单位为秒
    /// * `action`: 任务执行方法
    pub async fn add_repeat_task<F, Fut>(&self, interval: u32, action: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + Sync + 'static,
    {
        let mut tasks = self.tasks.lock().await;
        tasks.push(Task {
            interval,
            execute_at: unix_timestamp() + interval as u64,
            action: Arc::new(move || Box::pin(action())),
        });
    }

    /// 执行扫描, 每分钟扫描一次到期任务, 并执行它
    pub async fn run(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.interval as u64));

        loop {
            interval.tick().await;
            // 待删除的任务索引数组, 循环中先记录需要删除的索引, 循环完成再一次性处理
            let mut wait_del_indices = Vec::<u32>::new();
            let now = unix_timestamp();
            let mut tasks = self.tasks.lock().await;

            for (idx, task) in tasks.iter_mut().enumerate() {
                if task.execute_at > now {
                    continue;
                }

                let action = task.action.clone();
                tokio::spawn(action());

                let task_interval = task.interval;
                if task_interval > 0 {
                    task.execute_at = now + task_interval as u64;
                } else {
                    wait_del_indices.push(idx as u32);
                }
            }

            remove_from_vec(&mut tasks, &wait_del_indices);

            // 当任务数组的空闲空间过大时回收空间
            let cap = tasks.capacity();
            if cap > TASKS_IDLE_SIZE && cap / 2 > tasks.len() {
                let len = tasks.len();
                tasks.shrink_to(len);
            }
        }
    }
}
