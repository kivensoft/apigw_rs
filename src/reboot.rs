use shellflip::{lifecycle::{PipeWriter, LifecycleHandler, receive_from_old_process}, RestartConfig};
use std::io;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
use tokio_util::sync::CancellationToken;

// ================================================================
// 第一步：定义生命周期处理器（Lifecycle Handler）
// ================================================================
// 这个结构体用于处理新旧进程之间的状态传递。如果你的服务需要传递某些内部状态
// （比如内存中的缓存、统计信息等），可以在这里实现序列化和反序列化逻辑。
// 如果不需要传递状态，可以保持空实现。
struct MyLifecycleHandler;

#[async_trait::async_trait]
impl LifecycleHandler for MyLifecycleHandler {
    // 这个方法在旧进程中被调用，用于向新进程发送序列化的状态数据。
    // `pipe` 是一个单向管道，旧进程可以通过它写入数据，新进程可以通过
    // `receive_from_old_process` 读取这些数据。
    async fn send_to_new_process(&mut self, mut write_pipe: PipeWriter) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        debug!("[旧进程] 正在向新进程发送状态数据...");
        // 示例：发送一个简单的问候消息（实际使用时可以是 JSON、bincode 等格式）
        write_pipe.write_all(b"hello from old process").await?;
        debug!("[旧进程] 状态数据发送完成");
        Ok(())
    }

    // 可选：在 spawn 新进程之前被调用，可以在这里执行一些准备工作
    async fn pre_new_process(&mut self) {
        debug!("[旧进程] 即将创建新进程，执行准备工作...");
    }

    // 可选：在新进程启动失败时被调用，旧进程可以在这里执行一些清理或回滚操作
    async fn new_process_failed(&mut self) {
        error!("[旧进程] 新进程启动失败，继续运行当前进程");
    }
}

// ================================================================
// 第二步：新进程接收状态数据的辅助函数
// ================================================================
/// 在新进程中调用此函数，尝试接收来自旧进程的状态数据
/// 这是 shellflip::lifecycle::receive_from_old_process() 的封装
async fn try_receive_state_from_old_process() -> Option<String> {
    use tokio::io::AsyncReadExt;

    // 调用 shellflip 提供的独立函数
    // 如果当前进程是由热重启创建的，这个函数会返回 Some(PipeReader)
    // 否则返回 None
    if let Some(mut pipe_reader) = receive_from_old_process() {
        debug!("[新进程] 检测到来自旧进程的状态数据，正在接收...");

        let mut buf = Vec::new();
        match pipe_reader.read_to_end(&mut buf).await {
            Ok(n) if n > 0 => {
                let msg = String::from_utf8_lossy(&buf).to_string();
                debug!("[新进程] 成功接收状态数据: {} ({} 字节)", msg, n);
                Some(msg)
            },
            Ok(_) => {
                debug!("[新进程] 接收到空数据");
                None
            },
            Err(err) => {
                error!(%err, "[新进程] 接收状态数据失败");
                None
            },
        }
    } else {
        debug!("[新进程] 未检测到旧进程（首次启动），无状态数据需要接收");
        None
    }
}

pub async fn run_as_reboot(socket_path: &str, shutdown_token: CancellationToken) {
    // ---------- 在新进程启动时，首先尝试接收旧进程的状态 ----------
    // 注意：这一步必须在任何其他初始化之前执行
    let received_state = try_receive_state_from_old_process().await;

    if received_state.is_some() {
        info!("[新进程] 已成功接管旧进程的状态，继续初始化...");
    }

    // ---------- 配置热重启 ----------
    let restart_config = RestartConfig {
        enabled: true,
        coordination_socket_path: PathBuf::from(socket_path),
        environment: vec![], // 可以设置传递给新进程的环境变量
        lifecycle_handler: Box::new(MyLifecycleHandler),
        exit_on_error: false, // 新进程启动失败时不退出旧进程
    };

    // 尝试转换为重启任务
    // 注意：这里需要根据版本调整，不同版本 API 可能有差异
    let restart_future = match restart_config.try_into_restart_task() {
        Ok(future) => future,
        Err(err) => {
            warn!(%err, "未检测到重启协调信息，作为普通进程运行");
            // 创建一个不传递状态的简单配置
            let basic_config = RestartConfig {
                enabled: true,
                coordination_socket_path: PathBuf::from(socket_path),
                environment: vec![],
                lifecycle_handler: Box::new(MyLifecycleHandler),
                exit_on_error: false,
            };
            basic_config.try_into_restart_task().unwrap()
        },
    };

    match tokio::spawn(restart_future).await {
        Ok(Ok(child)) => {
            debug!(pid = %child.id(), "新进程已成功启动，当前进程退出");
            // 触发关闭信号，让 Axum 服务器开始优雅停机
            shutdown_token.cancel();
            // 给服务器一些时间处理现有的请求
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        },
        Ok(Err(err)) => {
            error!(%err, "重启失败");
        },
        Err(err) => {
            error!(%err, "重启任务出错");
        },
    };
}
