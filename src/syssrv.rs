//! linux service register

use crate::APP_NAME;

pub fn install() {
    const SYSTEMD_CONTENT: &str = r#"
        # /etc/systemd/system/?.service
        # apigw service
        # =======================

        [Unit]
        Description=api gateway service
        After=network.target

        [Service]
        # 【关键】指定运行用户，实现权限隔离
        #User=app_user
        #Group=app_user

        Type=simple
        # 工作目录
        WorkingDirectory=/opt/?

        # 【核心】启动命令
        ExecStart=? -c ?.conf

        # 崩溃自动重启配置
        #Restart=always
        #RestartSec=30

        #  重启命令
        #ExecReload=/bin/kill -HUP $MAINPID
        KillMode=process

        [Install]
        WantedBy=multi-user.target

        # 重载配置
        # systemctl daemon-reload
        # 设置开机自启
        # systemctl enable ?
        # 启动服务
        # systemctl start ?
    "#;

    // 替换"?"为实际的参数内容
    let slen = SYSTEMD_CONTENT.len() + APP_NAME.len() * SYSTEMD_CONTENT.matches('?').count();
    let mut systemd_content = String::with_capacity(slen);

    let mut parts = SYSTEMD_CONTENT.split('?');
    // 添加第一个部分
    if let Some(first) = parts.next() {
        systemd_content.push_str(first);
    }
    // 后续每个部分前添加 app_name
    for part in parts {
        systemd_content.push_str(APP_NAME);
        systemd_content.push_str(part);
    }

    // 删除前后空白行和每行的前导空白符
    let mut content = String::with_capacity(systemd_content.len());
    for s in systemd_content.split("\n").skip(1) {
        content.push_str(s.trim_start());
        content.push('\n');
    }
    content.truncate(content.len() - 1);

    // 在控制台输出服务配置文件内容
    println!("{}", content);
}
