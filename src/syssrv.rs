//! linux service register

#[cfg(not(target_os = "linux"))]
pub fn install() {
    println!("Windows type services are not supported!");
    println!("Please use third-party tools to install the application as a Windows service");
}

#[cfg(target_os = "linux")]
pub fn install() {
    use std::path::Path;

    const SYSTEMD_CONTENT: &str = r#"
        # apigw service
        # =======================
        #
        [Unit]
        Description=api gateway service
        After=network.target

        [Service]
        Type=simple
        ExecStart=? -c ?.conf
        #ExecReload=/bin/kill -HUP $MAINPID
        KillMode=process
        #Restart=on-failure

        [Install]
        WantedBy=multi-user.target
    "#;

    let mut args = std::env::args();
    let prog = args.next().unwrap();
    let prog = Path::new(&prog);
    let prog = prog.canonicalize().unwrap();
    let prog_str = prog.to_str().unwrap();

    // 替换"?"为实际的参数内容
    let mut systemd_content = String::with_capacity(SYSTEMD_CONTENT.len() + 128);
    let mut split = SYSTEMD_CONTENT.split('?');
    systemd_content.push_str(split.next().unwrap());
    systemd_content.push_str(prog_str);
    systemd_content.push_str(split.next().unwrap());
    systemd_content.push_str(prog_str);
    systemd_content.push_str(split.next().unwrap());

    // 删除前后空白行和每行的前导空白符
    let mut content = String::with_capacity(systemd_content.len());
    for s in systemd_content.split("\n").skip(1) {
        content.push_str(s.trim_start());
        content.push('\n');
    }
    content.truncate(content.len() - 1);

    // 写入服务配置文件
    let prog_noext = Path::new(prog.file_name().unwrap()).file_stem().unwrap();
    let prog_noext = prog_noext.to_str().unwrap();
    let path = format!("/lib/systemd/systemd/{}.service", prog_noext);
    let path = Path::new(&path);
    std::fs::write(&path, content).unwrap();

    let path_str = path.to_str().unwrap();
    println!("Generating service configuration file \"{}\" is complete.", path_str);
    println!("Please use \"systemctl start {}\" to start the service", prog_noext);

}
