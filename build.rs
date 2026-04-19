use std::{env, fs::File, io::Write, path::Path};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let app_name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");

    let mut f = File::create(Path::new(&out_dir).join(".app_name")).unwrap();
    f.write_all(app_name.trim().as_bytes()).unwrap();

    let mut f = File::create(Path::new(&out_dir).join(".version")).unwrap();
    f.write_all(version.trim().as_bytes()).unwrap();

    copy_files(&["apigw.conf", "dict.cfg"]);
}

/// 将项目的静态文件复制到 OUT_DIR
fn copy_files(sources: &[&str]) {
    // 获取项目根目录（Cargo.toml 所在目录）
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // 获取输出目录（target/debug 或 target/release）
    let out_dir = env::var("OUT_DIR").unwrap();

    for src in sources {
        let src_path = Path::new(&manifest_dir).join(src);
        // OUT_DIR 通常是 target/debug/build/xxx/out，向上两级到 target/debu
        let dst_path = Path::new(&out_dir).ancestors().nth(3).unwrap().join(src);

        // 复制文件
        if src_path.exists() {
            if std::fs::copy(&src_path, &dst_path).is_err() {
                panic!("Failed to copy {}", src);
            }

            println!("cargo:warning={} copied to {}", src, dst_path.to_str().unwrap());
        } else {
            println!("cargo:warning={} not found at {}", src, src_path.to_str().unwrap());
        }
    }
}
