use std::{env, fs::File, io::Write, path::Path};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let app_name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");

    let mut f = File::create(Path::new(&out_dir).join(".app_name")).unwrap();
    f.write_all(app_name.trim().as_bytes()).unwrap();

    let mut f = File::create(Path::new(&out_dir).join(".version")).unwrap();
    f.write_all(version.trim().as_bytes()).unwrap();
}
