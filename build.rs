use std::{env, fs::File, path::Path, io::Write};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let version = env!("CARGO_PKG_VERSION");

    let mut f = File::create(Path::new(&out_dir).join(".version")).unwrap();
    f.write_all(version.trim().as_bytes()).unwrap();
}
