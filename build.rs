use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    // config parameters
    let dwb_capacity = env::var("DWB_CAPACITY").unwrap_or_else(|_| "64".to_string());
    let btbe_capacity = env::var("BTBE_CAPACITY").unwrap_or_else(|_| "64".to_string());

    // path to destination config.rs file
    let out_dir = env::var("OUT_DIR").expect("Missing OUT_DIR");
    let dest_path = Path::new(&out_dir).join("config.rs");

    // write constants
    let mut file = File::create(&dest_path).expect("Failed to write to config.rs");
    writeln!(file, "pub const DWB_CAPACITY: u16 = {};", dwb_capacity).unwrap();
    writeln!(file, "pub const BTBE_CAPACITY: u16 = {};", btbe_capacity).unwrap();

    // monitor
    println!("cargo:rerun-if-env-changed=DWB_CAPACITY");
    println!("cargo:rerun-if-env-changed=BTBE_CAPACITY");
}
