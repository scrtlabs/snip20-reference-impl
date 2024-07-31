use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    // config parameters
    // let dwb_capacity = env!("DWB_CAPACITY").parse().unwrap_or_else(|_| "4".to_string());
    let dwb_capacity = env::var("DWB_CAPACITY").unwrap_or_else(|_| "4".to_string());

    // path to destination config.rs file
	let out_dir = env::var("OUT_DIR").expect("Missing OUT_DIR");
    let dest_path = Path::new(&out_dir).join("config.rs");

    // write constants
    let mut file = File::create(&dest_path).expect("Failed to write to config.rs");
    write!(file, "pub const DWB_CAPACITY: u16 = {};", dwb_capacity).unwrap();

	// monitor
	println!("cargo:rerun-if-env-changed=DWB_CAPACITY");
}
