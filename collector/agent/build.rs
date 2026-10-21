// Stamps the build date (epoch seconds) into the binary: the time-sanity gate refuses to send
// while the router clock (no RTC) is earlier than this.
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let ts = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        })
        .unwrap_or(0);
    println!("cargo:rustc-env=VIGIE_BUILD_TS={ts}");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}
