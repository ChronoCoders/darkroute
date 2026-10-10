#![deny(warnings)]
#![forbid(unsafe_code)]

//! Does a default build of the SDK export the low level dialer?
//!
//! It must not: that dialer takes a caller supplied TLS connector and so is a
//! way around the SDK's own trust roots. This probe names the symbol and
//! nothing else, so the build fails when it is absent and succeeds when the
//! `with-test-util` feature puts it back. The gate runs both directions.

fn main() {
    let _ = quiethop_client::dial;
}
